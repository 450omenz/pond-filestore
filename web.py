#!/usr/bin/env python3
"""
Filestore Web UI
----------------
A Firefox-style file browser served at http://localhost:8080

Requires the filestore server to have been configured first:
    python server.py start

Then run:
    python web.py

Options:
    --data-dir   Storage root (default: ~/filestore-data)
    --port       Port to listen on (default: 8080)
    --host       Interface to bind (default: 127.0.0.1, use 0.0.0.0 for LAN/internet)
"""

import hashlib
import hmac as _hmac
import json
import mimetypes
import secrets
import time
from pathlib import Path

import bcrypt
import click
import uvicorn
from fastapi import FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, StreamingResponse

DEFAULT_DATA_DIR = Path.home() / "filestore-data"
DEFAULT_PORT     = 8080
DEFAULT_HOST     = "127.0.0.1"
CONFIG_FILE      = "config.json"

# Set at startup
_data_dir:       Path  | None = None
_private_hash:   bytes | None = None
_session_secret: str   | None = None

app = FastAPI(title="Filestore")


# ── Auth helpers ───────────────────────────────────────────────────────────────

def _sign(payload: str) -> str:
    return _hmac.new(_session_secret.encode(), payload.encode(), hashlib.sha256).hexdigest()

def _make_token() -> str:
    exp     = int(time.time()) + 86400 * 7   # 7-day expiry
    payload = f"private:{exp}"
    return   f"{payload}:{_sign(payload)}"

def _verify_token(token: str | None) -> bool:
    if not token or not _session_secret:
        return False
    try:
        *parts, sig = token.split(":")
        payload     = ":".join(parts)
        _area, exp_str = parts[0], parts[1]
        if int(exp_str) < time.time():
            return False
        return _hmac.compare_digest(sig, _sign(payload))
    except Exception:
        return False

def _bearer(authorization: str | None) -> str | None:
    return authorization[7:] if authorization and authorization.startswith("Bearer ") else None

def _require_private(authorization: str | None) -> None:
    if not _verify_token(_bearer(authorization)):
        raise HTTPException(401, "Private area requires authentication")


# ── Path helper ────────────────────────────────────────────────────────────────

def _resolve(area: str, path: str) -> Path:
    if area not in ("vestibule", "private"):
        raise HTTPException(400, "Invalid area")
    root = (_data_dir / area).resolve()
    full = (root / path.lstrip("/")).resolve()
    try:
        full.relative_to(root)
    except ValueError:
        raise HTTPException(403, "Path traversal not allowed")
    return full


# ── API ────────────────────────────────────────────────────────────────────────

@app.post("/api/auth")
async def api_auth(request: Request):
    body = await request.json()
    pw   = body.get("password", "").encode()
    if not _private_hash or not bcrypt.checkpw(pw, _private_hash):
        raise HTTPException(401, "Invalid password")
    return {"token": _make_token()}


@app.get("/api/ls")
async def api_ls(
    path:          str      = "/",
    area:          str      = "vestibule",
    authorization: str|None = Header(default=None),
):
    if area == "private":
        _require_private(authorization)
    full = _resolve(area, path)
    if not full.is_dir():
        raise HTTPException(404, "Not a directory")
    entries = []
    for item in sorted(full.iterdir(), key=lambda p: (p.is_file(), p.name.lower())):
        st = item.stat()
        entries.append({
            "name":     item.name,
            "is_dir":   item.is_dir(),
            "size":     st.st_size if item.is_file() else None,
            "modified": st.st_mtime,
        })
    return {"entries": entries}


@app.get("/api/file")
async def api_get_file(
    path:          str,
    area:          str      = "vestibule",
    authorization: str|None = Header(default=None),
):
    if area == "private":
        _require_private(authorization)
    full = _resolve(area, path)
    if not full.is_file():
        raise HTTPException(404, "File not found")
    mime, _ = mimetypes.guess_type(str(full))
    mime     = mime or "application/octet-stream"
    size     = full.stat().st_size
    def stream():
        with open(full, "rb") as f:
            while chunk := f.read(65536):
                yield chunk
    return StreamingResponse(stream(), media_type=mime, headers={
        "Content-Disposition": f'inline; filename="{full.name}"',
        "Content-Length":      str(size),
    })


@app.put("/api/file")
async def api_put_file(
    request:       Request,
    path:          str,
    area:          str      = "private",
    authorization: str|None = Header(default=None),
):
    if area == "vestibule":
        raise HTTPException(403, "Vestibule is read-only")
    _require_private(authorization)
    full = _resolve(area, path)
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_bytes(await request.body())
    return {"ok": True}


@app.delete("/api/file")
async def api_delete(
    path:          str,
    area:          str      = "private",
    authorization: str|None = Header(default=None),
):
    if area == "vestibule":
        raise HTTPException(403, "Vestibule is read-only")
    _require_private(authorization)
    full = _resolve(area, path)
    if not full.exists():
        raise HTTPException(404, "Not found")
    if full.is_dir():
        import shutil; shutil.rmtree(full)
    else:
        full.unlink()
    return {"ok": True}


@app.post("/api/mkdir")
async def api_mkdir(
    request:       Request,
    authorization: str|None = Header(default=None),
):
    body = await request.json()
    area = body.get("area", "private")
    if area == "vestibule":
        raise HTTPException(403, "Vestibule is read-only")
    _require_private(authorization)
    _resolve(area, body.get("path", "")).mkdir(parents=True, exist_ok=True)
    return {"ok": True}


@app.post("/api/upload")
async def api_upload(
    files:         list[UploadFile] = File(...),
    path:          str              = Form("/"),
    area:          str              = Form("private"),
    authorization: str|None         = Header(default=None),
):
    if area == "vestibule":
        raise HTTPException(403, "Vestibule is read-only")
    _require_private(authorization)
    saved = []
    for f in files:
        dest = _resolve(area, f"{path.rstrip('/')}/{f.filename}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "wb") as out:
            while chunk := await f.read(65536):
                out.write(chunk)
        saved.append(f.filename)
    return {"ok": True, "saved": saved}


# ── Frontend ───────────────────────────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Filestore</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600&display=swap');

:root {
  --blue:        #0060df;
  --blue-hover:  #0250bb;
  --blue-dim:    rgba(0,96,223,.10);
  --bg:          #ffffff;
  --surface:     #f9f9fb;
  --surface2:    #f0f0f4;
  --border:      #d7d7db;
  --text:        #15141a;
  --dim:         #6f6f7e;
  --header:      #1c1b22;
  --red:         #c50042;
  --green:       #017a40;
  --font:        'IBM Plex Sans', system-ui, sans-serif;
  --mono:        'IBM Plex Mono', 'Fira Code', monospace;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: var(--font);
  font-size: 13px;
  color: var(--text);
  background: var(--bg);
  height: 100dvh;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

/* ── Header ── */
header {
  background: var(--header);
  color: #fff;
  height: 46px;
  padding: 0 18px;
  display: flex;
  align-items: center;
  gap: 20px;
  flex-shrink: 0;
  user-select: none;
}
.logo {
  display: flex; align-items: center; gap: 8px;
  font-size: 15px; font-weight: 600; letter-spacing: -.3px; color: #fff;
}
.logo svg { flex-shrink: 0; }
.area-nav { display: flex; gap: 3px; }
.area-btn {
  background: none; border: none; color: rgba(255,255,255,.6);
  font: 500 12px var(--font); padding: 5px 13px; border-radius: 5px;
  cursor: pointer; transition: background .12s, color .12s;
}
.area-btn:hover  { background: rgba(255,255,255,.1); color: #fff; }
.area-btn.active { background: rgba(255,255,255,.16); color: #fff; }
.header-spacer { flex: 1; }
.header-note { font-size: 11px; color: rgba(255,255,255,.35); font-family: var(--mono); }

/* ── Toolbar ── */
.toolbar {
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  padding: 0 18px;
  height: 40px;
  display: flex; align-items: center; gap: 10px;
  flex-shrink: 0;
}
.breadcrumb { display: flex; align-items: center; gap: 1px; flex: 1; overflow: hidden; }
.bc-seg {
  color: var(--blue); cursor: pointer; padding: 3px 5px;
  border-radius: 4px; white-space: nowrap; font-size: 12px;
  max-width: 150px; overflow: hidden; text-overflow: ellipsis;
}
.bc-seg:hover { background: var(--blue-dim); }
.bc-seg.tail  { color: var(--text); cursor: default; font-weight: 500; }
.bc-sep { color: var(--dim); font-size: 11px; padding: 0 1px; }
.toolbar-actions { display: flex; gap: 6px; }

/* ── Workspace ── */
.workspace { display: flex; flex: 1; overflow: hidden; }

/* ── File pane ── */
.pane-files { flex: 1; overflow-y: auto; min-width: 0; }
.pane-files.drag-over {
  background: var(--blue-dim);
  outline: 2px dashed var(--blue); outline-offset: -3px;
}

/* ── File table ── */
.ftable { width: 100%; border-collapse: collapse; }
.ftable th {
  text-align: left; padding: 7px 16px;
  font: 600 10px/1 var(--font); text-transform: uppercase; letter-spacing: .6px;
  color: var(--dim); border-bottom: 1px solid var(--border);
  position: sticky; top: 0; background: var(--bg);
  cursor: pointer; user-select: none; white-space: nowrap;
}
.ftable th:hover { color: var(--text); }
.ftable th.sorted { color: var(--blue); }
.sort-ic { margin-left: 3px; opacity: .5; }
.ftable th.sorted .sort-ic { opacity: 1; }
.ftable td { padding: 6px 16px; border-bottom: 1px solid var(--border); }
.ftable tr:hover td { background: var(--surface); }
.ftable tr.sel td   { background: #dbeafe; }
.col-name { width: 100%; }
.col-size { text-align: right; color: var(--dim); min-width: 76px; font-family: var(--mono); font-size: 11px; }
.col-date { color: var(--dim); min-width: 148px; font-family: var(--mono); font-size: 11px; }
.col-del  { min-width: 34px; text-align: right; }
.name-cell {
  display: flex; align-items: center; gap: 8px;
  cursor: pointer; min-width: 0;
}
.name-cell:hover .name-txt { color: var(--blue); text-decoration: underline; }
.f-icon { width: 18px; text-align: center; font-size: 14px; flex-shrink: 0; }
.name-txt { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.del-btn {
  opacity: 0; background: none; border: none; color: var(--red);
  cursor: pointer; padding: 2px 5px; border-radius: 4px; font-size: 13px; line-height: 1;
}
.ftable tr:hover .del-btn { opacity: 1; }
.del-btn:hover { background: #ffe8ec; }

/* ── Preview pane ── */
.pane-preview {
  width: 420px; flex-shrink: 0;
  border-left: 1px solid var(--border);
  display: flex; flex-direction: column;
  background: var(--bg); overflow: hidden;
}
.preview-head {
  padding: 9px 14px;
  border-bottom: 1px solid var(--border);
  display: flex; align-items: center; gap: 8px;
  background: var(--surface); flex-shrink: 0;
}
.preview-title {
  flex: 1; font-weight: 600; font-size: 12px;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.preview-acts { display: flex; gap: 5px; align-items: center; }
.preview-body { flex: 1; overflow: auto; padding: 14px; }
.preview-body img { max-width: 100%; border-radius: 6px; display: block; }
.preview-body pre {
  font: 12px/1.65 var(--mono);
  white-space: pre-wrap; word-break: break-all; color: var(--text);
}
.preview-body iframe { width: 100%; min-height: 500px; border: none; }
.no-preview {
  height: 100%; display: flex; flex-direction: column;
  align-items: center; justify-content: center;
  gap: 10px; color: var(--dim); text-align: center;
}
.no-preview .big-icon { font-size: 44px; }
.edit-ta {
  width: 100%; height: 100%;
  font: 12px/1.65 var(--mono);
  border: 1px solid var(--border); border-radius: 6px;
  padding: 10px; resize: none; outline: none;
  color: var(--text); background: var(--bg);
  transition: border-color .12s, box-shadow .12s;
}
.edit-ta:focus { border-color: var(--blue); box-shadow: 0 0 0 3px var(--blue-dim); }
.editor-foot {
  padding: 9px 14px; border-top: 1px solid var(--border);
  display: flex; align-items: center; gap: 8px;
  background: var(--surface); flex-shrink: 0;
}
.save-st { font-size: 11px; color: var(--green); margin-left: 4px; }

/* ── Buttons ── */
.btn-primary {
  background: var(--blue); color: #fff; border: none;
  padding: 6px 15px; border-radius: 5px;
  font: 500 12px var(--font); cursor: pointer;
  transition: background .12s;
}
.btn-primary:hover   { background: var(--blue-hover); }
.btn-primary:active  { filter: brightness(.9); }
.btn-primary:disabled { opacity: .5; cursor: default; }
.btn {
  background: var(--surface2); color: var(--text);
  border: 1px solid var(--border);
  padding: 5px 11px; border-radius: 5px;
  font: 12px var(--font); cursor: pointer;
  transition: background .12s; white-space: nowrap;
}
.btn:hover  { background: var(--surface); border-color: #b9b9c8; }
.btn-ghost {
  background: none; color: var(--dim); border: none;
  padding: 5px 9px; border-radius: 5px;
  font: 12px var(--font); cursor: pointer;
}
.btn-ghost:hover { background: var(--surface2); color: var(--text); }

/* ── Input ── */
.field {
  width: 100%; padding: 8px 11px;
  border: 1px solid var(--border); border-radius: 5px;
  font: 13px var(--font); outline: none; color: var(--text);
  background: var(--bg); transition: border-color .12s, box-shadow .12s;
}
.field:focus { border-color: var(--blue); box-shadow: 0 0 0 3px var(--blue-dim); }

/* ── Modal ── */
.overlay {
  position: fixed; inset: 0; background: rgba(0,0,0,.45);
  display: flex; align-items: center; justify-content: center;
  z-index: 100; backdrop-filter: blur(3px);
}
.modal {
  background: var(--bg); border-radius: 10px; padding: 24px;
  width: 360px; box-shadow: 0 24px 64px rgba(0,0,0,.28);
  display: flex; flex-direction: column; gap: 14px;
}
.modal h3 { font-size: 16px; font-weight: 600; }
.modal p  { font-size: 12px; color: var(--dim); line-height: 1.6; }
.modal-foot { display: flex; gap: 7px; justify-content: flex-end; }
.err-txt { font-size: 11px; color: var(--red); min-height: 16px; }

/* ── Toast ── */
.toast {
  position: fixed; bottom: 22px; left: 50%;
  transform: translateX(-50%) translateY(70px);
  background: var(--header); color: #fff;
  padding: 9px 18px; border-radius: 7px; font-size: 12px;
  transition: transform .2s ease; z-index: 200;
  pointer-events: none; box-shadow: 0 4px 20px rgba(0,0,0,.3);
  white-space: nowrap;
}
.toast.show  { transform: translateX(-50%) translateY(0); }
.toast.err   { background: var(--red); }

/* ── Empty / loading ── */
.empty {
  padding: 56px 20px; text-align: center;
  color: var(--dim); font-size: 13px; line-height: 1.7;
}
.empty .ic { font-size: 36px; margin-bottom: 10px; }
.loading-row td { padding: 36px; text-align: center; color: var(--dim); }
</style>
</head>
<body>

<!-- Header -->
<header>
  <div class="logo">
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
      <rect x="2" y="2" width="7" height="7" rx="1.5" fill="rgba(255,255,255,.7)"/>
      <rect x="11" y="2" width="7" height="7" rx="1.5" fill="rgba(255,255,255,.7)"/>
      <rect x="2" y="11" width="7" height="7" rx="1.5" fill="rgba(255,255,255,.7)"/>
      <rect x="11" y="11" width="7" height="7" rx="1.5" fill="#0060df"/>
    </svg>
    Filestore
  </div>
  <nav class="area-nav">
    <button class="area-btn active" data-area="vestibule">Vestibule</button>
    <button class="area-btn"        data-area="private">🔒 Private</button>
  </nav>
  <div class="header-spacer"></div>
  <span class="header-note" id="hdr-note"></span>
</header>

<!-- Toolbar -->
<div class="toolbar">
  <div class="breadcrumb" id="breadcrumb"></div>
  <div class="toolbar-actions" id="toolbar-actions" style="display:none">
    <button class="btn" id="btn-upload">↑ Upload</button>
    <button class="btn" id="btn-mkdir">+ Folder</button>
  </div>
</div>

<!-- Workspace -->
<div class="workspace">

  <!-- File list -->
  <div class="pane-files" id="pane-files">
    <table class="ftable">
      <thead>
        <tr>
          <th class="col-name sorted" data-sort="name">Name <span class="sort-ic">↑</span></th>
          <th class="col-size" data-sort="size">Size <span class="sort-ic">↕</span></th>
          <th class="col-date" data-sort="modified">Modified <span class="sort-ic">↕</span></th>
          <th class="col-del"></th>
        </tr>
      </thead>
      <tbody id="tbody"></tbody>
    </table>
  </div>

  <!-- Preview pane (hidden until file selected) -->
  <div class="pane-preview" id="pane-preview" style="display:none">
    <div class="preview-head">
      <span class="preview-title" id="preview-title"></span>
      <div class="preview-acts">
        <button class="btn" id="btn-edit"     style="display:none">Edit</button>
        <button class="btn" id="btn-download">↓ Download</button>
        <button class="btn-ghost" id="btn-close-preview">✕</button>
      </div>
    </div>
    <div class="preview-body" id="preview-body" style="height:calc(100% - 44px - 0px)"></div>
    <div class="editor-foot" id="editor-foot" style="display:none">
      <button class="btn-primary" id="btn-save">Save</button>
      <button class="btn-ghost"   id="btn-cancel-edit">Cancel</button>
      <span class="save-st" id="save-st"></span>
    </div>
  </div>

</div><!-- workspace -->

<!-- Auth modal -->
<div class="overlay" id="modal-auth" style="display:none">
  <div class="modal">
    <h3>🔒 Private Area</h3>
    <p>Enter your password to access private files.</p>
    <input class="field" type="password" id="auth-pw" placeholder="Password" autocomplete="current-password">
    <div class="modal-foot">
      <button class="btn-ghost"   id="btn-auth-cancel">Cancel</button>
      <button class="btn-primary" id="btn-auth-ok">Unlock</button>
    </div>
    <p class="err-txt" id="auth-err"></p>
  </div>
</div>

<!-- Mkdir modal -->
<div class="overlay" id="modal-mkdir" style="display:none">
  <div class="modal">
    <h3>New Folder</h3>
    <input class="field" type="text" id="mkdir-name" placeholder="Folder name">
    <div class="modal-foot">
      <button class="btn-ghost"   id="btn-mkdir-cancel">Cancel</button>
      <button class="btn-primary" id="btn-mkdir-ok">Create</button>
    </div>
  </div>
</div>

<!-- Toast -->
<div class="toast" id="toast"></div>

<!-- Hidden file input -->
<input type="file" id="file-input" multiple style="display:none">

<script>
// ── State ──────────────────────────────────────────────────────────────────────
const S = {
  area:     'vestibule',
  path:     '/',
  token:    localStorage.getItem('fs_token') || '',
  entries:  [],
  sort:     { by: 'name', asc: true },
  sel:      null,   // { name, path }
  editing:  false,
  origText: '',
};

// ── Utilities ──────────────────────────────────────────────────────────────────
const fmtSize = n => {
  if (n == null) return '—';
  if (n < 1024)       return n + ' B';
  if (n < 1048576)    return (n/1024).toFixed(1)    + ' KB';
  if (n < 1073741824) return (n/1048576).toFixed(1) + ' MB';
  return (n/1073741824).toFixed(2) + ' GB';
};

const fmtDate = ts => {
  const d = new Date(ts * 1000);
  return d.toLocaleDateString(undefined, {year:'numeric',month:'short',day:'numeric'})
       + ' ' + d.toLocaleTimeString(undefined, {hour:'2-digit',minute:'2-digit'});
};

const fileIcon = (name, isDir) => {
  if (isDir) return '📁';
  const e = name.split('.').pop().toLowerCase();
  return ({
    png:'🖼️',jpg:'🖼️',jpeg:'🖼️',gif:'🖼️',webp:'🖼️',svg:'🖼️',bmp:'🖼️',ico:'🖼️',
    pdf:'📕',
    doc:'📘',docx:'📘',odt:'📘',
    xls:'📗',xlsx:'📗',csv:'📊',
    ppt:'📙',pptx:'📙',
    py:'🐍',js:'📜',ts:'📜',jsx:'📜',tsx:'📜',
    html:'🌐',htm:'🌐',css:'🎨',scss:'🎨',
    json:'📋',xml:'📋',yaml:'📋',yml:'📋',toml:'📋',
    md:'📝',txt:'📄',rst:'📄',
    sh:'⚙️',bash:'⚙️',zsh:'⚙️',fish:'⚙️',
    zip:'📦',tar:'📦',gz:'📦',bz2:'📦',rar:'📦',
    mp3:'🎵',wav:'🎵',flac:'🎵',ogg:'🎵',
    mp4:'🎬',mov:'🎬',mkv:'🎬',webm:'🎬',
  }[e] || '📄');
};

const TEXT_EXT = new Set(['txt','md','py','js','ts','jsx','tsx','html','htm',
  'css','scss','json','xml','yaml','yml','toml','sh','bash','zsh','fish',
  'env','gitignore','csv','log','cfg','conf','ini','svg','rs','go','java',
  'c','cpp','h','rb','php','swift','kt','r','sql','lua','vim','dockerfile',
  'rst','makefile','license','readme']);
const IMG_EXT  = new Set(['png','jpg','jpeg','gif','webp','svg','bmp','ico']);
const isText  = n => TEXT_EXT.has(n.split('.').pop().toLowerCase()) || !n.includes('.');
const isImage = n => IMG_EXT.has(n.split('.').pop().toLowerCase());
const isPdf   = n => n.toLowerCase().endsWith('.pdf');

const authHdr = () => S.token ? {'Authorization': 'Bearer ' + S.token} : {};
const join    = (a, b) => (a.replace(/\/$/, '') + '/' + b).replace(/^\/\//, '/');
const esc     = s => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

// ── Toast ──────────────────────────────────────────────────────────────────────
let _toastTimer;
function toast(msg, isErr = false) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = 'toast show' + (isErr ? ' err' : '');
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => el.className = 'toast', 2600);
}

// ── Navigation ─────────────────────────────────────────────────────────────────
async function navigate(path) {
  S.path = path; S.sel = null; closePreview(); await refresh();
}

async function refresh() {
  document.getElementById('tbody').innerHTML =
    '<tr class="loading-row"><td colspan="4">Loading…</td></tr>';
  renderBreadcrumb();

  const r = await fetch(
    `/api/ls?path=${encodeURIComponent(S.path)}&area=${S.area}`,
    { headers: authHdr() }
  );
  if (r.status === 401) { showAuth(); return; }
  if (!r.ok) {
    document.getElementById('tbody').innerHTML =
      '<tr class="loading-row"><td colspan="4">Failed to load.</td></tr>';
    return;
  }
  S.entries = (await r.json()).entries;
  renderList();
}

// ── Render: breadcrumb ─────────────────────────────────────────────────────────
function renderBreadcrumb() {
  const parts = S.path.split('/').filter(Boolean);
  const icon  = S.area === 'private' ? '🔒' : '📂';
  let html = `<span class="bc-seg ${!parts.length ? 'tail' : ''}"
    ${parts.length ? "onclick=\"navigate('/')\"" : ''}>
    ${icon} ${S.area === 'private' ? 'Private' : 'Vestibule'}
  </span>`;
  parts.forEach((p, i) => {
    const sub = '/' + parts.slice(0, i+1).join('/');
    const last = i === parts.length - 1;
    html += `<span class="bc-sep">›</span>
      <span class="bc-seg ${last ? 'tail' : ''}"
        ${!last ? `onclick="navigate('${sub.replace(/'/g,"\\'")}')"` : ''}>
        ${p}
      </span>`;
  });
  document.getElementById('breadcrumb').innerHTML = html;
  const priv = S.area === 'private';
  document.getElementById('toolbar-actions').style.display = priv ? 'flex' : 'none';
  document.getElementById('hdr-note').textContent = priv ? '' : 'read-only';
}

// ── Render: file list ──────────────────────────────────────────────────────────
function renderList() {
  const sorted = [...S.entries].sort((a, b) => {
    if (a.is_dir !== b.is_dir) return a.is_dir ? -1 : 1;
    let va = a[S.sort.by] ?? '', vb = b[S.sort.by] ?? '';
    if (typeof va === 'string') va = va.toLowerCase();
    if (typeof vb === 'string') vb = vb.toLowerCase();
    return (S.sort.asc ? 1 : -1) * (va < vb ? -1 : va > vb ? 1 : 0);
  });

  if (!sorted.length) {
    document.getElementById('tbody').innerHTML =
      `<tr><td colspan="4"><div class="empty"><div class="ic">📭</div>This folder is empty</div></td></tr>`;
    return;
  }

  document.getElementById('tbody').innerHTML = sorted.map(e => {
    const fp  = join(S.path, e.name);
    const sfp = fp.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
    const sn  = e.name.replace(/\\/g,'\\\\').replace(/'/g,"\\'");
    const sel = S.sel?.name === e.name ? ' sel' : '';
    const act = e.is_dir
      ? `navigate('${sfp}')`
      : `openFile('${sfp}','${sn}')`;
    return `<tr class="${sel}">
      <td class="col-name">
        <div class="name-cell" onclick="${act}">
          <span class="f-icon">${fileIcon(e.name, e.is_dir)}</span>
          <span class="name-txt">${e.name}${e.is_dir ? '/' : ''}</span>
        </div>
      </td>
      <td class="col-size">${fmtSize(e.size)}</td>
      <td class="col-date">${fmtDate(e.modified)}</td>
      <td class="col-del">
        ${S.area === 'private'
          ? `<button class="del-btn" title="Delete"
              onclick="confirmDelete('${sfp}','${sn}',${e.is_dir})">🗑</button>`
          : ''}
      </td>
    </tr>`;
  }).join('');
}

// ── Sort ───────────────────────────────────────────────────────────────────────
function sortBy(col) {
  S.sort = { by: col, asc: S.sort.by === col ? !S.sort.asc : true };
  renderList();
  document.querySelectorAll('.ftable th').forEach(th => {
    const me = th.dataset.sort === col;
    th.classList.toggle('sorted', me);
    if (th.querySelector('.sort-ic'))
      th.querySelector('.sort-ic').textContent = me ? (S.sort.asc ? '↑' : '↓') : '↕';
  });
}

// ── Preview ────────────────────────────────────────────────────────────────────
async function openFile(fp, name) {
  S.sel = { name, path: fp }; S.editing = false;
  renderList();

  const preview  = document.getElementById('pane-preview');
  const body     = document.getElementById('preview-body');
  const foot     = document.getElementById('editor-foot');
  const btnEdit  = document.getElementById('btn-edit');

  preview.style.display = 'flex';
  document.getElementById('preview-title').textContent = name;
  body.innerHTML = '<div class="empty" style="height:100%"><div class="ic">⏳</div>Loading…</div>';
  foot.style.display = 'none';
  document.getElementById('btn-download').style.display = '';
  btnEdit.style.display = (S.area === 'private' && isText(name)) ? '' : 'none';
  body.style.padding = '14px';

  const url = `/api/file?path=${encodeURIComponent(fp)}&area=${S.area}`;

  if (isImage(name)) {
    const blob = await fetch(url, { headers: authHdr() }).then(r => r.blob());
    const obj  = URL.createObjectURL(blob);
    body.innerHTML = `<img src="${obj}" alt="${name}" onload="URL.revokeObjectURL(this.src)">`;

  } else if (isPdf(name)) {
    const blob = await fetch(url, { headers: authHdr() }).then(r => r.blob());
    const obj  = URL.createObjectURL(blob);
    body.style.padding = '0';
    body.innerHTML     = `<iframe src="${obj}" style="width:100%;height:100%"></iframe>`;

  } else if (isText(name)) {
    const r    = await fetch(url, { headers: authHdr() });
    const text = await r.text();
    S.origText = text;
    body.innerHTML = `<pre>${esc(text)}</pre>`;

  } else {
    body.innerHTML = `<div class="no-preview">
      <div class="big-icon">${fileIcon(name, false)}</div>
      <div>No preview available</div>
      <button class="btn" onclick="downloadFile()">↓ Download</button>
    </div>`;
  }
}

function closePreview() {
  document.getElementById('pane-preview').style.display = 'none';
  S.sel = null; S.editing = false;
}

function downloadFile() {
  if (!S.sel) return;
  const url = `/api/file?path=${encodeURIComponent(S.sel.path)}&area=${S.area}`;
  fetch(url, { headers: authHdr() })
    .then(r => r.blob())
    .then(blob => {
      const a = Object.assign(document.createElement('a'), {
        href: URL.createObjectURL(blob), download: S.sel.name
      });
      a.click();
    });
}

// ── Editor ─────────────────────────────────────────────────────────────────────
function startEdit() {
  if (!S.sel) return;
  S.editing = true;
  const body = document.getElementById('preview-body');
  const ta   = document.createElement('textarea');
  ta.className  = 'edit-ta';
  ta.value      = S.origText;
  ta.style.height = '100%';
  ta.addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key === 's') { e.preventDefault(); saveEdit(ta.value); }
  });
  body.innerHTML = '';
  body.appendChild(ta);
  ta.focus();

  document.getElementById('editor-foot').style.display = 'flex';
  document.getElementById('save-st').textContent = '';
  document.getElementById('btn-edit').style.display     = 'none';
  document.getElementById('btn-download').style.display = 'none';
}

async function saveEdit(content) {
  const st = document.getElementById('save-st');
  st.textContent = 'Saving…';
  const r = await fetch(
    `/api/file?path=${encodeURIComponent(S.sel.path)}&area=${S.area}`,
    { method: 'PUT', headers: { ...authHdr(), 'Content-Type': 'text/plain' }, body: content }
  );
  if (r.ok) {
    S.origText = content;
    st.textContent = '✓ Saved';
    toast('File saved');
    setTimeout(() => st.textContent = '', 3000);
  } else {
    st.textContent = '✗ Error';
    toast('Save failed', true);
  }
}

function cancelEdit() {
  S.editing = false;
  document.getElementById('editor-foot').style.display        = 'none';
  document.getElementById('btn-edit').style.display           = S.area === 'private' ? '' : 'none';
  document.getElementById('btn-download').style.display       = '';
  document.getElementById('preview-body').innerHTML = `<pre>${esc(S.origText)}</pre>`;
}

// ── Delete ─────────────────────────────────────────────────────────────────────
function confirmDelete(fp, name, isDir) {
  if (!confirm(`Delete "${name}"${isDir ? ' and all its contents' : ''}?`)) return;
  fetch(`/api/file?path=${encodeURIComponent(fp)}&area=${S.area}`,
    { method: 'DELETE', headers: authHdr() })
    .then(r => {
      if (r.ok) { toast(`Deleted ${name}`); if (S.sel?.name === name) closePreview(); refresh(); }
      else toast('Delete failed', true);
    });
}

// ── Mkdir ──────────────────────────────────────────────────────────────────────
function showMkdir() {
  document.getElementById('modal-mkdir').style.display = 'flex';
  const inp = document.getElementById('mkdir-name');
  inp.value = ''; setTimeout(() => inp.focus(), 30);
}
function hideMkdir() { document.getElementById('modal-mkdir').style.display = 'none'; }

async function doMkdir() {
  const name = document.getElementById('mkdir-name').value.trim();
  if (!name) return;
  const r = await fetch('/api/mkdir', {
    method: 'POST',
    headers: { ...authHdr(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ area: S.area, path: join(S.path, name) }),
  });
  if (r.ok) { toast(`Created ${name}/`); hideMkdir(); refresh(); }
  else toast('Failed to create folder', true);
}

// ── Upload ─────────────────────────────────────────────────────────────────────
async function uploadFiles(fileList) {
  const form = new FormData();
  for (const f of fileList) form.append('files', f);
  form.append('path', S.path);
  form.append('area', S.area);
  const r = await fetch('/api/upload', { method: 'POST', headers: authHdr(), body: form });
  if (r.ok) {
    const d = await r.json();
    toast(`Uploaded ${d.saved.length} file${d.saved.length !== 1 ? 's' : ''}`);
    refresh();
  } else toast('Upload failed', true);
}

// ── Auth ───────────────────────────────────────────────────────────────────────
function showAuth() {
  document.getElementById('modal-auth').style.display = 'flex';
  document.getElementById('auth-pw').value            = '';
  document.getElementById('auth-err').textContent     = '';
  setTimeout(() => document.getElementById('auth-pw').focus(), 30);
}

function hideAuth() {
  document.getElementById('modal-auth').style.display = 'none';
  if (S.area === 'private') switchArea('vestibule', true);
}

async function doAuth() {
  const pw  = document.getElementById('auth-pw').value;
  const btn = document.getElementById('btn-auth-ok');
  btn.disabled = true; btn.textContent = 'Checking…';
  const r = await fetch('/api/auth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: pw }),
  });
  btn.disabled = false; btn.textContent = 'Unlock';
  if (r.ok) {
    S.token = (await r.json()).token;
    localStorage.setItem('fs_token', S.token);
    document.getElementById('modal-auth').style.display = 'none';
    refresh();
  } else {
    document.getElementById('auth-err').textContent = 'Incorrect password.';
  }
}

// ── Area switch ────────────────────────────────────────────────────────────────
async function switchArea(area, skipRefresh = false) {
  if (area === S.area && !skipRefresh) return;
  S.area = area; S.path = '/'; S.sel = null; closePreview();
  document.querySelectorAll('.area-btn').forEach(b =>
    b.classList.toggle('active', b.dataset.area === area));
  if (area === 'private' && !S.token) { showAuth(); return; }
  if (!skipRefresh) await refresh();
}

// ── Drag & drop ────────────────────────────────────────────────────────────────
function setupDnD() {
  const pane = document.getElementById('pane-files');
  pane.addEventListener('dragover', e => {
    if (S.area !== 'private') return;
    e.preventDefault(); pane.classList.add('drag-over');
  });
  pane.addEventListener('dragleave', e => {
    if (!pane.contains(e.relatedTarget)) pane.classList.remove('drag-over');
  });
  pane.addEventListener('drop', async e => {
    e.preventDefault(); pane.classList.remove('drag-over');
    if (S.area !== 'private') { toast('Vestibule is read-only', true); return; }
    if (e.dataTransfer.files.length) await uploadFiles(e.dataTransfer.files);
  });
}

// ── Init ───────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  // Buttons
  document.getElementById('btn-upload').addEventListener('click', () =>
    document.getElementById('file-input').click());
  document.getElementById('btn-mkdir').addEventListener('click', showMkdir);
  document.getElementById('btn-close-preview').addEventListener('click', closePreview);
  document.getElementById('btn-download').addEventListener('click', downloadFile);
  document.getElementById('btn-edit').addEventListener('click', startEdit);
  document.getElementById('btn-save').addEventListener('click', () => {
    const ta = document.querySelector('.edit-ta'); if (ta) saveEdit(ta.value);
  });
  document.getElementById('btn-cancel-edit').addEventListener('click', cancelEdit);

  // Auth modal
  document.getElementById('btn-auth-ok').addEventListener('click', doAuth);
  document.getElementById('btn-auth-cancel').addEventListener('click', hideAuth);
  document.getElementById('auth-pw').addEventListener('keydown', e => {
    if (e.key === 'Enter') doAuth();
    if (e.key === 'Escape') hideAuth();
  });

  // Mkdir modal
  document.getElementById('btn-mkdir-ok').addEventListener('click', doMkdir);
  document.getElementById('btn-mkdir-cancel').addEventListener('click', hideMkdir);
  document.getElementById('mkdir-name').addEventListener('keydown', e => {
    if (e.key === 'Enter') doMkdir();
    if (e.key === 'Escape') hideMkdir();
  });

  // File input
  document.getElementById('file-input').addEventListener('change', e => {
    if (e.target.files.length) uploadFiles(e.target.files);
    e.target.value = '';
  });

  // Area tabs
  document.querySelectorAll('.area-btn').forEach(b =>
    b.addEventListener('click', () => switchArea(b.dataset.area)));

  // Sort headers
  document.querySelectorAll('.ftable th[data-sort]').forEach(th =>
    th.addEventListener('click', () => sortBy(th.dataset.sort)));

  // Modal overlay click-outside
  document.getElementById('modal-auth').addEventListener('click', e => {
    if (e.target === e.currentTarget) hideAuth();
  });
  document.getElementById('modal-mkdir').addEventListener('click', e => {
    if (e.target === e.currentTarget) hideMkdir();
  });

  setupDnD();
  await refresh();
});
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTML


# ── CLI ────────────────────────────────────────────────────────────────────────

@click.command()
@click.option("--data-dir", default=str(DEFAULT_DATA_DIR), show_default=True, help="Storage root")
@click.option("--port",     default=DEFAULT_PORT,          show_default=True, help="Port to listen on")
@click.option("--host",     default=DEFAULT_HOST,          show_default=True, help="Interface to bind (0.0.0.0 for LAN/internet)")
def main(data_dir, port, host):
    """Start the Filestore web UI."""
    global _data_dir, _private_hash, _session_secret

    _data_dir   = Path(data_dir)
    config_path = _data_dir / CONFIG_FILE

    if not config_path.exists():
        click.echo(f"Config not found at {config_path}. Run 'python server.py start' first.")
        raise SystemExit(1)

    with open(config_path) as f:
        config = json.load(f)

    _private_hash   = config["private_password_hash"].encode()
    _session_secret = config.get("session_secret") or secrets.token_hex(32)

    if "session_secret" not in config:
        config["session_secret"] = _session_secret
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)

    click.echo(f"\n✓ Filestore web UI → http://{host if host != '0.0.0.0' else 'localhost'}:{port}")
    if host == "0.0.0.0":
        click.echo("  Listening on all interfaces (LAN/internet accessible)")
    click.echo()

    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    main()