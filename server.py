#!/usr/bin/env python3
"""
pond server  —  SSH file server + web UI in one process.

    pond-server start    Start both servers (default)
    pond-server passwd   Change the private-area password
"""

import asyncio
import hashlib
import hmac as _hmac
import json
import mimetypes
import os
import secrets
import stat as _stat
import time
from pathlib import Path

import asyncssh
import bcrypt
import click
import uvicorn
from fastapi import FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, StreamingResponse

# ── Defaults ───────────────────────────────────────────────────────────────────
DEFAULT_DATA_DIR = Path.home() / ".pond"
DEFAULT_SSH_PORT = 8022
DEFAULT_WEB_PORT = 8080
DEFAULT_WEB_HOST = "0.0.0.0"
CONFIG_FILE      = "config.json"
HOST_KEY_FILE    = "host_key"


# ══════════════════════════════════════════════════════════════════════════════
#  SSH SERVER
# ══════════════════════════════════════════════════════════════════════════════

class _ReadOnlySFTP(asyncssh.SFTPServer):
    _W = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC
    _D = "Vestibule is read-only"
    def open(self, path, pflags, attrs):
        if pflags & self._W:
            raise asyncssh.SFTPError(asyncssh.FX_PERMISSION_DENIED, self._D)
        return super().open(path, pflags, attrs)
    def remove(self, path):        raise asyncssh.SFTPError(asyncssh.FX_PERMISSION_DENIED, self._D)
    def rename(self, old, new):    raise asyncssh.SFTPError(asyncssh.FX_PERMISSION_DENIED, self._D)
    def mkdir(self, path, attrs):  raise asyncssh.SFTPError(asyncssh.FX_PERMISSION_DENIED, self._D)
    def rmdir(self, path):         raise asyncssh.SFTPError(asyncssh.FX_PERMISSION_DENIED, self._D)


def _make_sftp_factory(data_dir: Path):
    def factory(conn):
        username = conn.get_extra_info("username")
        if username == "admin":
            return asyncssh.SFTPServer(conn, chroot=str(data_dir / "private"))
        return _ReadOnlySFTP(conn, chroot=str(data_dir / "vestibule"))
    return factory


def _make_ssh_server_class(private_hash: bytes):
    class _Server(asyncssh.SSHServer):
        def begin_auth(self, username):
            return username != "guest"
        def password_auth_supported(self):
            return True
        def validate_password(self, username, password):
            return username == "admin" and bcrypt.checkpw(password.encode(), private_hash)
    return _Server


# ══════════════════════════════════════════════════════════════════════════════
#  WEB SERVER
# ══════════════════════════════════════════════════════════════════════════════

web_app = FastAPI(title="Pond")

# State set at startup
_data_dir:       Path  | None = None
_private_hash:   bytes | None = None
_session_secret: str   | None = None


# ── Web auth ───────────────────────────────────────────────────────────────────

def _sign(p: str) -> str:
    return _hmac.new(_session_secret.encode(), p.encode(), hashlib.sha256).hexdigest()

def _make_token() -> str:
    payload = f"private:{int(time.time()) + 86400 * 7}"
    return f"{payload}:{_sign(payload)}"

def _verify_token(token: str | None) -> bool:
    if not token or not _session_secret:
        return False
    try:
        *parts, sig = token.split(":")
        payload = ":".join(parts)
        if int(parts[1]) < time.time():
            return False
        return _hmac.compare_digest(sig, _sign(payload))
    except Exception:
        return False

def _bearer(auth: str | None) -> str | None:
    return auth[7:] if auth and auth.startswith("Bearer ") else None

def _require_private(auth: str | None) -> None:
    if not _verify_token(_bearer(auth)):
        raise HTTPException(401, "Private area requires authentication")


# ── Web path helper ────────────────────────────────────────────────────────────

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


# ── Web routes ─────────────────────────────────────────────────────────────────

@web_app.post("/api/auth")
async def api_auth(request: Request):
    pw = (await request.json()).get("password", "").encode()
    if not _private_hash or not bcrypt.checkpw(pw, _private_hash):
        raise HTTPException(401, "Invalid password")
    return {"token": _make_token()}


@web_app.get("/api/ls")
async def api_ls(path: str = "/", area: str = "vestibule",
                 authorization: str | None = Header(default=None)):
    if area == "private":
        _require_private(authorization)
    full = _resolve(area, path)
    if not full.is_dir():
        raise HTTPException(404, "Not a directory")
    entries = []
    for item in sorted(full.iterdir(), key=lambda p: (p.is_file(), p.name.lower())):
        st = item.stat()
        entries.append({"name": item.name, "is_dir": item.is_dir(),
                         "size": st.st_size if item.is_file() else None,
                         "modified": st.st_mtime})
    return {"entries": entries}


@web_app.get("/api/file")
async def api_get_file(path: str, area: str = "vestibule",
                       authorization: str | None = Header(default=None)):
    if area == "private":
        _require_private(authorization)
    full = _resolve(area, path)
    if not full.is_file():
        raise HTTPException(404, "File not found")
    mime, _ = mimetypes.guess_type(str(full))
    def stream():
        with open(full, "rb") as f:
            while chunk := f.read(65536): yield chunk
    return StreamingResponse(stream(), media_type=mime or "application/octet-stream",
                             headers={"Content-Disposition": f'inline; filename="{full.name}"',
                                      "Content-Length": str(full.stat().st_size)})


@web_app.put("/api/file")
async def api_put(request: Request, path: str, area: str = "private",
                  authorization: str | None = Header(default=None)):
    if area == "vestibule": raise HTTPException(403, "Vestibule is read-only")
    _require_private(authorization)
    full = _resolve(area, path)
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_bytes(await request.body())
    return {"ok": True}


@web_app.delete("/api/file")
async def api_delete(path: str, area: str = "private",
                     authorization: str | None = Header(default=None)):
    if area == "vestibule": raise HTTPException(403, "Vestibule is read-only")
    _require_private(authorization)
    full = _resolve(area, path)
    if not full.exists(): raise HTTPException(404, "Not found")
    if full.is_dir():
        import shutil; shutil.rmtree(full)
    else:
        full.unlink()
    return {"ok": True}


@web_app.post("/api/mkdir")
async def api_mkdir(request: Request, authorization: str | None = Header(default=None)):
    body = await request.json()
    area = body.get("area", "private")
    if area == "vestibule": raise HTTPException(403, "Vestibule is read-only")
    _require_private(authorization)
    _resolve(area, body.get("path", "")).mkdir(parents=True, exist_ok=True)
    return {"ok": True}


@web_app.post("/api/upload")
async def api_upload(files: list[UploadFile] = File(...),
                     path: str = Form("/"), area: str = Form("private"),
                     authorization: str | None = Header(default=None)):
    if area == "vestibule": raise HTTPException(403, "Vestibule is read-only")
    _require_private(authorization)
    saved = []
    for f in files:
        dest = _resolve(area, f"{path.rstrip('/')}/{f.filename}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "wb") as out:
            while chunk := await f.read(65536): out.write(chunk)
        saved.append(f.filename)
    return {"ok": True, "saved": saved}


@web_app.get("/", response_class=HTMLResponse)
async def index():
    return _HTML


# ══════════════════════════════════════════════════════════════════════════════
#  CONFIG HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _load_or_create_config(data_dir: Path, password: str | None) -> dict:
    path = data_dir / CONFIG_FILE
    if path.exists():
        with open(path) as f:
            return json.load(f)
    if not password:
        password = click.prompt("Set private-area password",
                                hide_input=True, confirmation_prompt=True)
    config = {"private_password_hash": bcrypt.hashpw(
        password.encode(), bcrypt.gensalt()).decode()}
    with open(path, "w") as f:
        json.dump(config, f, indent=2)
    return config


def _ensure_session_secret(config: dict, path: Path) -> str:
    if "session_secret" not in config:
        config["session_secret"] = secrets.token_hex(32)
        with open(path, "w") as f:
            json.dump(config, f, indent=2)
    return config["session_secret"]


# ══════════════════════════════════════════════════════════════════════════════
#  COMBINED RUNNER
# ══════════════════════════════════════════════════════════════════════════════

async def _run(data_dir: Path, ssh_port: int,
               web_host: str, web_port: int, config: dict):
    global _data_dir, _private_hash, _session_secret

    # Web state
    _data_dir       = data_dir
    _private_hash   = config["private_password_hash"].encode()
    _session_secret = _ensure_session_secret(config, data_dir / CONFIG_FILE)

    # SSH host key
    key_path = data_dir / HOST_KEY_FILE
    if not key_path.exists():
        click.echo("  Generating SSH host key…")
        k = asyncssh.generate_private_key("ssh-ed25519")
        k.write_private_key(str(key_path))
        os.chmod(key_path, _stat.S_IRUSR | _stat.S_IWUSR)

    ssh_class   = _make_ssh_server_class(config["private_password_hash"].encode())
    sftp_factory = _make_sftp_factory(data_dir)

    ssh_server = await asyncssh.create_server(
        ssh_class, host="", port=ssh_port,
        server_host_keys=[str(key_path)],
        sftp_factory=sftp_factory, allow_scp=True,
    )

    uvi = uvicorn.Server(
        uvicorn.Config(web_app, host=web_host, port=web_port, log_level="warning")
    )

    click.echo(f"\n🌿 Pond is running\n")
    click.echo(f"   SSH  →  port {ssh_port}   (pond --host <ip> ls)")
    click.echo(f"   Web  →  http://{'localhost' if web_host == '127.0.0.1' else web_host}:{web_port}")
    click.echo(f"\n   Data →  {data_dir}\n")

    async with ssh_server:
        await uvi.serve()


# ══════════════════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════════════════

@click.group()
def cli():
    """Pond server — SSH file store + web UI."""


@cli.command("start")
@click.option("--data-dir",  default=str(DEFAULT_DATA_DIR), show_default=True)
@click.option("--ssh-port",  default=DEFAULT_SSH_PORT,      show_default=True)
@click.option("--web-port",  default=DEFAULT_WEB_PORT,      show_default=True)
@click.option("--web-host",  default=DEFAULT_WEB_HOST,      show_default=True,
              help="Interface for web UI (0.0.0.0 = all, 127.0.0.1 = local only)")
@click.option("--password",  default=None,
              help="Private-area password (prompted on first run)")
def start(data_dir, ssh_port, web_port, web_host, password):
    """Start the SSH server and web UI together."""
    dd = Path(data_dir)
    (dd / "vestibule").mkdir(parents=True, exist_ok=True)
    (dd / "private").mkdir(parents=True, exist_ok=True)
    config = _load_or_create_config(dd, password)
    try:
        asyncio.run(_run(dd, ssh_port, web_host, web_port, config))
    except KeyboardInterrupt:
        click.echo("\n  Pond stopped.")


@cli.command("passwd")
@click.option("--data-dir", default=str(DEFAULT_DATA_DIR), show_default=True)
def passwd(data_dir):
    """Change the private-area password."""
    path = Path(data_dir) / CONFIG_FILE
    if not path.exists():
        click.echo("No config found. Run 'pond-server start' first.")
        raise SystemExit(1)
    with open(path) as f:
        config = json.load(f)
    new_pw = click.prompt("New password", hide_input=True, confirmation_prompt=True)
    config["private_password_hash"] = bcrypt.hashpw(
        new_pw.encode(), bcrypt.gensalt()).decode()
    with open(path, "w") as f:
        json.dump(config, f, indent=2)
    click.echo("Password updated.")


# ══════════════════════════════════════════════════════════════════════════════
#  WEB UI HTML
# ══════════════════════════════════════════════════════════════════════════════

_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Pond</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600&display=swap');

:root {
  --blue:       #0060df;
  --blue-hover: #0250bb;
  --blue-dim:   rgba(0,96,223,.10);
  --bg:         #ffffff;
  --surface:    #f9f9fb;
  --surface2:   #f0f0f4;
  --border:     #d7d7db;
  --text:       #15141a;
  --dim:        #6f6f7e;
  --header:     #1c1b22;
  --red:        #c50042;
  --green:      #017a40;
  --font:       'IBM Plex Sans', system-ui, sans-serif;
  --mono:       'IBM Plex Mono', 'Fira Code', monospace;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: var(--font); font-size: 13px; color: var(--text);
  background: var(--bg); height: 100dvh;
  display: flex; flex-direction: column; overflow: hidden;
}

/* Header */
header {
  background: var(--header); color: #fff; height: 46px;
  padding: 0 18px; display: flex; align-items: center; gap: 20px;
  flex-shrink: 0; user-select: none;
}
.logo {
  display: flex; align-items: center; gap: 9px;
  font-size: 15px; font-weight: 600; letter-spacing: -.3px; color: #fff;
}
.logo-mark {
  width: 22px; height: 22px; border-radius: 50%;
  background: radial-gradient(circle at 35% 35%, #4fc3f7, #0060df 60%, #003a8c);
  box-shadow: 0 0 0 2px rgba(255,255,255,.15);
  flex-shrink: 0;
}
.area-nav { display: flex; gap: 3px; }
.area-btn {
  background: none; border: none; color: rgba(255,255,255,.6);
  font: 500 12px var(--font); padding: 5px 13px; border-radius: 5px;
  cursor: pointer; transition: background .12s, color .12s;
}
.area-btn:hover  { background: rgba(255,255,255,.1); color: #fff; }
.area-btn.active { background: rgba(255,255,255,.16); color: #fff; }
.h-spacer { flex: 1; }
.h-note { font-size: 11px; color: rgba(255,255,255,.3); font-family: var(--mono); }

/* Toolbar */
.toolbar {
  background: var(--surface); border-bottom: 1px solid var(--border);
  padding: 0 18px; height: 40px;
  display: flex; align-items: center; gap: 10px; flex-shrink: 0;
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
.t-actions { display: flex; gap: 6px; }

/* Workspace */
.workspace { display: flex; flex: 1; overflow: hidden; }

/* File pane */
.pane-files { flex: 1; overflow-y: auto; min-width: 0; }
.pane-files.drag-over {
  background: var(--blue-dim);
  outline: 2px dashed var(--blue); outline-offset: -3px;
}

/* File table */
.ft { width: 100%; border-collapse: collapse; }
.ft th {
  text-align: left; padding: 7px 16px;
  font: 600 10px/1 var(--font); text-transform: uppercase; letter-spacing: .6px;
  color: var(--dim); border-bottom: 1px solid var(--border);
  position: sticky; top: 0; background: var(--bg);
  cursor: pointer; user-select: none; white-space: nowrap;
}
.ft th:hover { color: var(--text); }
.ft th.sorted { color: var(--blue); }
.si { margin-left: 3px; opacity: .5; }
.ft th.sorted .si { opacity: 1; }
.ft td { padding: 6px 16px; border-bottom: 1px solid var(--border); }
.ft tr:hover td { background: var(--surface); }
.ft tr.sel td   { background: #dbeafe; }
.cn  { width: 100%; }
.cs  { text-align: right; color: var(--dim); min-width: 76px; font: 11px var(--mono); }
.cd  { color: var(--dim); min-width: 148px; font: 11px var(--mono); }
.cdd { min-width: 34px; text-align: right; }
.nc {
  display: flex; align-items: center; gap: 8px;
  cursor: pointer; min-width: 0;
}
.nc:hover .nt { color: var(--blue); text-decoration: underline; }
.fi { width: 18px; text-align: center; font-size: 14px; flex-shrink: 0; }
.nt { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.db {
  opacity: 0; background: none; border: none; color: var(--red);
  cursor: pointer; padding: 2px 5px; border-radius: 4px; font-size: 13px; line-height: 1;
}
.ft tr:hover .db { opacity: 1; }
.db:hover { background: #ffe8ec; }

/* Preview */
.pane-preview {
  width: 420px; flex-shrink: 0;
  border-left: 1px solid var(--border);
  display: flex; flex-direction: column;
  background: var(--bg); overflow: hidden;
}
.ph {
  padding: 9px 14px; border-bottom: 1px solid var(--border);
  display: flex; align-items: center; gap: 8px;
  background: var(--surface); flex-shrink: 0;
}
.pt { flex: 1; font-weight: 600; font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.pa { display: flex; gap: 5px; align-items: center; }
.pb { flex: 1; overflow: auto; padding: 14px; }
.pb img { max-width: 100%; border-radius: 6px; display: block; }
.pb pre { font: 12px/1.65 var(--mono); white-space: pre-wrap; word-break: break-all; }
.pb iframe { width: 100%; min-height: 500px; border: none; }
.np {
  height: 100%; display: flex; flex-direction: column;
  align-items: center; justify-content: center;
  gap: 10px; color: var(--dim); text-align: center;
}
.np .bi { font-size: 44px; }
.eta {
  width: 100%; height: 100%; font: 12px/1.65 var(--mono);
  border: 1px solid var(--border); border-radius: 6px;
  padding: 10px; resize: none; outline: none;
  color: var(--text); background: var(--bg);
  transition: border-color .12s, box-shadow .12s;
}
.eta:focus { border-color: var(--blue); box-shadow: 0 0 0 3px var(--blue-dim); }
.ef {
  padding: 9px 14px; border-top: 1px solid var(--border);
  display: flex; align-items: center; gap: 8px;
  background: var(--surface); flex-shrink: 0;
}
.ss { font-size: 11px; color: var(--green); margin-left: 4px; }

/* Buttons */
.btn-p {
  background: var(--blue); color: #fff; border: none;
  padding: 6px 15px; border-radius: 5px; font: 500 12px var(--font);
  cursor: pointer; transition: background .12s;
}
.btn-p:hover    { background: var(--blue-hover); }
.btn-p:disabled { opacity: .5; cursor: default; }
.btn {
  background: var(--surface2); color: var(--text);
  border: 1px solid var(--border); padding: 5px 11px; border-radius: 5px;
  font: 12px var(--font); cursor: pointer; transition: background .12s; white-space: nowrap;
}
.btn:hover { background: var(--surface); border-color: #b9b9c8; }
.btn-g {
  background: none; color: var(--dim); border: none;
  padding: 5px 9px; border-radius: 5px; font: 12px var(--font); cursor: pointer;
}
.btn-g:hover { background: var(--surface2); color: var(--text); }

/* Input */
.fld {
  width: 100%; padding: 8px 11px; border: 1px solid var(--border); border-radius: 5px;
  font: 13px var(--font); outline: none; color: var(--text); background: var(--bg);
  transition: border-color .12s, box-shadow .12s;
}
.fld:focus { border-color: var(--blue); box-shadow: 0 0 0 3px var(--blue-dim); }

/* Modal */
.ov {
  position: fixed; inset: 0; background: rgba(0,0,0,.45);
  display: flex; align-items: center; justify-content: center;
  z-index: 100; backdrop-filter: blur(3px);
}
.modal {
  background: var(--bg); border-radius: 10px; padding: 24px; width: 360px;
  box-shadow: 0 24px 64px rgba(0,0,0,.28);
  display: flex; flex-direction: column; gap: 14px;
}
.modal h3 { font-size: 16px; font-weight: 600; }
.modal p  { font-size: 12px; color: var(--dim); line-height: 1.6; }
.mf { display: flex; gap: 7px; justify-content: flex-end; }
.et { font-size: 11px; color: var(--red); min-height: 16px; }

/* Toast */
.toast {
  position: fixed; bottom: 22px; left: 50%;
  transform: translateX(-50%) translateY(70px);
  background: var(--header); color: #fff;
  padding: 9px 18px; border-radius: 7px; font-size: 12px;
  transition: transform .2s ease; z-index: 200;
  pointer-events: none; box-shadow: 0 4px 20px rgba(0,0,0,.3); white-space: nowrap;
}
.toast.show { transform: translateX(-50%) translateY(0); }
.toast.err  { background: var(--red); }

/* Empty/loading */
.empty { padding: 56px 20px; text-align: center; color: var(--dim); font-size: 13px; line-height: 1.7; }
.empty .ic { font-size: 36px; margin-bottom: 10px; }
.lr td { padding: 36px; text-align: center; color: var(--dim); }
</style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-mark"></div>
    Pond
  </div>
  <nav class="area-nav">
    <button class="area-btn active" data-area="vestibule">Vestibule</button>
    <button class="area-btn"        data-area="private">🔒 Private</button>
  </nav>
  <div class="h-spacer"></div>
  <span class="h-note" id="hn"></span>
</header>

<div class="toolbar">
  <div class="breadcrumb" id="bc"></div>
  <div class="t-actions" id="ta" style="display:none">
    <button class="btn" id="bu">↑ Upload</button>
    <button class="btn" id="bm">+ Folder</button>
  </div>
</div>

<div class="workspace">
  <div class="pane-files" id="pf">
    <table class="ft">
      <thead><tr>
        <th class="cn sorted" data-sort="name">Name <span class="si">↑</span></th>
        <th class="cs" data-sort="size">Size <span class="si">↕</span></th>
        <th class="cd" data-sort="modified">Modified <span class="si">↕</span></th>
        <th class="cdd"></th>
      </tr></thead>
      <tbody id="tb"></tbody>
    </table>
  </div>

  <div class="pane-preview" id="pp" style="display:none">
    <div class="ph">
      <span class="pt" id="ptitle"></span>
      <div class="pa">
        <button class="btn"   id="bedit"  style="display:none">Edit</button>
        <button class="btn"   id="bdl">↓ Download</button>
        <button class="btn-g" id="bclose">✕</button>
      </div>
    </div>
    <div class="pb" id="pb" style="height:calc(100% - 44px)"></div>
    <div class="ef" id="ef" style="display:none">
      <button class="btn-p" id="bsave">Save</button>
      <button class="btn-g" id="bcancel">Cancel</button>
      <span class="ss" id="ss"></span>
    </div>
  </div>
</div>

<!-- Auth modal -->
<div class="ov" id="mauth" style="display:none">
  <div class="modal">
    <h3>🔒 Private Area</h3>
    <p>Enter your password to access private files.</p>
    <input class="fld" type="password" id="apw" placeholder="Password" autocomplete="current-password">
    <div class="mf">
      <button class="btn-g" id="bac">Cancel</button>
      <button class="btn-p" id="bao">Unlock</button>
    </div>
    <p class="et" id="aerr"></p>
  </div>
</div>

<!-- Mkdir modal -->
<div class="ov" id="mmkdir" style="display:none">
  <div class="modal">
    <h3>New Folder</h3>
    <input class="fld" type="text" id="mdn" placeholder="Folder name">
    <div class="mf">
      <button class="btn-g" id="bmc">Cancel</button>
      <button class="btn-p" id="bmo">Create</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>
<input type="file" id="fi" multiple style="display:none">

<script>
const S = {
  area:'vestibule', path:'/', token:localStorage.getItem('pond_token')||'',
  entries:[], sort:{by:'name',asc:true}, sel:null, editing:false, orig:'',
};

const fmtSize = n => {
  if(n==null)return'—';
  if(n<1024)return n+' B';
  if(n<1048576)return(n/1024).toFixed(1)+' KB';
  if(n<1073741824)return(n/1048576).toFixed(1)+' MB';
  return(n/1073741824).toFixed(2)+' GB';
};
const fmtDate = ts => {
  const d=new Date(ts*1000);
  return d.toLocaleDateString(undefined,{year:'numeric',month:'short',day:'numeric'})
    +' '+d.toLocaleTimeString(undefined,{hour:'2-digit',minute:'2-digit'});
};
const fileIcon = (name,isDir) => {
  if(isDir)return'📁';
  const e=name.split('.').pop().toLowerCase();
  return({png:'🖼️',jpg:'🖼️',jpeg:'🖼️',gif:'🖼️',webp:'🖼️',svg:'🖼️',bmp:'🖼️',ico:'🖼️',
    pdf:'📕',doc:'📘',docx:'📘',xls:'📗',xlsx:'📗',csv:'📊',ppt:'📙',pptx:'📙',
    py:'🐍',js:'📜',ts:'📜',jsx:'📜',tsx:'📜',html:'🌐',css:'🎨',scss:'🎨',
    json:'📋',xml:'📋',yaml:'📋',yml:'📋',toml:'📋',md:'📝',txt:'📄',
    sh:'⚙️',bash:'⚙️',zsh:'⚙️',zip:'📦',tar:'📦',gz:'📦',rar:'📦',
    mp3:'🎵',wav:'🎵',flac:'🎵',mp4:'🎬',mov:'🎬',mkv:'🎬',webm:'🎬',
  }[e]||'📄');
};
const TEXT=new Set(['txt','md','py','js','ts','jsx','tsx','html','htm','css','scss',
  'json','xml','yaml','yml','toml','sh','bash','zsh','fish','env','gitignore',
  'csv','log','cfg','conf','ini','svg','rs','go','java','c','cpp','h','rb',
  'php','swift','kt','r','sql','lua','vim','dockerfile','rst']);
const IMG=new Set(['png','jpg','jpeg','gif','webp','svg','bmp','ico']);
const ext  = n => n.split('.').pop().toLowerCase();
const isTx = n => TEXT.has(ext(n))||!n.includes('.');
const isIm = n => IMG.has(ext(n));
const isPd = n => ext(n)==='pdf';
const aHdr = () => S.token?{'Authorization':'Bearer '+S.token}:{};
const join = (a,b) => (a.replace(/\/$/,'')+'/'+b).replace(/^\/\//,'/');
const esc  = s => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

let _tt;
function toast(msg,err=false){
  const el=document.getElementById('toast');
  el.textContent=msg; el.className='toast show'+(err?' err':'');
  clearTimeout(_tt); _tt=setTimeout(()=>el.className='toast',2600);
}

async function navigate(p){S.path=p;S.sel=null;closePreview();await refresh();}
async function refresh(){
  document.getElementById('tb').innerHTML='<tr class="lr"><td colspan="4">Loading…</td></tr>';
  renderBC();
  const r=await fetch(`/api/ls?path=${encodeURIComponent(S.path)}&area=${S.area}`,{headers:aHdr()});
  if(r.status===401){showAuth();return;}
  if(!r.ok){document.getElementById('tb').innerHTML='<tr class="lr"><td colspan="4">Error.</td></tr>';return;}
  S.entries=(await r.json()).entries;
  renderList();
}

function renderBC(){
  const parts=S.path.split('/').filter(Boolean);
  const icon=S.area==='private'?'🔒':'📂';
  let h=`<span class="bc-seg ${!parts.length?'tail':''}" ${parts.length?`onclick="navigate('/')"`:''}>
    ${icon} ${S.area==='private'?'Private':'Vestibule'}</span>`;
  parts.forEach((p,i)=>{
    const sub='/'+parts.slice(0,i+1).join('/'),last=i===parts.length-1;
    h+=`<span class="bc-sep">›</span>
      <span class="bc-seg ${last?'tail':''}" ${!last?`onclick="navigate('${sub.replace(/'/g,"\\'")}')"`:''}>${p}</span>`;
  });
  document.getElementById('bc').innerHTML=h;
  document.getElementById('ta').style.display=S.area==='private'?'flex':'none';
  document.getElementById('hn').textContent=S.area==='private'?'':'read-only';
}

function renderList(){
  const rows=[...S.entries].sort((a,b)=>{
    if(a.is_dir!==b.is_dir)return a.is_dir?-1:1;
    let va=a[S.sort.by]??'',vb=b[S.sort.by]??'';
    if(typeof va==='string'){va=va.toLowerCase();vb=vb.toLowerCase();}
    return(S.sort.asc?1:-1)*(va<vb?-1:va>vb?1:0);
  });
  if(!rows.length){
    document.getElementById('tb').innerHTML=
      `<tr><td colspan="4"><div class="empty"><div class="ic">📭</div>This folder is empty</div></td></tr>`;
    return;
  }
  document.getElementById('tb').innerHTML=rows.map(e=>{
    const fp=join(S.path,e.name),sfp=fp.replace(/\\/g,'\\\\').replace(/'/g,"\\'");
    const sn=e.name.replace(/\\/g,'\\\\').replace(/'/g,"\\'");
    const sel=S.sel?.name===e.name?' sel':'';
    const act=e.is_dir?`navigate('${sfp}')`:`openFile('${sfp}','${sn}')`;
    return`<tr class="${sel}">
      <td class="cn"><div class="nc" onclick="${act}">
        <span class="fi">${fileIcon(e.name,e.is_dir)}</span>
        <span class="nt">${e.name}${e.is_dir?'/':''}</span></div></td>
      <td class="cs">${fmtSize(e.size)}</td>
      <td class="cd">${fmtDate(e.modified)}</td>
      <td class="cdd">${S.area==='private'
        ?`<button class="db" onclick="confirmDelete('${sfp}','${sn}',${e.is_dir})">🗑</button>`:''}</td>
    </tr>`;
  }).join('');
}

function sortBy(col){
  S.sort={by:col,asc:S.sort.by===col?!S.sort.asc:true};
  renderList();
  document.querySelectorAll('.ft th').forEach(th=>{
    const me=th.dataset.sort===col;
    th.classList.toggle('sorted',me);
    if(th.querySelector('.si'))th.querySelector('.si').textContent=me?(S.sort.asc?'↑':'↓'):'↕';
  });
}

async function openFile(fp,name){
  S.sel={name,path:fp};S.editing=false;renderList();
  const pp=document.getElementById('pp'),pb=document.getElementById('pb');
  const ef=document.getElementById('ef'),be=document.getElementById('bedit');
  pp.style.display='flex';
  document.getElementById('ptitle').textContent=name;
  pb.innerHTML='<div class="empty" style="height:100%"><div class="ic">⏳</div>Loading…</div>';
  ef.style.display='none'; pb.style.padding='14px';
  document.getElementById('bdl').style.display='';
  be.style.display=(S.area==='private'&&isTx(name))?'':'none';
  const url=`/api/file?path=${encodeURIComponent(fp)}&area=${S.area}`;
  if(isIm(name)){
    const b=await fetch(url,{headers:aHdr()}).then(r=>r.blob());
    pb.innerHTML=`<img src="${URL.createObjectURL(b)}" alt="${name}" onload="URL.revokeObjectURL(this.src)">`;
  } else if(isPd(name)){
    const b=await fetch(url,{headers:aHdr()}).then(r=>r.blob());
    pb.style.padding='0';
    pb.innerHTML=`<iframe src="${URL.createObjectURL(b)}" style="width:100%;height:100%"></iframe>`;
  } else if(isTx(name)){
    const t=await fetch(url,{headers:aHdr()}).then(r=>r.text());
    S.orig=t; pb.innerHTML=`<pre>${esc(t)}</pre>`;
  } else {
    pb.innerHTML=`<div class="np"><div class="bi">${fileIcon(name,false)}</div>
      <div>No preview available</div>
      <button class="btn" onclick="downloadFile()">↓ Download</button></div>`;
  }
}

function closePreview(){document.getElementById('pp').style.display='none';S.sel=null;S.editing=false;}
function downloadFile(){
  if(!S.sel)return;
  fetch(`/api/file?path=${encodeURIComponent(S.sel.path)}&area=${S.area}`,{headers:aHdr()})
    .then(r=>r.blob()).then(b=>{
      Object.assign(document.createElement('a'),
        {href:URL.createObjectURL(b),download:S.sel.name}).click();
    });
}

function startEdit(){
  S.editing=true;
  const pb=document.getElementById('pb');
  const ta=document.createElement('textarea');
  ta.className='eta';ta.value=S.orig;ta.style.height='100%';
  ta.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key==='s'){e.preventDefault();doSave(ta.value);}});
  pb.innerHTML='';pb.appendChild(ta);ta.focus();
  document.getElementById('ef').style.display='flex';
  document.getElementById('ss').textContent='';
  document.getElementById('bedit').style.display='none';
  document.getElementById('bdl').style.display='none';
}

async function doSave(content){
  const ss=document.getElementById('ss');ss.textContent='Saving…';
  const r=await fetch(`/api/file?path=${encodeURIComponent(S.sel.path)}&area=${S.area}`,
    {method:'PUT',headers:{...aHdr(),'Content-Type':'text/plain'},body:content});
  if(r.ok){S.orig=content;ss.textContent='✓ Saved';toast('Saved');setTimeout(()=>ss.textContent='',3000);}
  else{ss.textContent='✗ Error';toast('Save failed',true);}
}

function cancelEdit(){
  S.editing=false;
  document.getElementById('ef').style.display='none';
  document.getElementById('bedit').style.display=S.area==='private'?'':'none';
  document.getElementById('bdl').style.display='';
  document.getElementById('pb').innerHTML=`<pre>${esc(S.orig)}</pre>`;
}

function confirmDelete(fp,name,isDir){
  if(!confirm(`Delete "${name}"${isDir?' and all its contents':''}?`))return;
  fetch(`/api/file?path=${encodeURIComponent(fp)}&area=${S.area}`,{method:'DELETE',headers:aHdr()})
    .then(r=>{if(r.ok){toast(`Deleted ${name}`);if(S.sel?.name===name)closePreview();refresh();}
              else toast('Delete failed',true);});
}

function showMkdir(){
  document.getElementById('mmkdir').style.display='flex';
  const i=document.getElementById('mdn');i.value='';setTimeout(()=>i.focus(),30);
}
function hideMkdir(){document.getElementById('mmkdir').style.display='none';}
async function doMkdir(){
  const name=document.getElementById('mdn').value.trim();if(!name)return;
  const r=await fetch('/api/mkdir',{method:'POST',
    headers:{...aHdr(),'Content-Type':'application/json'},
    body:JSON.stringify({area:S.area,path:join(S.path,name)})});
  if(r.ok){toast(`Created ${name}/`);hideMkdir();refresh();}else toast('Failed',true);
}

async function uploadFiles(list){
  const fd=new FormData();
  for(const f of list)fd.append('files',f);
  fd.append('path',S.path);fd.append('area',S.area);
  const r=await fetch('/api/upload',{method:'POST',headers:aHdr(),body:fd});
  if(r.ok){const d=await r.json();toast(`Uploaded ${d.saved.length} file${d.saved.length!==1?'s':''}`);refresh();}
  else toast('Upload failed',true);
}

function showAuth(){
  document.getElementById('mauth').style.display='flex';
  document.getElementById('apw').value='';
  document.getElementById('aerr').textContent='';
  setTimeout(()=>document.getElementById('apw').focus(),30);
}
function hideAuth(){
  document.getElementById('mauth').style.display='none';
  if(S.area==='private')switchArea('vestibule',true);
}
async function doAuth(){
  const pw=document.getElementById('apw').value;
  const btn=document.getElementById('bao');
  btn.disabled=true;btn.textContent='Checking…';
  const r=await fetch('/api/auth',{method:'POST',
    headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});
  btn.disabled=false;btn.textContent='Unlock';
  if(r.ok){
    S.token=(await r.json()).token;
    localStorage.setItem('pond_token',S.token);
    document.getElementById('mauth').style.display='none';
    refresh();
  } else document.getElementById('aerr').textContent='Incorrect password.';
}

async function switchArea(area,skipRefresh=false){
  if(area===S.area&&!skipRefresh)return;
  S.area=area;S.path='/';S.sel=null;closePreview();
  document.querySelectorAll('.area-btn').forEach(b=>b.classList.toggle('active',b.dataset.area===area));
  if(area==='private'&&!S.token){showAuth();return;}
  if(!skipRefresh)await refresh();
}

function setupDnD(){
  const pf=document.getElementById('pf');
  pf.addEventListener('dragover',e=>{if(S.area!=='private')return;e.preventDefault();pf.classList.add('drag-over');});
  pf.addEventListener('dragleave',e=>{if(!pf.contains(e.relatedTarget))pf.classList.remove('drag-over');});
  pf.addEventListener('drop',async e=>{
    e.preventDefault();pf.classList.remove('drag-over');
    if(S.area!=='private'){toast('Vestibule is read-only',true);return;}
    if(e.dataTransfer.files.length)await uploadFiles(e.dataTransfer.files);
  });
}

document.addEventListener('DOMContentLoaded',async()=>{
  document.getElementById('bu').onclick=()=>document.getElementById('fi').click();
  document.getElementById('bm').onclick=showMkdir;
  document.getElementById('bclose').onclick=closePreview;
  document.getElementById('bdl').onclick=downloadFile;
  document.getElementById('bedit').onclick=startEdit;
  document.getElementById('bsave').onclick=()=>{const ta=document.querySelector('.eta');if(ta)doSave(ta.value);};
  document.getElementById('bcancel').onclick=cancelEdit;
  document.getElementById('bao').onclick=doAuth;
  document.getElementById('bac').onclick=hideAuth;
  document.getElementById('apw').addEventListener('keydown',e=>{if(e.key==='Enter')doAuth();if(e.key==='Escape')hideAuth();});
  document.getElementById('bmo').onclick=doMkdir;
  document.getElementById('bmc').onclick=hideMkdir;
  document.getElementById('mdn').addEventListener('keydown',e=>{if(e.key==='Enter')doMkdir();if(e.key==='Escape')hideMkdir();});
  document.getElementById('fi').addEventListener('change',e=>{if(e.target.files.length)uploadFiles(e.target.files);e.target.value='';});
  document.querySelectorAll('.area-btn').forEach(b=>b.addEventListener('click',()=>switchArea(b.dataset.area)));
  document.querySelectorAll('.ft th[data-sort]').forEach(th=>th.addEventListener('click',()=>sortBy(th.dataset.sort)));
  document.getElementById('mauth').addEventListener('click',e=>{if(e.target===e.currentTarget)hideAuth();});
  document.getElementById('mmkdir').addEventListener('click',e=>{if(e.target===e.currentTarget)hideMkdir();});
  setupDnD();
  await refresh();
});
</script>
</body>
</html>"""


if __name__ == "__main__":
    cli()
