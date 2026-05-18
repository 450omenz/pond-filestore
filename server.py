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

# ui.html lives next to this file — edit it freely without restarting the server
_UI_PATH = Path(__file__).with_name("ui.html")


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
    def remove(self, path):       raise asyncssh.SFTPError(asyncssh.FX_PERMISSION_DENIED, self._D)
    def rename(self, old, new):   raise asyncssh.SFTPError(asyncssh.FX_PERMISSION_DENIED, self._D)
    def mkdir(self, path, attrs): raise asyncssh.SFTPError(asyncssh.FX_PERMISSION_DENIED, self._D)
    def rmdir(self, path):        raise asyncssh.SFTPError(asyncssh.FX_PERMISSION_DENIED, self._D)


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
    """Serve ui.html — reads fresh on every request so edits take effect immediately."""
    if not _UI_PATH.exists():
        raise HTTPException(500, f"UI file not found: {_UI_PATH}\n"
                                  "Place ui.html next to server.py.")
    return _UI_PATH.read_text()


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

    _data_dir       = data_dir
    _private_hash   = config["private_password_hash"].encode()
    _session_secret = _ensure_session_secret(config, data_dir / CONFIG_FILE)

    key_path = data_dir / HOST_KEY_FILE
    if not key_path.exists():
        click.echo("  generating ssh host key...")
        k = asyncssh.generate_private_key("ssh-ed25519")
        k.write_private_key(str(key_path))
        os.chmod(key_path, _stat.S_IRUSR | _stat.S_IWUSR)

    ssh_server = await asyncssh.create_server(
        _make_ssh_server_class(config["private_password_hash"].encode()),
        host="", port=ssh_port,
        server_host_keys=[str(key_path)],
        sftp_factory=_make_sftp_factory(data_dir),
        allow_scp=True,
    )

    uvi = uvicorn.Server(
        uvicorn.Config(web_app, host=web_host, port=web_port, log_level="warning")
    )

    click.echo(f"\n  pond is running\n")
    click.echo(f"  ssh  →  port {ssh_port}")
    click.echo(f"  web  →  http://{'localhost' if web_host == '127.0.0.1' else web_host}:{web_port}")
    click.echo(f"  data →  {data_dir}\n")

    async with ssh_server:
        await uvi.serve()


# ══════════════════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════════════════

@click.group()
def cli():
    """pond-server — SSH file store + web UI."""


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
        click.echo("\n  pond stopped.")


@cli.command("passwd")
@click.option("--data-dir", default=str(DEFAULT_DATA_DIR), show_default=True)
def passwd(data_dir):
    """Change the private-area password."""
    path = Path(data_dir) / CONFIG_FILE
    if not path.exists():
        click.echo("no config found. run 'pond-server start' first.")
        raise SystemExit(1)
    with open(path) as f:
        config = json.load(f)
    new_pw = click.prompt("new password", hide_input=True, confirmation_prompt=True)
    config["private_password_hash"] = bcrypt.hashpw(
        new_pw.encode(), bcrypt.gensalt()).decode()
    with open(path, "w") as f:
        json.dump(config, f, indent=2)
    click.echo("password updated.")


if __name__ == "__main__":
    cli()
