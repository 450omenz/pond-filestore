#!/usr/bin/env python3
"""
Filestore Server
----------------
An asyncssh-based file store with two areas:
  - Vestibule : public, read-only (username: guest)
  - Private   : password-protected, full access (username: admin)
"""

import asyncio
import asyncssh
import bcrypt
import click
import json
import os
import stat
from pathlib import Path

DEFAULT_DATA_DIR = Path.home() / "filestore-data"
DEFAULT_PORT = 8022
HOST_KEY_FILE = "host_key"
CONFIG_FILE = "config.json"


# ---------------------------------------------------------------------------
# SFTP Handlers
# ---------------------------------------------------------------------------

class ReadOnlySFTPServer(asyncssh.SFTPServer):
    """Vestibule SFTP handler — reads only, no writes."""

    _WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC
    _DENY = "Vestibule is read-only"

    def open(self, path, pflags, attrs):
        if pflags & self._WRITE_FLAGS:
            raise asyncssh.SFTPError(asyncssh.FX_PERMISSION_DENIED, self._DENY)
        return super().open(path, pflags, attrs)

    def remove(self, path):
        raise asyncssh.SFTPError(asyncssh.FX_PERMISSION_DENIED, self._DENY)

    def rename(self, oldpath, newpath):
        raise asyncssh.SFTPError(asyncssh.FX_PERMISSION_DENIED, self._DENY)

    def mkdir(self, path, attrs):
        raise asyncssh.SFTPError(asyncssh.FX_PERMISSION_DENIED, self._DENY)

    def rmdir(self, path):
        raise asyncssh.SFTPError(asyncssh.FX_PERMISSION_DENIED, self._DENY)


def make_sftp_factory(data_dir: Path):
    """Return an SFTP factory that chroots into the right area per user."""

    def sftp_factory(conn):
        username = conn.get_extra_info("username")
        if username == "admin":
            root = str(data_dir / "private")
            return asyncssh.SFTPServer(conn, chroot=root)
        else:
            root = str(data_dir / "vestibule")
            return ReadOnlySFTPServer(conn, chroot=root)

    return sftp_factory


# ---------------------------------------------------------------------------
# SSH Auth
# ---------------------------------------------------------------------------

def make_ssh_server_class(private_hash: bytes):
    """Return an SSHServer subclass closed over the hashed password."""

    class FilestoreSSHServer(asyncssh.SSHServer):

        def begin_auth(self, username):
            # guest needs no credentials at all
            return username != "guest"

        def password_auth_supported(self):
            return True

        def validate_password(self, username, password):
            if username == "admin":
                return bcrypt.checkpw(password.encode(), private_hash)
            return False

    return FilestoreSSHServer


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def load_or_create_config(data_dir: Path, password: str | None) -> dict:
    config_path = data_dir / CONFIG_FILE

    if config_path.exists():
        with open(config_path) as f:
            return json.load(f)

    if not password:
        password = click.prompt(
            "Set private area password", hide_input=True, confirmation_prompt=True
        )

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    config = {"private_password_hash": hashed}

    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)

    click.echo("Config saved.")
    return config


def change_password(data_dir: Path):
    """Update the stored admin password hash."""
    config_path = data_dir / CONFIG_FILE
    new_password = click.prompt(
        "New private area password", hide_input=True, confirmation_prompt=True
    )
    hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()

    config = {}
    if config_path.exists():
        with open(config_path) as f:
            config = json.load(f)
    config["private_password_hash"] = hashed

    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)
    click.echo("Password updated.")


# ---------------------------------------------------------------------------
# Server entry-point
# ---------------------------------------------------------------------------

async def run_server(data_dir: Path, port: int, config: dict):
    key_path = data_dir / HOST_KEY_FILE

    if not key_path.exists():
        click.echo("Generating SSH host key…")
        key = asyncssh.generate_private_key("ssh-ed25519")
        key.write_private_key(str(key_path))
        os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)
        click.echo(f"Host key saved → {key_path}")

    private_hash = config["private_password_hash"].encode()
    ssh_server_class = make_ssh_server_class(private_hash)
    sftp_factory = make_sftp_factory(data_dir)

    server = await asyncssh.create_server(
        ssh_server_class,
        host="",
        port=port,
        server_host_keys=[str(key_path)],
        sftp_factory=sftp_factory,
        allow_scp=True,
    )

    click.echo(f"\n✓ Filestore running on port {port}")
    click.echo(f"  Vestibule : {data_dir / 'vestibule'}")
    click.echo(f"  Private   : {data_dir / 'private'}")
    click.echo(f"\n  Guest  → filestore --host <ip> ls")
    click.echo(f"  Admin  → filestore --host <ip> --private ls\n")

    async with server:
        await asyncio.Future()  # run forever


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@click.group()
def cli():
    """Filestore server management."""


@cli.command("start")
@click.option("--data-dir", default=str(DEFAULT_DATA_DIR), show_default=True, help="Storage root")
@click.option("--port", default=DEFAULT_PORT, show_default=True, help="Port to listen on")
@click.option("--password", default=None, help="Admin password (prompted on first run)")
def start(data_dir, port, password):
    """Start the filestore server."""
    data_dir = Path(data_dir)
    (data_dir / "vestibule").mkdir(parents=True, exist_ok=True)
    (data_dir / "private").mkdir(parents=True, exist_ok=True)

    config = load_or_create_config(data_dir, password)

    try:
        asyncio.run(run_server(data_dir, port, config))
    except KeyboardInterrupt:
        click.echo("\nServer stopped.")


@cli.command("passwd")
@click.option("--data-dir", default=str(DEFAULT_DATA_DIR), show_default=True)
def passwd(data_dir):
    """Change the admin password."""
    change_password(Path(data_dir))


if __name__ == "__main__":
    cli()