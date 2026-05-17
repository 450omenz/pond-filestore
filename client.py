#!/usr/bin/env python3
"""
pond — SSH-backed filestore client
───────────────────────────────────
Usage:  pond [OPTIONS] COMMAND [ARGS]

Options (also via env vars):
  --host     POND_HOST      server hostname   [localhost]
  --port     POND_PORT      server port       [8022]
  --private  POND_PRIVATE   connect as admin
  --password POND_PASSWORD  admin password

Commands:
  ls      [PATH]        list directory
  get     REMOTE [LOCAL] download a file
  put     LOCAL [REMOTE] upload a file       (--private)
  rm      REMOTE        delete a file        (--private)
  mkdir   REMOTE        create a directory   (--private)
  mv      SRC DST       move / rename        (--private)
  cat     REMOTE        print a text file
  browse                interactive TUI browser
  completion [SHELL]    print completion setup
"""

from __future__ import annotations

import asyncio
import os
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Optional

import asyncssh
import click
from click.shell_completion import CompletionItem
from rich.console import Console
from rich.progress import BarColumn, DownloadColumn, Progress, TextColumn, TransferSpeedColumn
from rich.table import Table

out = Console()
err = Console(stderr=True)

DEFAULT_PORT = 8022


# ── formatting ────────────────────────────────────────────────────────────────

def fmt_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:6.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


# ── SSH / SFTP ────────────────────────────────────────────────────────────────

async def _connect(host: str, port: int, private: bool, password: str | None):
    """Return (conn, sftp_client), prompting for password when needed."""
    username = "admin" if private else "guest"
    kw: dict = dict(host=host, port=port, username=username, known_hosts=None)
    if private:
        if not password:
            password = click.prompt("Password", hide_input=True)
        kw["password"] = password
    conn = await asyncssh.connect(**kw)
    sftp = await conn.start_sftp_client()
    return conn, sftp


async def _ls_entries(host, port, private, password, path=".") -> list:
    """List directory entries silently (used for tab-completion)."""
    try:
        conn, sftp = await _connect(host, port, private, password)
        async with conn:
            return await sftp.readdir(path)
    except Exception:
        return []


def _run(coro):
    """Run a coroutine and map SSH/OS exceptions to clean error messages."""
    try:
        asyncio.run(coro)
    except asyncssh.PermissionDenied:
        err.print("[bold red]✗[/] Permission denied — wrong password?")
        sys.exit(1)
    except asyncssh.SFTPError as e:
        err.print(f"[bold red]✗[/] SFTP: {e.reason}")
        sys.exit(1)
    except (ConnectionRefusedError, OSError) as e:
        err.print(f"[bold red]✗[/] Cannot connect: {e}")
        sys.exit(1)
    except asyncssh.DisconnectError as e:
        err.print(f"[bold red]✗[/] Disconnected: {e}")
        sys.exit(1)
    except click.Abort:
        err.print("[yellow]Aborted.[/yellow]")
        sys.exit(130)


def _require_private(ctx):
    if not ctx.obj["private"]:
        err.print("[bold red]✗[/] This command requires [bold]--private[/].")
        sys.exit(1)


# ── remote-path tab-completion type ──────────────────────────────────────────

class RemotePath(click.ParamType):
    """Click type that live-completes paths from the server."""

    name = "path"

    def _conn_params(self, ctx):
        root = ctx
        while root.parent:
            root = root.parent
        p = root.params
        host    = p.get("host")    or os.environ.get("POND_HOST",     "localhost")
        port    = int(p.get("port") or os.environ.get("POND_PORT",    str(DEFAULT_PORT)))
        private = p.get("private", False) or \
                  os.environ.get("POND_PRIVATE", "").lower() in ("1", "true", "yes")
        pw      = p.get("password") or os.environ.get("POND_PASSWORD")
        return host, port, private, pw

    def shell_complete(self, ctx, param, incomplete) -> list[CompletionItem]:
        host, port, private, pw = self._conn_params(ctx)
        if "/" in incomplete:
            directory, prefix = incomplete.rsplit("/", 1)
            directory = directory or "/"
        else:
            directory, prefix = ".", incomplete

        entries = asyncio.run(_ls_entries(host, port, private, pw, directory))
        results = []
        for e in entries:
            if e.filename in (".", ".."):
                continue
            is_dir = stat.S_ISDIR(e.attrs.permissions)
            if not e.filename.startswith(prefix):
                continue
            full = f"{directory.rstrip('/')}/{e.filename}" if directory != "." else e.filename
            if is_dir:
                full += "/"
            results.append(CompletionItem(full, type="plain"))
        return results


# ── CLI root ──────────────────────────────────────────────────────────────────

@click.group("pond")
@click.option("--host",     default="localhost",  envvar="POND_HOST",     show_default=True)
@click.option("--port",     default=DEFAULT_PORT, envvar="POND_PORT",     show_default=True, type=int)
@click.option("--private",  is_flag=True,         envvar="POND_PRIVATE",  help="Connect as admin")
@click.option("--password", default=None,          envvar="POND_PASSWORD", help="Admin password")
@click.pass_context
def cli(ctx, host, port, private, password):
    """pond — SSH-backed filestore.\n
    Public access by default; use --private for the admin area.
    """
    ctx.ensure_object(dict)
    ctx.obj.update(host=host, port=port, private=private, password=password)


def _sftp(ctx):
    o = ctx.obj
    return _connect(o["host"], o["port"], o["private"], o["password"])


# ── ls ────────────────────────────────────────────────────────────────────────

@cli.command("ls")
@click.argument("path", default=".", type=RemotePath())
@click.pass_context
def ls(ctx, path):
    """List a directory (default: root)."""

    async def _go():
        conn, sftp = await _sftp(ctx)
        async with conn:
            entries = await sftp.readdir(path)

            area = "[bold magenta]private[/]" if ctx.obj["private"] else "[bold cyan]public[/]"
            display = "/" + path.strip("/") if path not in (".", "/", "") else "/"

            table = Table(
                title=f"{area}  {display}",
                header_style="bold",
                show_edge=True,
                padding=(0, 1),
            )
            table.add_column("Name",  style="cyan",  no_wrap=True, min_width=28)
            table.add_column("Size",  justify="right", style="green")
            table.add_column("Type",  style="dim")

            dirs, files = [], []
            for e in entries:
                if e.filename in (".", ".."):
                    continue
                (dirs if stat.S_ISDIR(e.attrs.permissions) else files).append(e)

            for e in sorted(dirs,  key=lambda x: x.filename):
                table.add_row(f"[bold]{e.filename}/[/]", "—", "dir")
            for e in sorted(files, key=lambda x: x.filename):
                table.add_row(e.filename, fmt_size(e.attrs.size), "file")

            out.print(table)

    _run(_go())


# ── get ───────────────────────────────────────────────────────────────────────

@cli.command("get")
@click.argument("remote", type=RemotePath())
@click.argument("local",  default=".")
@click.pass_context
def get(ctx, remote, local):
    """Download REMOTE to LOCAL (default: current directory)."""

    async def _go():
        conn, sftp = await _sftp(ctx)
        async with conn:
            dest = Path(local)
            if dest.is_dir():
                dest = dest / Path(remote).name

            size = (await sftp.stat(remote)).size

            with Progress(
                TextColumn("[cyan]{task.description}"),
                BarColumn(),
                DownloadColumn(),
                TransferSpeedColumn(),
            ) as bar:
                task = bar.add_task(f"↓ {Path(remote).name}", total=size)
                async with sftp.open(remote, "rb") as rf:
                    with open(dest, "wb") as lf:
                        while chunk := await rf.read(65536):
                            lf.write(chunk)
                            bar.update(task, advance=len(chunk))

            out.print(f"[green]✓[/] {dest}")

    _run(_go())


# ── put ───────────────────────────────────────────────────────────────────────

@cli.command("put")
@click.argument("local")
@click.argument("remote", default=".", type=RemotePath())
@click.pass_context
def put(ctx, local, remote):
    """Upload LOCAL to REMOTE (default: root). Requires --private."""
    _require_private(ctx)

    async def _go():
        src = Path(local)
        if not src.exists():
            err.print(f"[bold red]✗[/] File not found: {local}")
            sys.exit(1)
        if not src.is_file():
            err.print(f"[bold red]✗[/] Not a file: {local}")
            sys.exit(1)

        conn, sftp = await _sftp(ctx)
        async with conn:
            dest = remote
            try:
                if stat.S_ISDIR((await sftp.stat(remote)).permissions):
                    dest = f"{remote.rstrip('/')}/{src.name}"
            except asyncssh.SFTPError:
                pass  # remote doesn't exist yet — use path as-is

            with Progress(
                TextColumn("[magenta]{task.description}"),
                BarColumn(),
                DownloadColumn(),
                TransferSpeedColumn(),
            ) as bar:
                task = bar.add_task(f"↑ {src.name}", total=src.stat().st_size)
                async with sftp.open(dest, "wb") as rf:
                    with open(src, "rb") as lf:
                        while chunk := lf.read(65536):
                            await rf.write(chunk)
                            bar.update(task, advance=len(chunk))

            out.print(f"[green]✓[/] → {dest}")

    _run(_go())


# ── rm ────────────────────────────────────────────────────────────────────────

@cli.command("rm")
@click.argument("remote", type=RemotePath())
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
@click.pass_context
def rm(ctx, remote, yes):
    """Delete a remote file. Requires --private."""
    _require_private(ctx)
    if not yes:
        click.confirm(f"Delete '{remote}'?", abort=True)

    async def _go():
        conn, sftp = await _sftp(ctx)
        async with conn:
            await sftp.remove(remote)
            out.print(f"[green]✓[/] Deleted {remote}")

    _run(_go())


# ── mkdir ─────────────────────────────────────────────────────────────────────

@cli.command("mkdir")
@click.argument("remote", type=RemotePath())
@click.pass_context
def mkdir(ctx, remote):
    """Create a remote directory. Requires --private."""
    _require_private(ctx)

    async def _go():
        conn, sftp = await _sftp(ctx)
        async with conn:
            await sftp.mkdir(remote)
            out.print(f"[green]✓[/] Created {remote}/")

    _run(_go())


# ── mv ────────────────────────────────────────────────────────────────────────

@cli.command("mv")
@click.argument("src", type=RemotePath())
@click.argument("dst", type=RemotePath())
@click.pass_context
def mv(ctx, src, dst):
    """Move or rename a remote file. Requires --private."""
    _require_private(ctx)

    async def _go():
        conn, sftp = await _sftp(ctx)
        async with conn:
            await sftp.rename(src, dst)
            out.print(f"[green]✓[/] {src} → {dst}")

    _run(_go())


# ── cat ───────────────────────────────────────────────────────────────────────

@cli.command("cat")
@click.argument("remote", type=RemotePath())
@click.pass_context
def cat(ctx, remote):
    """Print a remote text file."""

    async def _go():
        conn, sftp = await _sftp(ctx)
        async with conn:
            st = await sftp.stat(remote)
            if stat.S_ISDIR(st.permissions):
                err.print("[bold red]✗[/] That's a directory — use [bold]ls[/].")
                sys.exit(1)
            async with sftp.open(remote, "rb") as rf:
                data = await rf.read()
        try:
            out.print(data.decode())
        except UnicodeDecodeError:
            err.print("[yellow]⚠[/]  Binary file. Use [bold]get[/] to download it.")
            sys.exit(1)

    _run(_go())


# ── browse (TUI) ──────────────────────────────────────────────────────────────

@cli.command("browse")
@click.pass_context
def browse(ctx):
    """Interactive file browser. Requires the [bold]textual[/bold] package."""
    try:
        from textual.app import App, ComposeResult
        from textual.binding import Binding
        from textual.containers import Horizontal, Vertical
        from textual.widgets import DataTable, Footer, Header, Input, Label, Static
    except ImportError:
        err.print("[bold red]✗[/] textual is required:  pip install textual")
        sys.exit(1)

    obj = ctx.obj

    # ── Textual App ──────────────────────────────────────────────────────────

    class PondApp(App):
        TITLE = "pond"
        CSS = """
        Screen {
            background: $surface;
        }
        #bar {
            height: 1;
            background: $primary-darken-3;
            color: $text-muted;
            padding: 0 1;
            content-align: left middle;
        }
        #status {
            height: 1;
            background: $surface-darken-1;
            color: $text-muted;
            padding: 0 1;
            content-align: left middle;
        }
        DataTable {
            height: 1fr;
            border: none;
        }
        DataTable > .datatable--header {
            background: $primary-darken-2;
        }
        #input-row {
            height: 3;
            background: $surface-darken-1;
            padding: 0 1;
            display: none;
        }
        #input-row.visible {
            display: block;
        }
        Input {
            border: none;
            background: $surface-darken-2;
        }
        """
        BINDINGS = [
            Binding("q",         "quit",    "Quit"),
            Binding("enter",     "open",    "Open / navigate"),
            Binding("backspace", "up",      "Parent dir"),
            Binding("g",         "get",     "Download"),
            Binding("u",         "put",     "Upload"),
            Binding("d",         "delete",  "Delete"),
            Binding("r",         "refresh", "Refresh"),
        ]

        def __init__(self, cfg):
            super().__init__()
            self._cfg = cfg
            self._cwd = "."
            self._conn = None
            self._sftp = None
            self._input_mode: str | None = None  # "put"

        # ── layout ──────────────────────────────────────────────────────────

        def compose(self) -> ComposeResult:
            yield Header(show_clock=False)
            yield Static("", id="bar")
            yield DataTable(cursor_type="row")
            yield Input(placeholder="", id="input-row")
            yield Static("", id="status")
            yield Footer()

        # ── lifecycle ───────────────────────────────────────────────────────

        async def on_mount(self):
            table = self.query_one(DataTable)
            table.add_columns("  Name", "Size", "Type")
            await self._open_connection()
            await self._load_dir(".")

        async def _open_connection(self):
            cfg = self._cfg
            self._set_status("Connecting…")
            try:
                conn, sftp = await _connect(
                    cfg["host"], cfg["port"], cfg["private"], cfg["password"]
                )
                self._conn = conn
                self._sftp = sftp
                area = "private" if cfg["private"] else "public"
                self._set_bar(f"  pond · {area} · {cfg['host']}:{cfg['port']}")
                self._set_status("Ready")
            except asyncssh.PermissionDenied:
                self._set_status("✗ Permission denied — wrong password?")
            except Exception as e:
                self._set_status(f"✗ Connection failed: {e}")

        # ── directory loading ────────────────────────────────────────────────

        async def _load_dir(self, path: str):
            if not self._sftp:
                self._set_status("✗ Not connected")
                return
            try:
                entries = await self._sftp.readdir(path)
                self._cwd = path
                table = self.query_one(DataTable)
                table.clear()

                display = "/" + path.strip("/") if path not in (".", "/", "") else "/"
                self._set_bar(f"  pond  {display}")

                dirs, files = [], []
                for e in entries:
                    if e.filename in (".", ".."):
                        continue
                    (dirs if stat.S_ISDIR(e.attrs.permissions) else files).append(e)

                if path not in (".", "/", ""):
                    table.add_row("  ../", "—", "dir", key="__up__")

                for e in sorted(dirs,  key=lambda x: x.filename):
                    table.add_row(f"  {e.filename}/", "—", "dir", key=f"d:{e.filename}")
                for e in sorted(files, key=lambda x: x.filename):
                    table.add_row(f"  {e.filename}", fmt_size(e.attrs.size), "file", key=f"f:{e.filename}")

                self._set_status(f"{len(dirs)} dir{'s' if len(dirs) != 1 else ''}, "
                                  f"{len(files)} file{'s' if len(files) != 1 else ''}")
            except asyncssh.SFTPError as e:
                self._set_status(f"✗ {e.reason}")
            except Exception as e:
                self._set_status(f"✗ {e}")

        # ── helpers ──────────────────────────────────────────────────────────

        def _set_bar(self, text: str):
            self.query_one("#bar", Static).update(text)

        def _set_status(self, text: str):
            self.query_one("#status", Static).update(f"  {text}")

        def _selected(self) -> tuple[str, bool] | None:
            """Return (name, is_dir) for the focused row, or None."""
            table = self.query_one(DataTable)
            if table.cursor_row is None or table.row_count == 0:
                return None
            raw = str(table.get_cell_at((table.cursor_row, 0))).strip()
            is_dir = raw.endswith("/")
            name = raw.rstrip("/")
            return name, is_dir

        def _remote(self, name: str) -> str:
            if self._cwd in (".", "/", ""):
                return name
            return f"{self._cwd.rstrip('/')}/{name}"

        # ── actions ──────────────────────────────────────────────────────────

        async def action_open(self):
            sel = self._selected()
            if not sel:
                return
            name, is_dir = sel
            if name == "..":
                await self.action_up()
            elif is_dir:
                await self._load_dir(self._remote(name))

        async def action_up(self):
            parent = str(PurePosixPath(self._cwd).parent)
            if parent == self._cwd:
                parent = "."
            await self._load_dir(parent)

        async def action_refresh(self):
            await self._load_dir(self._cwd)

        async def action_get(self):
            sel = self._selected()
            if not sel:
                return
            name, is_dir = sel
            if is_dir:
                self._set_status("⚠  Can't download a directory")
                return
            remote = self._remote(name)
            self._set_status(f"↓ Downloading {name}…")
            try:
                size = (await self._sftp.stat(remote)).size
                dest = Path.cwd() / name
                async with self._sftp.open(remote, "rb") as rf:
                    with open(dest, "wb") as lf:
                        downloaded = 0
                        while chunk := await rf.read(65536):
                            lf.write(chunk)
                            downloaded += len(chunk)
                            pct = int(downloaded / size * 100) if size else 100
                            self._set_status(f"↓ {name}  {pct}%")
                self._set_status(f"✓ Saved → {dest}")
            except asyncssh.SFTPError as e:
                self._set_status(f"✗ {e.reason}")
            except Exception as e:
                self._set_status(f"✗ {e}")

        async def action_put(self):
            if not self._cfg["private"]:
                self._set_status("✗ Upload requires --private")
                return
            inp = self.query_one(Input)
            inp.placeholder = "Local file path to upload…"
            inp.add_class("visible")
            inp.focus()
            self._input_mode = "put"

        async def action_delete(self):
            if not self._cfg["private"]:
                self._set_status("✗ Delete requires --private")
                return
            sel = self._selected()
            if not sel or sel[0] == "..":
                return
            name, is_dir = sel
            remote = self._remote(name)
            self._set_status(f"Deleting {name}…")
            try:
                if is_dir:
                    await self._sftp.rmdir(remote)
                else:
                    await self._sftp.remove(remote)
                self._set_status(f"✓ Deleted {name}")
                await self._load_dir(self._cwd)
            except asyncssh.SFTPError as e:
                self._set_status(f"✗ {e.reason}")
            except Exception as e:
                self._set_status(f"✗ {e}")

        # ── input widget (upload path prompt) ────────────────────────────────

        async def on_input_submitted(self, event: Input.Submitted):
            inp = self.query_one(Input)
            value = event.value.strip()
            inp.value = ""
            inp.remove_class("visible")
            self.query_one(DataTable).focus()

            if self._input_mode == "put" and value:
                src = Path(value)
                if not src.exists():
                    self._set_status(f"✗ Not found: {value}")
                    return
                if not src.is_file():
                    self._set_status(f"✗ Not a file: {value}")
                    return
                dest = self._remote(src.name)
                self._set_status(f"↑ Uploading {src.name}…")
                try:
                    size = src.stat().st_size
                    async with self._sftp.open(dest, "wb") as rf:
                        with open(src, "rb") as lf:
                            uploaded = 0
                            while chunk := lf.read(65536):
                                await rf.write(chunk)
                                uploaded += len(chunk)
                                pct = int(uploaded / size * 100) if size else 100
                                self._set_status(f"↑ {src.name}  {pct}%")
                    self._set_status(f"✓ Uploaded → {dest}")
                    await self._load_dir(self._cwd)
                except asyncssh.SFTPError as e:
                    self._set_status(f"✗ {e.reason}")
                except Exception as e:
                    self._set_status(f"✗ {e}")

            self._input_mode = None

        async def on_key(self, event):
            if self._input_mode and event.key == "escape":
                inp = self.query_one(Input)
                inp.value = ""
                inp.remove_class("visible")
                self.query_one(DataTable).focus()
                self._input_mode = None
                self._set_status("Cancelled")

        # ── cleanup ──────────────────────────────────────────────────────────

        async def on_unmount(self):
            if self._conn:
                self._conn.close()

    PondApp(obj).run()


# ── completion ────────────────────────────────────────────────────────────────

@cli.command("completion")
@click.argument("shell", type=click.Choice(["bash", "zsh", "fish"]), required=False)
def completion(shell):
    """Print shell completion setup instructions."""
    script = sys.argv[0]
    lines = {
        "bash": f'eval "$(_POND_COMPLETE=bash_source {script})"',
        "zsh":  f'eval "$(_POND_COMPLETE=zsh_source {script})"',
        "fish": f'_POND_COMPLETE=fish_source {script} | source',
    }
    rcs = {
        "bash": "~/.bashrc",
        "zsh":  "~/.zshrc",
        "fish": "~/.config/fish/config.fish",
    }
    shells = [shell] if shell else list(lines)
    for sh in shells:
        out.print(f"[dim]# {rcs[sh]}[/]")
        out.print(f"[green]{lines[sh]}[/]\n")


# ── entry ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cli()
