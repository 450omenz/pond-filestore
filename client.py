#!/usr/bin/env python3
"""
Filestore Client
----------------
CLI for interacting with a filestore server.

Enable tab completion (do this once):
    bash:  echo 'eval "$(_FILESTORE_COMPLETE=bash_source python client.py)"' >> ~/.bashrc
    zsh:   echo 'eval "$(_FILESTORE_COMPLETE=zsh_source python client.py)"'  >> ~/.zshrc
    fish:  echo '_FILESTORE_COMPLETE=fish_source python client.py | source'  >> ~/.config/fish/config.fish

Then reload your shell.  After that, tab-completes commands, options, AND
remote file paths live from the server.
"""

import asyncio
import os
import stat
import sys
from pathlib import Path

import asyncssh
import click
from click.shell_completion import CompletionItem
from rich.console import Console
from rich.progress import BarColumn, DownloadColumn, Progress, TextColumn, TransferSpeedColumn
from rich.table import Table

console = Console()
DEFAULT_PORT = 8022


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sizeof_fmt(num: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(num) < 1024.0:
            return f"{num:6.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} PB"


async def open_sftp(host: str, port: int, private: bool, password: str | None):
    """Open an SSH connection and return (conn, sftp_client)."""
    username = "admin" if private else "guest"
    kwargs = dict(host=host, port=port, username=username, known_hosts=None)
    if private:
        if not password:
            password = click.prompt("Private area password", hide_input=True)
        kwargs["password"] = password
    conn = await asyncssh.connect(**kwargs)
    sftp = await conn.start_sftp_client()
    return conn, sftp


async def _list_remote_entries(
    host: str, port: int, private: bool, password: str | None, directory: str = "."
) -> list[str]:
    """Return filenames in *directory*; dirs get a trailing '/'.  Never raises."""
    try:
        conn, sftp = await open_sftp(host, port, private, password)
        async with conn:
            entries = await sftp.readdir(directory or ".")
            return [
                e.filename + ("/" if stat.S_ISDIR(e.attrs.permissions) else "")
                for e in entries
                if e.filename not in (".", "..")
            ]
    except Exception:
        return []


def run_cmd(coro):
    """Run an async command, pretty-printing common errors."""
    try:
        asyncio.run(coro)
    except asyncssh.PermissionDenied:
        console.print("[red]✗ Permission denied.[/red]")
    except asyncssh.SFTPError as e:
        console.print(f"[red]✗ SFTP error:[/red] {e.reason}")
    except (ConnectionRefusedError, OSError) as e:
        console.print(f"[red]✗ Could not connect:[/red] {e}")
    except asyncssh.DisconnectError as e:
        console.print(f"[red]✗ Disconnected:[/red] {e}")
    except click.Abort:
        console.print("[yellow]Aborted.[/yellow]")


# ---------------------------------------------------------------------------
# Remote-path completion type
# ---------------------------------------------------------------------------

class RemotePath(click.ParamType):
    """
    Click parameter type that tab-completes remote paths.

    At completion time it walks up the context tree to find --host / --port /
    --private / --password, then falls back to env vars so completion works
    even when those flags haven't been typed yet in the current line.
    """

    name = "remote_path"

    def _conn_params(self, ctx) -> tuple[str, int, bool, str | None]:
        root = ctx
        while root.parent:
            root = root.parent
        p = root.params

        host     = p.get("host")     or os.environ.get("FILESTORE_HOST",     "localhost")
        port     = int(p.get("port") or os.environ.get("FILESTORE_PORT",     str(DEFAULT_PORT)))
        private  = p.get("private",  False) or os.environ.get("FILESTORE_PRIVATE", "").lower() in ("1", "true", "yes")
        password = p.get("password") or os.environ.get("FILESTORE_PASSWORD")
        return host, port, private, password

    def shell_complete(self, ctx, param, incomplete) -> list[CompletionItem]:
        host, port, private, password = self._conn_params(ctx)

        # "docs/rep" → directory="docs", prefix="rep"
        if "/" in incomplete:
            directory, prefix = incomplete.rsplit("/", 1)
            directory = directory or "/"
        else:
            directory, prefix = ".", incomplete

        entries = asyncio.run(
            _list_remote_entries(host, port, private, password, directory)
        )

        results = []
        for entry in entries:
            bare   = entry.rstrip("/")
            is_dir = entry.endswith("/")
            if not bare.startswith(prefix):
                continue
            full = f"{directory.rstrip('/')}/{bare}" if directory != "." else bare
            if is_dir:
                full += "/"
            results.append(CompletionItem(full, type="plain"))

        return results


# ---------------------------------------------------------------------------
# CLI root
# ---------------------------------------------------------------------------

@click.group(name="filestore")
@click.option("--host",     default="localhost",  envvar="FILESTORE_HOST",     show_default=True)
@click.option("--port",     default=DEFAULT_PORT, envvar="FILESTORE_PORT",     show_default=True)
@click.option("--private",  is_flag=True,         envvar="FILESTORE_PRIVATE",  help="Connect to the private area")
@click.option("--password", default=None,          envvar="FILESTORE_PASSWORD", help="Admin password")
@click.pass_context
def cli(ctx, host, port, private, password):
    """Filestore — SSH-backed file store client.\n
    Connect to the public vestibule by default, or use --private for the
    password-protected area.
    """
    ctx.ensure_object(dict)
    ctx.obj.update(host=host, port=port, private=private, password=password)


def ctx_sftp(ctx):
    o = ctx.obj
    return open_sftp(o["host"], o["port"], o["private"], o["password"])


# ---------------------------------------------------------------------------
# ls
# ---------------------------------------------------------------------------

@cli.command("ls")
@click.argument("path", default=".", type=RemotePath())
@click.pass_context
def ls(ctx, path):
    """List files at PATH (default: root)."""

    async def _run():
        conn, sftp = await ctx_sftp(ctx)
        async with conn:
            entries = await sftp.readdir(path)
            area = (
                "[bold magenta]private[/]"
                if ctx.obj["private"]
                else "[bold cyan]vestibule[/]"
            )
            table = Table(
                title=f"{area}  /{path.strip('/')}",
                show_header=True,
                header_style="bold",
            )
            table.add_column("Name", style="cyan", no_wrap=True)
            table.add_column("Size", justify="right", style="green")
            table.add_column("Type", style="dim")

            dirs, files = [], []
            for e in entries:
                if e.filename in (".", ".."):
                    continue
                (dirs if stat.S_ISDIR(e.attrs.permissions) else files).append(e)

            for e in sorted(dirs,  key=lambda x: x.filename):
                table.add_row(f"{e.filename}/", "—", "dir")
            for e in sorted(files, key=lambda x: x.filename):
                table.add_row(e.filename, sizeof_fmt(e.attrs.size), "file")

            console.print(table)

    run_cmd(_run())


# ---------------------------------------------------------------------------
# get
# ---------------------------------------------------------------------------

@cli.command("get")
@click.argument("remote_path", type=RemotePath())
@click.argument("local_path",  default=".")
@click.pass_context
def get(ctx, remote_path, local_path):
    """Download REMOTE_PATH to LOCAL_PATH."""

    async def _run():
        conn, sftp = await ctx_sftp(ctx)
        async with conn:
            local = Path(local_path)
            if local.is_dir():
                local = local / Path(remote_path).name

            size = (await sftp.stat(remote_path)).size

            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(), DownloadColumn(), TransferSpeedColumn(),
            ) as progress:
                task = progress.add_task(
                    f"[cyan]↓[/cyan] {Path(remote_path).name}", total=size
                )
                async with sftp.open(remote_path, "rb") as rf:
                    with open(local, "wb") as lf:
                        while chunk := await rf.read(65536):
                            lf.write(chunk)
                            progress.update(task, advance=len(chunk))

            console.print(f"[green]✓[/green] Saved → {local}")

    run_cmd(_run())


# ---------------------------------------------------------------------------
# put
# ---------------------------------------------------------------------------

@cli.command("put")
@click.argument("local_path")
@click.argument("remote_path", default=".", type=RemotePath())
@click.pass_context
def put(ctx, local_path, remote_path):
    """Upload LOCAL_PATH to REMOTE_PATH. Requires --private."""
    if not ctx.obj["private"]:
        console.print("[red]✗[/red] Upload requires [bold]--private[/bold].")
        return

    async def _run():
        local = Path(local_path)
        if not local.exists():
            console.print(f"[red]✗[/red] File not found: {local_path}")
            return

        conn, sftp = await ctx_sftp(ctx)
        async with conn:
            dest = remote_path
            try:
                st = await sftp.stat(remote_path)
                if stat.S_ISDIR(st.permissions):
                    dest = f"{remote_path.rstrip('/')}/{local.name}"
            except asyncssh.SFTPError:
                pass

            size = local.stat().st_size

            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(), DownloadColumn(), TransferSpeedColumn(),
            ) as progress:
                task = progress.add_task(
                    f"[magenta]↑[/magenta] {local.name}", total=size
                )
                async with sftp.open(dest, "wb") as rf:
                    with open(local, "rb") as lf:
                        while chunk := lf.read(65536):
                            await rf.write(chunk)
                            progress.update(task, advance=len(chunk))

            console.print(f"[green]✓[/green] Uploaded → {dest}")

    run_cmd(_run())


# ---------------------------------------------------------------------------
# rm
# ---------------------------------------------------------------------------

@cli.command("rm")
@click.argument("remote_path", type=RemotePath())
@click.option("--yes", is_flag=True, help="Skip confirmation")
@click.pass_context
def rm(ctx, remote_path, yes):
    """Remove a file. Requires --private."""
    if not ctx.obj["private"]:
        console.print("[red]✗[/red] Remove requires [bold]--private[/bold].")
        return
    if not yes:
        click.confirm(f"Delete '{remote_path}'?", abort=True)

    async def _run():
        conn, sftp = await ctx_sftp(ctx)
        async with conn:
            await sftp.remove(remote_path)
            console.print(f"[green]✓[/green] Deleted {remote_path}")

    run_cmd(_run())


# ---------------------------------------------------------------------------
# mkdir
# ---------------------------------------------------------------------------

@cli.command("mkdir")
@click.argument("remote_path", type=RemotePath())
@click.pass_context
def mkdir(ctx, remote_path):
    """Create a directory. Requires --private."""
    if not ctx.obj["private"]:
        console.print("[red]✗[/red] mkdir requires [bold]--private[/bold].")
        return

    async def _run():
        conn, sftp = await ctx_sftp(ctx)
        async with conn:
            await sftp.mkdir(remote_path)
            console.print(f"[green]✓[/green] Created {remote_path}/")

    run_cmd(_run())


# ---------------------------------------------------------------------------
# mv
# ---------------------------------------------------------------------------

@cli.command("mv")
@click.argument("remote_src", type=RemotePath())
@click.argument("remote_dst", type=RemotePath())
@click.pass_context
def mv(ctx, remote_src, remote_dst):
    """Move / rename a file. Requires --private."""
    if not ctx.obj["private"]:
        console.print("[red]✗[/red] mv requires [bold]--private[/bold].")
        return

    async def _run():
        conn, sftp = await ctx_sftp(ctx)
        async with conn:
            await sftp.rename(remote_src, remote_dst)
            console.print(f"[green]✓[/green] {remote_src} → {remote_dst}")

    run_cmd(_run())


# ---------------------------------------------------------------------------
# completion helper
# ---------------------------------------------------------------------------

@cli.command("completion")
@click.argument("shell", type=click.Choice(["bash", "zsh", "fish"]), default=None, required=False)
def completion(shell):
    """Print shell completion setup instructions."""
    script = sys.argv[0]

    lines = {
        "bash": f'eval "$(_FILESTORE_COMPLETE=bash_source {script})"',
        "zsh":  f'eval "$(_FILESTORE_COMPLETE=zsh_source {script})"',
        "fish": f'_FILESTORE_COMPLETE=fish_source {script} | source',
    }
    rc_files = {
        "bash": "~/.bashrc",
        "zsh":  "~/.zshrc",
        "fish": "~/.config/fish/config.fish",
    }

    if shell:
        rc = rc_files[shell]
        console.print(f"\nAdd this line to [bold]{rc}[/bold]:\n")
        console.print(f"  [green]{lines[shell]}[/green]\n")
        console.print(f"Then run [bold]source {rc}[/bold] (or open a new terminal).\n")
        console.print(
            "[dim]After that, tab-completes commands, flags, AND remote "
            "file paths live from the server.[/dim]\n"
        )
    else:
        console.print("\n[bold]Shell completion setup[/bold]\n")
        for sh, line in lines.items():
            console.print(f"  [bold]{sh}[/bold]  ({rc_files[sh]}):")
            console.print(f"    [green]{line}[/green]\n")
        console.print("[dim]Run [bold]completion <shell>[/bold] for shell-specific instructions.[/dim]\n")


if __name__ == "__main__":
    cli()