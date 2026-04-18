"""CLI entry point: Typer app with rich output, progress bars, and export support."""

from __future__ import annotations

import asyncio
import logging
import sys
from datetime import UTC, datetime
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from netscan import __version__
from netscan.exporters import export_csv, export_json, export_xml
from netscan.scanner import ScanConfig, Scanner, ScanResult
from netscan.utils import format_duration, parse_ports, parse_targets

app = typer.Typer(
    name="netscan",
    help="Modern async network scanner.  Only scan networks you own or have permission to test.",
    add_completion=False,
    rich_markup_mode="rich",
)

console = Console(stderr=False, highlight=False)
err_console = Console(stderr=True, style="red", highlight=False)

_EXPORT_FORMATS = {"json", "csv", "xml"}
_EXPORT_FUNCS = {"json": export_json, "csv": export_csv, "xml": export_xml}


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"netscan {__version__}")
        raise typer.Exit()


@app.command()
def scan(  # noqa: PLR0913
    target: Annotated[
        str,
        typer.Argument(help="Target: IP, hostname, CIDR (192.168.1.0/24), or range (192.168.1.1-50)"),
    ],
    ports: Annotated[
        str,
        typer.Option("-p", "--ports", help="Ports: 80,443  |  1-1024  |  top100  |  top1000"),
    ] = "top100",
    timeout: Annotated[
        float,
        typer.Option("-t", "--timeout", help="Connection timeout per port (seconds)"),
    ] = 1.0,
    concurrency: Annotated[
        int,
        typer.Option("-c", "--concurrency", help="Max simultaneous connections"),
    ] = 100,
    no_discovery: Annotated[
        bool,
        typer.Option("--no-discovery", help="Skip host-discovery phase (treat all targets as up)"),
    ] = False,
    no_banners: Annotated[
        bool,
        typer.Option("--no-banners", help="Skip banner grabbing (faster, less info)"),
    ] = False,
    no_os: Annotated[
        bool,
        typer.Option("--no-os", help="Skip OS fingerprinting"),
    ] = False,
    rate: Annotated[
        float | None,
        typer.Option("--rate", help="Rate limit: max new connections per second"),
    ] = None,
    export: Annotated[
        str | None,
        typer.Option("--export", help="Export format: json | csv | xml"),
    ] = None,
    output: Annotated[
        str | None,
        typer.Option("-o", "--output", help="Output file path (default: auto-named)"),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option("-v", "--verbose", help="Show debug logging"),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option("-q", "--quiet", help="Suppress all output except results table"),
    ] = False,
    version: Annotated[
        bool | None,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version"),
    ] = None,
) -> None:
    """Scan network targets for open TCP ports, services, and OS information."""
    _configure_logging(verbose)

    # --- Parse inputs ---
    try:
        targets = parse_targets(target)
        port_list = parse_ports(ports)
    except ValueError as exc:
        err_console.print(f"[bold]Error:[/bold] {exc}")
        raise typer.Exit(code=2) from exc

    if export and export.lower() not in _EXPORT_FORMATS:
        err_console.print(f"[bold]Error:[/bold] Unknown export format {export!r}. Use: json, csv, xml")
        raise typer.Exit(code=2)

    if not quiet:
        _print_banner()
        _print_ethical_notice()
        _print_config(target, targets, port_list, timeout, concurrency, no_discovery)

    config = ScanConfig(
        ports=port_list,
        timeout=timeout,
        concurrency=concurrency,
        rate_limit=rate,
        grab_banners=not no_banners,
        os_detection=not no_os,
        host_discovery=not no_discovery,
    )
    scanner = Scanner(config)

    # --- Run scan ---
    results: list[ScanResult] = []
    try:
        if quiet:
            results = asyncio.run(scanner.scan(targets))
        else:
            results = _run_with_progress(scanner, targets)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user (Ctrl+C)[/yellow]")
        raise typer.Exit(code=1) from None

    # --- Display results ---
    if not quiet:
        _display_results(results)
        _display_summary(results, port_list)

    # --- Export ---
    if export:
        _do_export(results, export.lower(), output)


def _run_with_progress(scanner: Scanner, targets: list[str]) -> list[ScanResult]:
    """Run scan while showing a live progress bar."""
    results: list[ScanResult] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        task_id = progress.add_task("Scanning hosts...", total=len(targets))

        def on_host_done(ip: str, completed: int, total: int) -> None:
            progress.update(task_id, completed=completed, description=f"[cyan]{ip}[/cyan]")

        results = asyncio.run(scanner.scan(targets, progress_callback=on_host_done))

    return results


def _display_results(results: list[ScanResult]) -> None:
    """Print per-host tables for all hosts with open ports."""
    up_with_ports = [r for r in results if r.is_up and r.open_ports]

    if not up_with_ports:
        console.print("\n[yellow]No open ports found.[/yellow]")
        return

    console.print()
    for result in up_with_ports:
        _display_host(result)


def _display_host(result: ScanResult) -> None:
    """Print a single host's open ports as a rich Table inside a Panel."""
    os_str = ""
    if result.os_guess:
        confidence_color = {"high": "green", "medium": "yellow", "low": "dim"}.get(
            result.os_guess.confidence, "white"
        )
        os_str = (
            f"  [dim]OS:[/dim] [{confidence_color}]{result.os_guess.name}[/{confidence_color}]"
            f" [dim]({result.os_guess.method}, {result.os_guess.confidence})[/dim]"
        )

    hostname_str = f" [dim]({result.hostname})[/dim]" if result.hostname else ""
    title = (
        f"[bold green]{result.ip}[/bold green]{hostname_str}"
        f"  [green]UP[/green]"
        f"  [dim]{format_duration(result.scan_duration)}[/dim]"
        f"{os_str}"
    )

    table = Table(show_header=True, header_style="bold cyan", box=None, padding=(0, 1))
    table.add_column("Port", style="bold", justify="right", width=6)
    table.add_column("Proto", width=5)
    table.add_column("Service", width=16)
    table.add_column("Version / Banner")

    for p in result.open_ports:
        version_cell = Text()
        if p.version:
            version_cell.append(p.version, style="green")
        elif p.banner:
            # Samo prva vrstica bannerja, skrajsano - dolgi banerji niso primerni za tabelo
            first_line = p.banner.split("\n")[0][:60]
            version_cell.append(first_line, style="dim")

        table.add_row(
            str(p.port),
            "tcp",
            p.service or "unknown",
            version_cell,
        )

    console.print(Panel(table, title=title, title_align="left", border_style="blue"))


def _display_summary(results: list[ScanResult], ports: list[int]) -> None:
    """Print a compact scan summary."""
    total = len(results)
    up = sum(1 for r in results if r.is_up)
    total_open = sum(len(r.open_ports) for r in results)
    total_duration = sum(r.scan_duration for r in results)
    errors = sum(1 for r in results if r.error)

    table = Table(title="Scan Summary", show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="dim")
    table.add_column("Value", style="bold")

    table.add_row("Hosts scanned", str(total))
    table.add_row("Hosts up", f"[green]{up}[/green] / {total}")
    table.add_row("Ports per host", str(len(ports)))
    table.add_row("Total open ports", f"[cyan]{total_open}[/cyan]")
    table.add_row("Total scan time", format_duration(total_duration))
    if errors:
        table.add_row("Errors", f"[red]{errors}[/red]")

    console.print()
    console.print(table)


def _do_export(results: list[ScanResult], fmt: str, output_path: str | None) -> None:
    """Write results to file in the requested format."""
    if not output_path:
        stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        output_path = f"netscan_{stamp}.{fmt}"

    try:
        _EXPORT_FUNCS[fmt](results, output_path)
        console.print(f"\n[green]Exported[/green] -> [bold]{output_path}[/bold]")
    except OSError as exc:
        err_console.print(f"Export failed: {exc}")
        raise typer.Exit(code=1) from exc


def _print_banner() -> None:
    console.print(
        Panel(
            f"[bold cyan]netscan[/bold cyan] [dim]v{__version__}[/dim]\n"
            "[dim]Modern Async Network Scanner[/dim]",
            border_style="cyan",
            expand=False,
        )
    )


def _print_ethical_notice() -> None:
    console.print(
        "[bold yellow][!] ETHICAL USE ONLY[/bold yellow]  "
        "[dim]Only scan networks you own or have explicit permission to test.[/dim]\n"
    )


def _print_config(
    raw_target: str,
    targets: list[str],
    ports: list[int],
    timeout: float,
    concurrency: int,
    no_discovery: bool,
) -> None:
    console.print(
        f"  [dim]Target     [/dim] {raw_target} [dim]({len(targets)} host{'s' if len(targets) != 1 else ''})[/dim]\n"
        f"  [dim]Ports      [/dim] {len(ports)} ports\n"
        f"  [dim]Timeout    [/dim] {timeout}s\n"
        f"  [dim]Concurrency[/dim] {concurrency}\n"
        f"  [dim]Discovery  [/dim] {'disabled' if no_discovery else 'enabled'}\n"
    )


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(levelname)s %(name)s %(message)s",
        stream=sys.stderr,
    )
