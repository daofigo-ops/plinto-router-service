from __future__ import annotations

import argparse
from pathlib import Path
from typing import Callable

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

from app.config import DEFAULT_CONFIG_FILE, load_settings

RunScanCallable = Callable[[argparse.Namespace], int]
RunDoctorCallable = Callable[[Path, Console], int]


def _base_scan_namespace(config_path: Path) -> argparse.Namespace:
    """Return an argparse-compatible namespace for app.main.run_scan."""
    return argparse.Namespace(
        command="scan",
        target=None,
        config=config_path,
        local=False,
        gateway=False,
        local_prefix=None,
        ports=None,
        output_dir=None,
        timeout=None,
        concurrency=None,
        max_hosts=None,
        report_format="all",
        no_deep_fingerprint=False,
        max_extra_paths=None,
        no_history=False,
        no_latest=False,
        no_inventory=False,
        no_dns_audit=False,
        pentest=False,
        i_own_this_network=False,
        credentials_file=None,
        check_defaults=False,
        apply_pentest=False,
        pentest_rate_limit=None,
        pentest_audit_log=None,
    )


def _ask_ports(default_ports: list[int]) -> str | None:
    default_text = ",".join(str(port) for port in default_ports)
    value = Prompt.ask("Ports", default=default_text).strip()
    return value or None


def _ask_report_format() -> str:
    choices = ["all", "html", "json", "csv", "both"]
    return Prompt.ask("Report format", choices=choices, default="all")


def _ask_common_scan_options(args: argparse.Namespace, settings) -> argparse.Namespace:
    args.ports = _ask_ports(settings.default_ports)
    args.timeout = float(Prompt.ask("Timeout seconds", default=str(settings.scan.timeout)))
    args.concurrency = int(Prompt.ask("Concurrency", default=str(settings.scan.concurrency)))
    args.report_format = _ask_report_format()
    args.no_deep_fingerprint = not Confirm.ask("Enable deep fingerprinting?", default=settings.scan.deep_fingerprint)
    args.no_dns_audit = not Confirm.ask("Enable audit-only DNS checks?", default=settings.dns.audit_visible_dns)
    args.no_history = not Confirm.ask("Save timestamped scan history?", default=settings.reports.save_history)
    args.no_inventory = not Confirm.ask("Update local device inventory?", default=settings.inventory.enabled)
    args.no_latest = not Confirm.ask("Update reports/latest.* copies?", default=settings.reports.write_latest_copies)
    return args


def _confirm_ownership(console: Console) -> bool:
    console.print(
        Panel(
            "Pentest Mode is only for devices and networks you own or are explicitly authorized to audit.\n"
            "It does not brute-force, does not change DNS, and does not modify router settings.",
            title="Authorization Required",
            border_style="yellow",
        )
    )
    if not Confirm.ask("Do you own or have explicit permission to test this network/device?", default=False):
        return False
    phrase = Prompt.ask("Type I OWN THIS NETWORK to continue", default="")
    return phrase.strip().upper() == "I OWN THIS NETWORK"


def _ask_credentials_file(default_path: str = "config/credentials.yaml") -> Path | None:
    use_credentials = Confirm.ask("Use a credentials YAML file?", default=False)
    if not use_credentials:
        return None
    value = Prompt.ask("Credentials file", default=default_path).strip()
    return Path(value) if value else None


def _render_menu(console: Console) -> None:
    table = Table(title="Plinto Interactive Console", show_header=True)
    table.add_column("Option", justify="right", style="cyan", no_wrap=True)
    table.add_column("Action", style="bold")
    table.add_column("Description")
    table.add_row("1", "Local LAN scan", "Auto-detect local subnet and run a safe audit scan")
    table.add_row("2", "Gateway-only scan", "Auto-detect and scan only the default gateway/router")
    table.add_row("3", "Custom target scan", "Scan one private IP or CIDR range")
    table.add_row("4", "Pentest dry-run", "Prepare authorized validation plan without credential attempts")
    table.add_row("5", "Pentest validation", "Run restricted known-credential validation with explicit authorization")
    table.add_row("6", "Doctor", "Check install, config, directories, and local network detection")
    table.add_row("7", "Show latest report paths", "Display latest JSON/CSV/HTML report locations")
    table.add_row("0", "Exit", "Close the menu")
    console.print(table)


def _show_latest_report_paths(console: Console, settings) -> None:
    base = settings.reports.output_dir
    table = Table(title="Latest Report Paths")
    table.add_column("Report")
    table.add_column("Path")
    for name in ("latest.json", "latest.csv", "latest.html"):
        path = base / name
        exists = "yes" if path.exists() else "no"
        table.add_row(f"{name} ({exists})", str(path))
    table.add_row("Pentest audit log", str(settings.pentest.audit_log))
    table.add_row("Inventory", str(settings.inventory.path))
    console.print(table)


def interactive_menu(
    *,
    config_path: Path = DEFAULT_CONFIG_FILE,
    run_scan: RunScanCallable,
    run_doctor: RunDoctorCallable,
    console: Console | None = None,
) -> int:
    """Run the interactive terminal workflow."""
    console = console or Console()

    try:
        settings = load_settings(config_path)
    except Exception as exc:  # noqa: BLE001 - user-facing command should not dump traceback.
        console.print(f"[red]Could not load config:[/red] {exc}")
        return 2

    console.print(
        Panel(
            "Choose a safe audit action. Nothing modifies router/device settings.",
            title="Plinto Network Audit",
            border_style="green",
        )
    )

    while True:
        _render_menu(console)
        choice = IntPrompt.ask("Choose option", default=0)

        if choice == 0:
            console.print("[green]Exited interactive console.[/green]")
            return 0

        if choice == 1:
            args = _base_scan_namespace(config_path)
            args.local = True
            args = _ask_common_scan_options(args, settings)
            return run_scan(args)

        if choice == 2:
            args = _base_scan_namespace(config_path)
            args.local = True
            args.gateway = True
            args = _ask_common_scan_options(args, settings)
            return run_scan(args)

        if choice == 3:
            args = _base_scan_namespace(config_path)
            args.target = Prompt.ask("Private target IP/CIDR", default="192.168.1.1").strip()
            args = _ask_common_scan_options(args, settings)
            return run_scan(args)

        if choice == 4:
            if not _confirm_ownership(console):
                console.print("[red]Pentest dry-run cancelled: authorization phrase was not confirmed.[/red]")
                continue
            args = _base_scan_namespace(config_path)
            scan_scope = Prompt.ask("Scope", choices=["local", "gateway", "custom"], default="gateway")
            args.local = scan_scope in {"local", "gateway"}
            args.gateway = scan_scope == "gateway"
            if scan_scope == "custom":
                args.target = Prompt.ask("Private target IP/CIDR", default="192.168.1.1").strip()
            args.pentest = True
            args.i_own_this_network = True
            args.apply_pentest = False
            args.credentials_file = _ask_credentials_file()
            args = _ask_common_scan_options(args, settings)
            return run_scan(args)

        if choice == 5:
            if not _confirm_ownership(console):
                console.print("[red]Pentest validation cancelled: authorization phrase was not confirmed.[/red]")
                continue
            args = _base_scan_namespace(config_path)
            scan_scope = Prompt.ask("Scope", choices=["local", "gateway", "custom"], default="gateway")
            args.local = scan_scope in {"local", "gateway"}
            args.gateway = scan_scope == "gateway"
            if scan_scope == "custom":
                args.target = Prompt.ask("Private target IP/CIDR", default="192.168.1.1").strip()
            args.pentest = True
            args.i_own_this_network = True
            args.apply_pentest = True
            args.credentials_file = _ask_credentials_file()
            args.check_defaults = Confirm.ask("Also run tiny default-credential audit if enabled in config?", default=False)
            args = _ask_common_scan_options(args, settings)
            return run_scan(args)

        if choice == 6:
            return run_doctor(config_path, console=console)

        if choice == 7:
            _show_latest_report_paths(console, settings)
            continue

        console.print("[red]Invalid option.[/red]")
