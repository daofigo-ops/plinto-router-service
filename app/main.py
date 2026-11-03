from __future__ import annotations

import argparse
import asyncio
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from app.commands.doctor import run_doctor
from app.config import DEFAULT_CONFIG_FILE, ScanConfig, load_settings, parse_ports
from app.inventory.device_inventory import update_inventory
from app.interactive.menu import interactive_menu
from app.reports.csv_report import write_csv_report
from app.reports.history import prepare_report_paths, write_latest_copy
from app.reports.html_report import write_html_report
from app.reports.json_report import write_json_report
from app.reports.summary import build_summary
from app.dns.dns_audit import apply_dns_audit
from app.pentest.auth_check import run_authorized_auth_checks
from app.safety.pentest_guard import PentestGuardError, validate_pentest_mode
from app.safety.scope_guard import ScopeError
from app.scanner.discovery import scan_network
from app.scanner.local_network import LocalNetworkError, detect_local_target

console = Console()


DESCRIPTION = "Authorized private-network router/IoT discovery and risk reporting tool."


def render_findings_table(findings) -> None:
    table = Table(title="Plinto Network Audit Findings", show_lines=False)
    table.add_column("IP", style="cyan", no_wrap=True)
    table.add_column("Port", justify="right")
    table.add_column("Scheme")
    table.add_column("Status")
    table.add_column("Type")
    table.add_column("Vendor")
    table.add_column("Risk", justify="right")
    table.add_column("DNS")
    table.add_column("Pentest")
    table.add_column("Title / Server")
    table.add_column("Top Recommendation")

    for item in findings:
        title_or_server = item.title or item.server or item.redirect_location or "-"
        if len(title_or_server) > 42:
            title_or_server = title_or_server[:39] + "..."
        recommendation = item.recommendations[0] if item.recommendations else "-"
        if len(recommendation) > 48:
            recommendation = recommendation[:45] + "..."
        pentest_status = "-"
        if item.pentest_attempts:
            success_count = sum(1 for attempt in item.pentest_attempts if attempt.result == "success")
            pentest_status = f"success:{success_count}" if success_count else f"attempts:{len(item.pentest_attempts)}"
        elif item.pentest_notes:
            pentest_status = "dry-run"
        table.add_row(
            item.ip,
            str(item.port),
            item.scheme,
            str(item.status_code or "-"),
            item.device_type,
            item.vendor_guess,
            f"{item.risk_level} ({item.risk_score})",
            item.dns_audit.status,
            pentest_status,
            title_or_server,
            recommendation,
        )

    console.print(table)


def render_summary(summary) -> None:
    risk_text = ", ".join(f"{key}: {value}" for key, value in sorted(summary.risk_counts.items())) or "None"
    body = (
        f"Target: [bold]{summary.target}[/bold]\n"
        f"Unique hosts: [bold]{summary.unique_hosts}[/bold]\n"
        f"Web services: [bold]{summary.service_count}[/bold]\n"
        f"HTTP-only services: [bold]{summary.http_only_count}[/bold]\n"
        f"HTTPS services: [bold]{summary.https_count}[/bold]\n"
        f"Router/gateway-like services: [bold]{summary.router_like_count}[/bold]\n"
        f"Admin-like services: [bold]{summary.admin_like_count}[/bold]\n"
        f"Server errors: [bold]{summary.server_error_count}[/bold]\n"
        f"DNS checks needing review: [bold]{summary.dns_needs_review_count}[/bold]\n"
        f"Pentest attempts/successes: [bold]{summary.pentest_attempt_count}/{summary.pentest_success_count}[/bold]\n"
        f"Highest risk: [bold]{summary.highest_risk_level} ({summary.highest_risk_score})[/bold]\n"
        f"Risk mix: {risk_text}"
    )
    console.print(Panel(body, title="Scan Summary", border_style="green"))

    if summary.top_actions:
        action_text = "\n".join(f"{idx}. {action}" for idx, action in enumerate(summary.top_actions, start=1))
        console.print(Panel(action_text, title="Top Recommended Actions", border_style="yellow"))


def render_inventory_changes(changes: dict | None) -> None:
    if not changes:
        return

    new_count = len(changes.get("new_services", []))
    changed_count = len(changes.get("changed_services", []))
    missing_count = len(changes.get("missing_known_services", []))
    unchanged = changes.get("unchanged_services", 0)
    total = changes.get("total_known_services", 0)

    body = (
        f"Inventory file: [bold]{changes.get('inventory_path')}[/bold]\n"
        f"New services this run: [bold]{new_count}[/bold]\n"
        f"Changed services this run: [bold]{changed_count}[/bold]\n"
        f"Unchanged services this run: [bold]{unchanged}[/bold]\n"
        f"Known services not seen in this run: [bold]{missing_count}[/bold]\n"
        f"Total known services: [bold]{total}[/bold]"
    )
    console.print(Panel(body, title="Inventory Delta", border_style="blue"))

    if new_count or changed_count:
        table = Table(title="Inventory Highlights")
        table.add_column("Kind")
        table.add_column("Service")
        table.add_column("Detail")
        for item in changes.get("new_services", [])[:8]:
            service = item.get("service", {})
            table.add_row("New", item.get("key", "-"), f"{service.get('device_type', 'Unknown')} · {service.get('risk_level', '-')}")
        for item in changes.get("changed_services", [])[:8]:
            fields = ", ".join(item.get("changes", {}).keys())
            table.add_row("Changed", item.get("key", "-"), fields or "Updated")
        console.print(table)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="plinto-audit",
        description=DESCRIPTION,
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan an authorized private IPv4 target, CIDR range, or the local LAN.",
        description="Scan an authorized private network range without logging in or changing devices.",
    )
    scan_parser.add_argument(
        "target",
        nargs="?",
        help="Private IPv4 target, for example 192.168.1.1 or 192.168.1.0/24. Omit when using --local.",
    )
    scan_parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_FILE,
        type=Path,
        help="YAML config file. Default: config/plinto.yaml",
    )
    scan_parser.add_argument(
        "--local",
        action="store_true",
        help="Auto-detect the current private LAN and scan it. Defaults to /24 unless config overrides it.",
    )
    scan_parser.add_argument(
        "--gateway",
        action="store_true",
        help="With --local, scan only the detected default gateway instead of the full local range.",
    )
    scan_parser.add_argument(
        "--local-prefix",
        default=None,
        type=int,
        help="CIDR prefix used with --local. For safety, allowed range is 24-32.",
    )
    scan_parser.add_argument(
        "--ports",
        default=None,
        help="Comma-separated TCP ports to probe. If omitted, config/plinto.yaml is used.",
    )
    scan_parser.add_argument(
        "--out",
        dest="output_dir",
        default=None,
        type=Path,
        help="Directory where reports will be written. If omitted, config/plinto.yaml is used.",
    )
    scan_parser.add_argument("--timeout", default=None, type=float, help="Per-request timeout in seconds.")
    scan_parser.add_argument("--concurrency", default=None, type=int, help="Maximum concurrent HTTP probes.")
    scan_parser.add_argument("--max-hosts", default=None, type=int, help="Safety cap for number of hosts in one scan.")
    scan_parser.add_argument(
        "--format",
        dest="report_format",
        default="all",
        choices=("json", "csv", "html", "both", "all"),
        help="Report format. 'both' writes JSON+CSV. 'all' writes JSON+CSV+HTML. Default: all",
    )
    scan_parser.add_argument(
        "--no-deep-fingerprint",
        action="store_true",
        help="Disable safe extra path probes such as /login, /admin, /docs.",
    )
    scan_parser.add_argument(
        "--max-extra-paths",
        default=None,
        type=int,
        help="Maximum common paths checked per discovered service during deep fingerprinting.",
    )
    scan_parser.add_argument("--no-history", action="store_true", help="Write directly into the report directory instead of timestamped scan folders.")
    scan_parser.add_argument("--no-latest", action="store_true", help="Do not refresh reports/latest.* copies.")
    scan_parser.add_argument("--no-inventory", action="store_true", help="Do not update data/device_inventory.json after the scan.")
    scan_parser.add_argument("--no-dns-audit", action="store_true", help="Disable audit-only visible DNS resolver checks.")
    scan_parser.add_argument("--pentest", action="store_true", help="Enable restricted authorized Pentest Mode. Requires --i-own-this-network.")
    scan_parser.add_argument("--i-own-this-network", action="store_true", help="Required confirmation for Pentest Mode on your owned/authorized private network.")
    scan_parser.add_argument("--credentials", dest="credentials_file", default=None, type=Path, help="YAML file containing user-supplied known credentials for owned devices.")
    scan_parser.add_argument("--check-defaults", action="store_true", help="Optional tiny factory-default credential audit. Disabled in config by default.")
    scan_parser.add_argument("--apply-pentest", action="store_true", help="Actually run authorized validation attempts. Without this, Pentest Mode is a dry run.")
    scan_parser.add_argument("--pentest-rate-limit", default=None, type=float, help="Seconds to wait between credential validation attempts. Minimum 0.25.")
    scan_parser.add_argument("--pentest-audit-log", default=None, type=Path, help="JSONL audit log path for Pentest Mode attempts.")

    menu_parser = subparsers.add_parser("menu", aliases=["interactive"], help="Open an interactive terminal menu for scans, reports, pentest dry-run, and diagnostics.")
    menu_parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_FILE,
        type=Path,
        help="YAML config file. Default: config/plinto.yaml",
    )

    doctor_parser = subparsers.add_parser("doctor", help="Check installation, config, directories, and local network detection.")
    doctor_parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_FILE,
        type=Path,
        help="YAML config file. Default: config/plinto.yaml",
    )

    return parser


def normalize_argv(argv: Sequence[str]) -> list[str]:
    """Allow both `scan TARGET` and the convenient direct form `TARGET`.

    Also allow `--local` as shorthand for `scan --local`.
    """
    args = list(argv)
    if not args:
        return args

    first = args[0]
    if first in {"-h", "--help", "scan", "doctor", "menu", "interactive"}:
        return args

    if not first.startswith("-"):
        return ["scan", *args]

    scan_option_firsts = {
        "--config",
        "--local",
        "--gateway",
        "--local-prefix",
        "--ports",
        "--out",
        "--timeout",
        "--concurrency",
        "--max-hosts",
        "--format",
        "--no-deep-fingerprint",
        "--max-extra-paths",
        "--no-history",
        "--no-latest",
        "--no-inventory",
        "--no-dns-audit",
        "--pentest",
        "--i-own-this-network",
        "--credentials",
        "--check-defaults",
        "--apply-pentest",
        "--pentest-rate-limit",
        "--pentest-audit-log",
    }
    if first in scan_option_firsts:
        return ["scan", *args]

    return args


def resolve_target(args: argparse.Namespace, local_prefix: int) -> str:
    if args.local:
        return detect_local_target(prefix=local_prefix, gateway_only=args.gateway)
    if args.target:
        return args.target
    raise ValueError("Missing target. Provide a private IP/CIDR or use --local.")


def build_scan_config(args: argparse.Namespace) -> ScanConfig:
    settings = load_settings(args.config)
    local_prefix = args.local_prefix if args.local_prefix is not None else settings.scan.local_prefix
    target = resolve_target(args, local_prefix=local_prefix)

    ports = parse_ports(args.ports) if args.ports is not None else list(settings.default_ports)
    return ScanConfig(
        target=target,
        ports=ports,
        timeout=args.timeout if args.timeout is not None else settings.scan.timeout,
        concurrency=args.concurrency if args.concurrency is not None else settings.scan.concurrency,
        max_hosts=args.max_hosts if args.max_hosts is not None else settings.scan.max_hosts,
        output_dir=args.output_dir if args.output_dir is not None else settings.reports.output_dir,
        fingerprint_file=settings.fingerprint_file,
        private_only=settings.scan.private_only,
        deep_fingerprint=False if args.no_deep_fingerprint else settings.scan.deep_fingerprint,
        max_extra_paths=args.max_extra_paths if args.max_extra_paths is not None else settings.scan.max_extra_paths,
        save_history=False if args.no_history else settings.reports.save_history,
        write_latest_copies=False if args.no_latest else settings.reports.write_latest_copies,
        inventory_enabled=False if args.no_inventory else settings.inventory.enabled,
        inventory_path=settings.inventory.path,
        dns_audit_enabled=False if args.no_dns_audit else settings.dns.audit_visible_dns,
        pentest_enabled=bool(args.pentest),
        i_own_this_network=bool(args.i_own_this_network),
        credentials_file=args.credentials_file,
        check_defaults=bool(args.check_defaults),
        allow_default_credential_check=settings.pentest.allow_default_credential_check,
        pentest_dry_run=False if args.apply_pentest else settings.pentest.dry_run,
        pentest_rate_limit_seconds=args.pentest_rate_limit if args.pentest_rate_limit is not None else settings.pentest.rate_limit_seconds,
        max_default_credentials=settings.pentest.max_default_credentials,
        pentest_audit_log=args.pentest_audit_log if args.pentest_audit_log is not None else settings.pentest.audit_log,
    )


def run_scan(args: argparse.Namespace) -> int:
    try:
        config = build_scan_config(args)
    except (ValueError, LocalNetworkError) as exc:
        console.print(f"[red]Configuration error:[/red] {exc}")
        return 2

    if config.pentest_enabled:
        try:
            validate_pentest_mode(config)
        except PentestGuardError as exc:
            console.print(f"[red]Pentest mode blocked:[/red] {exc}")
            return 4

    console.print(
        f"[bold]Starting safe audit scan[/bold] target={config.target} "
        f"ports={','.join(map(str, config.ports))} private_only={config.private_only} "
        f"deep_fingerprint={config.deep_fingerprint} dns_audit={config.dns_audit_enabled} "
        f"history={config.save_history} pentest={config.pentest_enabled}"
    )
    if config.pentest_enabled:
        dry_run_text = "dry-run" if config.pentest_dry_run else "active validation"
        console.print(
            f"[yellow]Authorized Pentest Mode enabled ({dry_run_text}).[/yellow] "
            f"Audit log: {config.pentest_audit_log}"
        )

    started_at = datetime.now(timezone.utc)
    try:
        findings = asyncio.run(scan_network(config))
    except ScopeError as exc:
        console.print(f"[red]Scope blocked:[/red] {exc}")
        return 3
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        return 130

    if config.dns_audit_enabled:
        findings = apply_dns_audit(findings)

    if config.pentest_enabled:
        try:
            findings = asyncio.run(run_authorized_auth_checks(findings, config))
        except PentestGuardError as exc:
            console.print(f"[red]Pentest mode blocked:[/red] {exc}")
            return 4

    finished_at = datetime.now(timezone.utc)
    summary = build_summary(findings, target=config.target, started_at=started_at, finished_at=finished_at)

    inventory_changes = None
    if config.inventory_enabled:
        inventory_changes = update_inventory(findings, config.inventory_path, target=config.target)

    if findings:
        render_findings_table(findings)
    else:
        console.print("[yellow]No HTTP/HTTPS services responded on the selected ports.[/yellow]")

    render_summary(summary)
    render_inventory_changes(inventory_changes)

    paths = prepare_report_paths(
        output_dir=config.output_dir,
        started_at=started_at,
        save_history=config.save_history,
        write_latest_copies=config.write_latest_copies,
    )

    written: list[Path] = []
    latest_written: list[Path] = []
    report_format = args.report_format.lower().strip()

    json_name = "report.json" if config.save_history else "plinto_audit_report.json"
    csv_name = "report.csv" if config.save_history else "plinto_audit_report.csv"
    html_name = "report.html" if config.save_history else "plinto_audit_report.html"

    if report_format in {"json", "both", "all"}:
        written.append(write_json_report(findings, paths.run_dir, summary=summary, inventory_changes=inventory_changes, filename=json_name))
    if report_format in {"csv", "both", "all"}:
        written.append(write_csv_report(findings, paths.run_dir, filename=csv_name))
    if report_format in {"html", "all"}:
        written.append(write_html_report(findings, paths.run_dir, summary=summary, inventory_changes=inventory_changes, filename=html_name))

    if paths.latest_enabled:
        for path in written:
            latest_written.append(write_latest_copy(path, paths.base_dir))

    for path in written:
        console.print(f"[green]Wrote report:[/green] {path}")
    for path in latest_written:
        console.print(f"[green]Updated latest copy:[/green] {path}")

    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    normalized = normalize_argv(sys.argv[1:] if argv is None else argv)

    if not normalized:
        parser.print_help()
        return 0

    args = parser.parse_args(normalized)

    if args.command == "scan":
        return run_scan(args)
    if args.command in {"menu", "interactive"}:
        return interactive_menu(config_path=args.config, run_scan=run_scan, run_doctor=run_doctor, console=console)
    if args.command == "doctor":
        return run_doctor(args.config, console=console)

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
