from __future__ import annotations

import importlib.metadata
import platform
import sys
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from app.config import DEFAULT_CONFIG_FILE, load_settings
from app.scanner.local_network import LocalNetworkError, detect_local_target


REQUIRED_PACKAGES = ["httpx", "rich", "pydantic", "PyYAML"]


def _ok(value: bool) -> str:
    return "[green]OK[/green]" if value else "[red]Needs attention[/red]"


def _package_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return "not installed"


def _check_writable_dir(path: Path) -> tuple[bool, str]:
    try:
        path.mkdir(parents=True, exist_ok=True)
        test_file = path / ".plinto_write_test"
        test_file.write_text("ok", encoding="utf-8")
        test_file.unlink(missing_ok=True)
        return True, str(path)
    except OSError as exc:
        return False, f"{path} ({exc})"


def run_doctor(config_file: Path | None = None, console: Console | None = None) -> int:
    console = console or Console()
    config_path = config_file or DEFAULT_CONFIG_FILE

    checks: list[tuple[str, bool, str]] = []
    py_ok = sys.version_info >= (3, 10)
    checks.append(("Python", py_ok, f"{platform.python_version()} at {sys.executable}"))

    try:
        settings = load_settings(config_path)
        checks.append(("Config file", True, f"Loaded {config_path}" if config_path.exists() else f"Using defaults; optional file not found: {config_path}"))
    except Exception as exc:
        checks.append(("Config file", False, f"{config_path}: {exc}"))
        settings = load_settings(None)

    for package in REQUIRED_PACKAGES:
        version = _package_version(package)
        checks.append((f"Package: {package}", version != "not installed", version))

    reports_ok, reports_detail = _check_writable_dir(settings.reports.output_dir)
    checks.append(("Reports directory", reports_ok, reports_detail))

    inventory_parent = settings.inventory.path.parent
    inventory_ok, inventory_detail = _check_writable_dir(inventory_parent)
    checks.append(("Inventory directory", inventory_ok, inventory_detail))

    fp = settings.fingerprint_file
    checks.append(("Fingerprint rules", fp.exists(), str(fp)))

    credentials_example = Path("config/credentials.example.yaml")
    checks.append(("Credential example", credentials_example.exists(), str(credentials_example)))
    checks.append(("Pentest default", not settings.pentest.enabled, "disabled by default" if not settings.pentest.enabled else "enabled in config"))
    checks.append(("Default credential check", not settings.pentest.allow_default_credential_check, "disabled by default" if not settings.pentest.allow_default_credential_check else "enabled in config"))
    checks.append(("DNS audit default", settings.dns.audit_visible_dns, "visible DNS audit enabled" if settings.dns.audit_visible_dns else "disabled"))

    try:
        local_target = detect_local_target(prefix=settings.scan.local_prefix, gateway_only=False)
        checks.append(("Local subnet detection", True, local_target))
    except LocalNetworkError as exc:
        checks.append(("Local subnet detection", False, str(exc)))

    try:
        gateway = detect_local_target(prefix=settings.scan.local_prefix, gateway_only=True)
        checks.append(("Gateway detection", True, gateway))
    except LocalNetworkError as exc:
        checks.append(("Gateway detection", False, str(exc)))

    table = Table(title="Plinto Doctor")
    table.add_column("Check", style="cyan")
    table.add_column("Status")
    table.add_column("Details")
    for label, ok, detail in checks:
        table.add_row(label, _ok(ok), detail)
    console.print(table)

    failed = [label for label, ok, _ in checks if not ok and label not in {"Gateway detection"}]
    if failed:
        console.print("[yellow]Doctor completed with issues.[/yellow]")
        return 1

    console.print("[green]Doctor completed successfully.[/green]")
    return 0
