from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator


DEFAULT_PORTS = [80, 443, 8080, 8443, 8000, 8888]
DEFAULT_CONFIG_FILE = Path("config/plinto.yaml")


class ScanDefaults(BaseModel):
    timeout: float = 3.0
    concurrency: int = 128
    max_hosts: int = 512
    local_prefix: int = 24
    private_only: bool = True
    deep_fingerprint: bool = True
    max_extra_paths: int = 14


class ReportDefaults(BaseModel):
    output_dir: Path = Path("reports")
    save_history: bool = True
    write_latest_copies: bool = True


class InventoryDefaults(BaseModel):
    enabled: bool = True
    path: Path = Path("data/device_inventory.json")


class PentestDefaults(BaseModel):
    enabled: bool = False
    allow_default_credential_check: bool = False
    dry_run: bool = True
    rate_limit_seconds: float = 1.0
    max_default_credentials: int = 3
    audit_log: Path = Path("reports/pentest_audit.jsonl")


class DNSDefaults(BaseModel):
    audit_visible_dns: bool = True


class AppSettings(BaseModel):
    default_ports: list[int] = Field(default_factory=lambda: list(DEFAULT_PORTS))
    scan: ScanDefaults = Field(default_factory=ScanDefaults)
    reports: ReportDefaults = Field(default_factory=ReportDefaults)
    inventory: InventoryDefaults = Field(default_factory=InventoryDefaults)
    pentest: PentestDefaults = Field(default_factory=PentestDefaults)
    dns: DNSDefaults = Field(default_factory=DNSDefaults)
    fingerprint_file: Path = Path("data/fingerprints.yaml")

    @field_validator("default_ports")
    @classmethod
    def validate_default_ports(cls, value: list[int]) -> list[int]:
        return validate_ports(value)


class ScanConfig(BaseModel):
    """Runtime scan configuration."""

    target: str
    ports: list[int] = Field(default_factory=lambda: list(DEFAULT_PORTS))
    timeout: float = 3.0
    concurrency: int = 128
    max_hosts: int = 512
    output_dir: Path = Path("reports")
    fingerprint_file: Path = Path("data/fingerprints.yaml")
    private_only: bool = True
    deep_fingerprint: bool = True
    max_extra_paths: int = 14
    save_history: bool = True
    write_latest_copies: bool = True
    inventory_enabled: bool = True
    inventory_path: Path = Path("data/device_inventory.json")
    dns_audit_enabled: bool = True
    pentest_enabled: bool = False
    i_own_this_network: bool = False
    credentials_file: Path | None = None
    check_defaults: bool = False
    allow_default_credential_check: bool = False
    pentest_dry_run: bool = True
    pentest_rate_limit_seconds: float = 1.0
    max_default_credentials: int = 3
    pentest_audit_log: Path = Path("reports/pentest_audit.jsonl")

    @field_validator("ports")
    @classmethod
    def validate_scan_ports(cls, value: list[int]) -> list[int]:
        return validate_ports(value)

    @field_validator("timeout")
    @classmethod
    def validate_timeout(cls, value: float) -> float:
        if value <= 0:
            raise ValueError("Timeout must be positive")
        return value

    @field_validator("concurrency")
    @classmethod
    def validate_concurrency(cls, value: int) -> int:
        if value < 1:
            raise ValueError("Concurrency must be at least 1")
        return value

    @field_validator("max_extra_paths")
    @classmethod
    def validate_max_extra_paths(cls, value: int) -> int:
        if value < 0:
            raise ValueError("max_extra_paths cannot be negative")
        return value

    @field_validator("pentest_rate_limit_seconds")
    @classmethod
    def validate_rate_limit(cls, value: float) -> float:
        if value < 0.25:
            raise ValueError("pentest_rate_limit_seconds must be at least 0.25")
        return value


def validate_ports(value: list[int]) -> list[int]:
    cleaned = sorted(set(int(item) for item in value))
    for port in cleaned:
        if port < 1 or port > 65535:
            raise ValueError(f"Invalid TCP port: {port}")
    return cleaned


def parse_ports(value: str | list[int] | tuple[int, ...] | None) -> list[int]:
    """Parse a comma-separated port list or a list of integers."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return validate_ports([int(item) for item in value])

    ports: list[int] = []
    for item in str(value).split(","):
        item = item.strip()
        if not item:
            continue
        ports.append(int(item))
    return validate_ports(ports)


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Config file must contain a YAML object: {path}")
    return data


def load_settings(config_file: Path | str | None = None) -> AppSettings:
    """Load optional YAML settings, falling back to safe defaults."""
    path = Path(config_file) if config_file else DEFAULT_CONFIG_FILE
    data = _read_yaml(path)
    return AppSettings.model_validate(data)


def resolve_path_from_project(path: Path) -> Path:
    """Return a normalized path while keeping relative paths project-friendly."""
    return path.expanduser()
