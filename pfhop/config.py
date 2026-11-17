"""Loads the static configuration file (TOML).

Static, install-time settings live in /etc/pfhop/pfhop.conf (or the file
pointed to by PFHOP_CONFIG). Settings that admins change at runtime from the
web UI live in the database (see db.py) instead.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CONFIG_PATH = "/etc/pfhop/pfhop.conf"


@dataclass
class Config:
    # [server]
    host: str = "127.0.0.1"
    port: int = 8000
    # Only trust X-Forwarded-For / X-Real-IP coming from these proxies.
    trusted_proxies: list[str] = field(default_factory=lambda: ["127.0.0.1", "::1"])

    # [paths]
    data_dir: str = "/var/lib/pfhop"
    maillog: str = "/var/log/maillog"

    # [security]
    secret_key: str = ""
    session_hours: int = 8
    cookie_secure: bool = True
    # Optional application-level allow-list (CIDRs). Empty = allow all
    # (network access is normally restricted by nginx/firewalld as well).
    allowed_networks: list[str] = field(default_factory=list)

    # [postfix]
    helper: str = "/usr/libexec/pfhop/pfhop-helper"
    use_sudo: bool = True

    config_path: str = DEFAULT_CONFIG_PATH

    @property
    def db_path(self) -> Path:
        return Path(self.data_dir) / "pfhop.db"

    @property
    def backup_dir(self) -> Path:
        return Path(self.data_dir) / "backups"


def load_config(path: str | None = None) -> Config:
    path = path or os.environ.get("PFHOP_CONFIG") or DEFAULT_CONFIG_PATH
    cfg = Config(config_path=path)
    p = Path(path)
    if p.exists():
        with p.open("rb") as fh:
            raw = tomllib.load(fh)
        sections = {
            "server": ("host", "port", "trusted_proxies"),
            "paths": ("data_dir", "maillog"),
            "security": ("secret_key", "session_hours", "cookie_secure", "allowed_networks"),
            "postfix": ("helper", "use_sudo"),
        }
        for section, keys in sections.items():
            values = raw.get(section, {})
            for key in keys:
                if key in values:
                    setattr(cfg, key, values[key])
    if not cfg.secret_key:
        raise SystemExit(
            f"pfhop: 'secret_key' is not set in {path}. "
            "Generate one with: python3 -c 'import secrets; print(secrets.token_hex(32))'"
        )
    return cfg
