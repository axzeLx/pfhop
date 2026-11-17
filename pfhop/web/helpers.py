"""Template filters and small request helpers."""

from __future__ import annotations

import ipaddress
import time
from datetime import datetime

from fastapi import Request


def filesize(n: int | float | None) -> str:
    if n is None:
        return "-"
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def duration(seconds: int | float | None, short: bool = False) -> str:
    if seconds is None:
        return "-"
    s = int(seconds)
    days, s = divmod(s, 86400)
    hours, s = divmod(s, 3600)
    minutes, s = divmod(s, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes and (not short or not days):
        parts.append(f"{minutes}m")
    if not parts:
        parts.append(f"{s}s")
    return " ".join(parts[:2] if short else parts)


def fmt_ts(ts: int | float | None, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    if not ts:
        return "-"
    return datetime.fromtimestamp(ts).strftime(fmt)


def ago(ts: int | float | None) -> str:
    if not ts:
        return "never"
    return duration(time.time() - ts, short=True) + " ago"


def level(percent: float, warn: float, crit: float) -> str:
    if percent >= crit:
        return "crit"
    if percent >= warn:
        return "warn"
    return "ok"


def parse_postfix_size(value: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def client_ip(request: Request, trusted_proxies: list[str]) -> str:
    peer = request.client.host if request.client else ""
    if peer in trusted_proxies:
        forwarded = request.headers.get("x-real-ip") or request.headers.get("x-forwarded-for", "")
        forwarded = forwarded.split(",")[0].strip()
        if forwarded:
            return forwarded
    return peer


def ip_allowed(ip: str, networks: list[str]) -> bool:
    if not networks:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in networks:
        try:
            if addr in ipaddress.ip_network(net, strict=False):
                return True
        except ValueError:
            continue
    return False
