"""Thin wrappers around Postfix / systemd command-line tools.

Everything here runs unprivileged. Anything that needs root goes through
run_helper(), which calls the whitelisted pfhop-helper via sudo.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass, field

from ..config import Config

POSTCONF = "/usr/sbin/postconf"
POSTQUEUE = "/usr/sbin/postqueue"
SYSTEMCTL = "/usr/bin/systemctl"


class CommandError(RuntimeError):
    pass


def _run(cmd: list[str], timeout: int = 15) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CommandError(f"{cmd[0]}: {exc}") from exc
    if proc.returncode != 0:
        raise CommandError(proc.stderr.strip() or f"{cmd[0]} exited with {proc.returncode}")
    return proc.stdout


def run_helper(cfg: Config, *args: str, timeout: int = 60, stdin: bytes | None = None,
               check: bool = True) -> bytes:
    """Run a pfhop-helper sub-command as root. Returns raw stdout."""
    cmd = [cfg.helper, *args]
    if os.geteuid() != 0 and cfg.use_sudo:
        cmd = ["sudo", "-n", *cmd]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False, input=stdin)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CommandError(f"pfhop-helper: {exc}") from exc
    if check and proc.returncode != 0:
        msg = proc.stderr.decode(errors="replace").strip()
        raise CommandError(msg or f"pfhop-helper exited with {proc.returncode}")
    return proc.stdout


# -- postconf -----------------------------------------------------------------

def _parse_postconf(text: str) -> dict[str, str]:
    params: dict[str, str] = {}
    for line in text.splitlines():
        if " = " in line:
            k, v = line.split(" = ", 1)
            params[k.strip()] = v.strip()
        elif line.endswith(" ="):
            params[line[:-2].strip()] = ""
    return params


def postconf_n() -> dict[str, str]:
    """Parameters explicitly set in main.cf."""
    return _parse_postconf(_run([POSTCONF, "-n"]))


def postconf_get(*names: str, expand: bool = False) -> dict[str, str]:
    """Effective values (including defaults) for specific parameters.

    expand=True resolves $name and ${...} expressions (postconf -x)."""
    return _parse_postconf(_run([POSTCONF, *(["-x"] if expand else []), *names]))


def postconf_defaults(*names: str) -> dict[str, str]:
    return _parse_postconf(_run([POSTCONF, "-d", *names]))


@dataclass
class MasterEntry:
    service: str
    type: str
    private: str
    unpriv: str
    chroot: str
    wakeup: str
    maxproc: str
    command: str


def postconf_master() -> list[MasterEntry]:
    entries: list[MasterEntry] = []
    for line in _run([POSTCONF, "-M"]).splitlines():
        parts = line.split(None, 7)
        if len(parts) == 8:
            entries.append(MasterEntry(*parts))
    return entries


# -- systemd ------------------------------------------------------------------

@dataclass
class ServiceStatus:
    active_state: str = "unknown"
    sub_state: str = ""
    unit_file_state: str = ""
    main_pid: int = 0
    active_since: int | None = None
    restarts: int = 0
    error: str = ""

    @property
    def running(self) -> bool:
        return self.active_state == "active"

    @property
    def uptime(self) -> int | None:
        return int(time.time()) - self.active_since if self.active_since and self.running else None


def service_status(unit: str = "postfix") -> ServiceStatus:
    props = "ActiveState,SubState,UnitFileState,MainPID,ActiveEnterTimestamp,NRestarts"
    try:
        out = _run([SYSTEMCTL, "show", unit, f"--property={props}", "--timestamp=unix"])
    except CommandError as exc:
        return ServiceStatus(error=str(exc))
    raw = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    since = raw.get("ActiveEnterTimestamp", "")
    return ServiceStatus(
        active_state=raw.get("ActiveState", "unknown"),
        sub_state=raw.get("SubState", ""),
        unit_file_state=raw.get("UnitFileState", ""),
        main_pid=int(raw.get("MainPID", "0") or 0),
        active_since=int(since[1:]) if since.startswith("@") else None,
        restarts=int(raw.get("NRestarts", "0") or 0),
    )


# -- queue --------------------------------------------------------------------

@dataclass
class QueueMessage:
    queue_id: str
    queue_name: str
    arrival_time: int
    size: int
    sender: str
    recipients: list[dict]

    @property
    def age(self) -> int:
        return max(0, int(time.time()) - self.arrival_time)

    @property
    def delay_reason(self) -> str:
        for r in self.recipients:
            if r.get("delay_reason"):
                return r["delay_reason"]
        return ""


@dataclass
class QueueSummary:
    messages: list[QueueMessage] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    error: str = ""

    @property
    def total(self) -> int:
        return len(self.messages)

    @property
    def total_size(self) -> int:
        return sum(m.size for m in self.messages)

    @property
    def recipients(self) -> int:
        return sum(len(m.recipients) for m in self.messages)

    @property
    def oldest(self) -> QueueMessage | None:
        return min(self.messages, key=lambda m: m.arrival_time, default=None)


def queue_summary() -> QueueSummary:
    summary = QueueSummary(counts={"active": 0, "incoming": 0, "deferred": 0, "hold": 0, "maildrop": 0})
    try:
        out = _run([POSTQUEUE, "-j"], timeout=30)
    except CommandError as exc:
        summary.error = str(exc)
        return summary
    for line in out.splitlines():
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        msg = QueueMessage(
            queue_id=d.get("queue_id", ""),
            queue_name=d.get("queue_name", ""),
            arrival_time=int(d.get("arrival_time", 0)),
            size=int(d.get("message_size", 0)),
            sender=d.get("sender", "") or "<>",
            recipients=d.get("recipients", []),
        )
        summary.messages.append(msg)
        summary.counts[msg.queue_name] = summary.counts.get(msg.queue_name, 0) + 1
    return summary


# -- misc ---------------------------------------------------------------------

def postfix_overview() -> dict:
    """Key Postfix facts for the dashboard."""
    names = (
        "mail_version", "myhostname", "relayhost", "mynetworks", "inet_interfaces",
        "inet_protocols", "smtp_tls_security_level", "smtpd_tls_security_level",
        "maximal_queue_lifetime", "bounce_queue_lifetime", "queue_minfree",
        "queue_directory", "message_size_limit", "default_destination_concurrency_limit",
        "smtp_destination_concurrency_limit",
    )
    try:
        values = postconf_get(*names)
        values["error"] = ""
    except CommandError as exc:
        values = {"error": str(exc)}
    values["mynetworks_list"] = values.get("mynetworks", "").replace(",", " ").split()
    return values


# -- actions ------------------------------------------------------------------
# Flushing / requeueing are allowed for any user (authorized_flush_users =
# static:anyone by default); deleting, holding and service control need root
# and go through pfhop-helper.

import re as _re

QUEUE_ID_RE = _re.compile(r"^[0-9A-Za-z]{6,20}$")
SERVICE_ACTIONS = ("start", "stop", "restart", "reload")
QUEUE_ACTIONS = ("retry", "delete", "hold", "release")


def flush_queue() -> str:
    _run([POSTQUEUE, "-f"], timeout=60)
    return "All queued messages scheduled for immediate delivery."


def _check_ids(ids: list[str]) -> list[str]:
    ids = [i.strip() for i in ids if i.strip()]
    if not ids or not all(QUEUE_ID_RE.match(i) for i in ids):
        raise CommandError("Invalid queue ID.")
    return ids


def queue_action(cfg: Config, action: str, ids: list[str]) -> str:
    ids = _check_ids(ids)
    if action == "retry":
        for qid in ids:
            _run([POSTQUEUE, "-i", qid], timeout=30)
        return f"Delivery requested for {len(ids)} message(s)."
    if action in ("delete", "hold", "release"):
        out = run_helper(cfg, f"queue-{action}", *ids, timeout=120).decode(errors="replace")
        # postsuper summary, e.g. "postsuper: Deleted: 3 messages"
        m = _re.search(r"(Deleted|Placed on hold|Released from hold): (\d+) message", out)
        n = int(m.group(2)) if m else 0
        verb = {"delete": "Deleted", "hold": "Put on hold", "release": "Released"}[action]
        if n == 0:
            raise CommandError("No message was changed - it may have already left the queue"
                               + (" or is not on hold." if action == "release" else "."))
        return f"{verb} {n} message(s)."
    raise CommandError("Unknown queue action.")


def service_action(cfg: Config, action: str) -> str:
    if action not in SERVICE_ACTIONS:
        raise CommandError("Unknown service action.")
    run_helper(cfg, "service", action, timeout=150)
    return f"Postfix {action} completed."


def apply_config(cfg: Config, bundle: dict) -> dict:
    """Send a configuration bundle to `pfhop-helper apply`. Returns {"ok", "log", "error"}."""
    out = run_helper(cfg, "apply", timeout=180, stdin=json.dumps(bundle).encode(), check=False)
    try:
        return json.loads(out.decode(errors="replace").strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"ok": False, "error": out.decode(errors="replace").strip() or "pfhop-helper failed"}
