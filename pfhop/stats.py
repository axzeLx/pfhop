"""Queries over the collected mail log (messages / deliveries / rejects)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from datetime import time as dtime

from .db import Database

DELIVERY_STATUSES = ("sent", "deferred", "bounced", "expired", "discarded")


def day_start(d: date | None = None) -> float:
    """Local midnight (00:00) of the given day, as epoch seconds."""
    return datetime.combine(d or date.today(), dtime.min).timestamp()


def collector_age(db: Database) -> int | None:
    """Seconds since the collector last reported in (None = never ran)."""
    row = db.query_one("SELECT value FROM meta WHERE key = 'collector_heartbeat'")
    return int(time.time()) - int(row["value"]) if row else None


def today_counts(db: Database) -> dict[str, int]:
    row = db.query_one(
        "SELECT "
        " SUM(status = 'sent') AS sent, "
        " SUM(status IN ('bounced', 'expired')) AS bounced, "
        " SUM(status = 'deferred') AS deferred_attempts "
        "FROM deliveries WHERE ts >= ?",
        (day_start(),),
    )
    return {k: int(row[k] or 0) for k in ("sent", "bounced", "deferred_attempts")}


def top_senders(db: Database, limit: int = 10) -> list:
    return db.query(
        "SELECT COALESCE(sender, '') AS sender, COUNT(*) AS messages, "
        "       COALESCE(SUM(nrcpt), 0) AS recipients "
        "FROM messages WHERE first_seen >= ? AND sender IS NOT NULL "
        "GROUP BY sender ORDER BY messages DESC, sender LIMIT ?",
        (day_start(), limit),
    )


def bounces_today(db: Database, limit: int = 10) -> list:
    return db.query(
        "SELECT recipient, COUNT(*) AS count, MAX(ts) AS last_ts, "
        "       (SELECT d2.response FROM deliveries d2 WHERE d2.recipient = d.recipient "
        "        AND d2.status = 'bounced' ORDER BY d2.ts DESC LIMIT 1) AS reason "
        "FROM deliveries d WHERE status = 'bounced' AND ts >= ? "
        "GROUP BY recipient ORDER BY count DESC, last_ts DESC LIMIT ?",
        (day_start(), limit),
    )


_DELIVERY_SELECT = (
    "SELECT d.id, d.ts, d.queue_id, d.recipient, d.orig_to, d.transport, d.relay, d.delay, "
    "       d.dsn, d.status, d.response, m.sender, m.client_ip, m.client_host, m.size, "
    "       m.first_seen, m.message_id "
    "FROM deliveries d LEFT JOIN messages m ON m.id = d.msg_id "
)


def recent_deliveries(db: Database, limit: int = 20) -> list:
    return db.query(_DELIVERY_SELECT + "ORDER BY d.ts DESC, d.id DESC LIMIT ?", (limit,))


# Date presets for the log filter: (value, label). "" = no date limit.
DATE_PERIODS = (
    ("", "Any time"),
    ("today", "Today (since 00:00)"),
    ("yesterday", "Yesterday"),
    ("last7", "Last 7 days"),
    ("last_week", "Previous week (Mon–Sun)"),
    ("last30", "Last 30 days"),
    ("last_month", "Previous month"),
    ("custom", "Custom range…"),
)


def period_bounds(period: str, today: date | None = None) -> tuple[float, float | None] | None:
    """[start, end) epoch bounds of a date preset; end None = up to now.

    "Last N days" counts calendar days including today (from local 00:00 of
    the first day), so it lines up with "Today". Weeks start on Monday.
    """
    t = today or date.today()
    if period == "today":
        return day_start(t), None
    if period == "yesterday":
        return day_start(t - timedelta(days=1)), day_start(t)
    if period == "last7":
        return day_start(t - timedelta(days=6)), None
    if period == "last30":
        return day_start(t - timedelta(days=29)), None
    if period == "last_week":
        monday = t - timedelta(days=t.weekday())
        return day_start(monday - timedelta(days=7)), day_start(monday)
    if period == "last_month":
        first = t.replace(day=1)
        prev_first = (first - timedelta(days=1)).replace(day=1)
        return day_start(prev_first), day_start(first)
    return None


@dataclass
class LogFilter:
    q: str = ""            # free text: sender, recipient, queue id, message-id
    sender: str = ""
    recipient: str = ""
    ip: str = ""           # client IP (prefix match, e.g. "10.16.")
    status: str = ""
    relay: str = ""
    date_from: str = ""    # "YYYY-MM-DDTHH:MM" (datetime-local)
    date_to: str = ""
    period: str = ""       # one of DATE_PERIODS; "custom" uses date_from / date_to
    errors: list[str] = field(default_factory=list)
    range_label: str = ""  # human-readable resolved range of a preset

    def __post_init__(self) -> None:
        if self.period not in dict(DATE_PERIODS):
            self.period = ""
        # Old links (e.g. dashboard) pass only date_from / date_to.
        if not self.period and (self.date_from or self.date_to):
            self.period = "custom"
        if self.period != "custom":
            self.date_from = self.date_to = ""

    @staticmethod
    def _parse_dt(value: str) -> float | None:
        for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(value, fmt).timestamp()
            except ValueError:
                continue
        return None

    def where(self) -> tuple[str, list]:
        clauses, params = [], []
        if self.q:
            like = f"%{self.q}%"
            clauses.append("(d.recipient LIKE ? OR m.sender LIKE ? OR d.queue_id LIKE ? "
                           "OR m.message_id LIKE ? OR d.response LIKE ?)")
            params += [like] * 5
        if self.sender:
            clauses.append("m.sender LIKE ?")
            params.append(f"%{self.sender}%")
        if self.recipient:
            clauses.append("d.recipient LIKE ?")
            params.append(f"%{self.recipient}%")
        if self.ip:
            clauses.append("(m.client_ip LIKE ? OR m.client_host LIKE ?)")
            params += [f"{self.ip}%", f"%{self.ip}%"]
        if self.status in DELIVERY_STATUSES:
            clauses.append("d.status = ?")
            params.append(self.status)
        if self.relay:
            clauses.append("d.relay LIKE ?")
            params.append(f"%{self.relay}%")
        bounds = period_bounds(self.period)
        if bounds:
            start, end = bounds
            clauses.append("d.ts >= ?")
            params.append(start)
            if end is not None:
                clauses.append("d.ts < ?")
                params.append(end)
            fmt = "%Y-%m-%d %H:%M"
            self.range_label = (time.strftime(fmt, time.localtime(start)) + " → "
                                + (time.strftime(fmt, time.localtime(end - 1)) if end is not None else "now"))
        for value, op, label in ((self.date_from, ">=", "From"), (self.date_to, "<=", "To")):
            if value:
                ts = self._parse_dt(value)
                if ts is None:
                    self.errors.append(f"{label} date is not valid.")
                else:
                    clauses.append(f"d.ts {op} ?")
                    params.append(ts + (59.999 if op == "<=" and len(value) == 16 else 0))
        return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


def search_deliveries(db: Database, flt: LogFilter, page: int, page_size: int) -> tuple[list, int]:
    where, params = flt.where()
    total = db.query_one(
        "SELECT COUNT(*) AS n FROM deliveries d LEFT JOIN messages m ON m.id = d.msg_id" + where,
        params,
    )["n"]
    rows = db.query(
        _DELIVERY_SELECT + where + " ORDER BY d.ts DESC, d.id DESC LIMIT ? OFFSET ?",
        [*params, page_size, max(0, page - 1) * page_size],
    )
    return rows, total


def queue_meta(db: Database, queue_ids: list[str]) -> dict[str, dict]:
    """Client IP / host for messages currently in the queue."""
    if not queue_ids:
        return {}
    marks = ",".join("?" * len(queue_ids))
    rows = db.query(
        f"SELECT queue_id, client_ip, client_host, origin FROM messages "
        f"WHERE removed_at IS NULL AND queue_id IN ({marks})",
        queue_ids,
    )
    return {r["queue_id"]: dict(r) for r in rows}
