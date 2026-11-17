"""SQLite storage: users, settings, audit log, backups, and mail log data."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 3

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('admin', 'viewer')),
    full_name     TEXT NOT NULL DEFAULT '',
    email         TEXT NOT NULL DEFAULT '',
    is_active     INTEGER NOT NULL DEFAULT 1,
    created_at    INTEGER NOT NULL,
    last_login    INTEGER
);

CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,          -- JSON encoded
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        INTEGER NOT NULL,
    username  TEXT NOT NULL,
    client_ip TEXT NOT NULL DEFAULT '',
    action    TEXT NOT NULL,
    target    TEXT NOT NULL DEFAULT '',
    details   TEXT NOT NULL DEFAULT '',
    success   INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);

CREATE TABLE IF NOT EXISTS backups (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind       TEXT NOT NULL CHECK (kind IN ('postfix', 'app')),
    filename   TEXT NOT NULL UNIQUE,
    size       INTEGER NOT NULL,
    sha256     TEXT NOT NULL,
    note       TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    created_by TEXT NOT NULL
);

-- One row per message that passed through Postfix (filled by the collector).
CREATE TABLE IF NOT EXISTS messages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    queue_id     TEXT NOT NULL,
    first_seen   REAL NOT NULL,
    client_host  TEXT NOT NULL DEFAULT '',
    client_ip    TEXT NOT NULL DEFAULT '',
    origin       TEXT NOT NULL DEFAULT '',     -- smtp | local | bounce
    sender       TEXT,
    size         INTEGER,
    nrcpt        INTEGER,
    message_id   TEXT NOT NULL DEFAULT '',
    removed_at   REAL,
    final_status TEXT NOT NULL DEFAULT ''      -- sent | partial | bounced | expired | deleted | discarded | unknown
);
CREATE INDEX IF NOT EXISTS idx_msg_qid ON messages(queue_id, removed_at);
CREATE INDEX IF NOT EXISTS idx_msg_first ON messages(first_seen);
CREATE INDEX IF NOT EXISTS idx_msg_sender ON messages(sender, first_seen);

-- One row per delivery attempt / result line (to=<...>, status=...).
CREATE TABLE IF NOT EXISTS deliveries (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL NOT NULL,
    msg_id    INTEGER,
    queue_id  TEXT NOT NULL,
    recipient TEXT NOT NULL DEFAULT '',
    orig_to   TEXT NOT NULL DEFAULT '',
    transport TEXT NOT NULL DEFAULT '',
    relay     TEXT NOT NULL DEFAULT '',
    delay     REAL,
    dsn       TEXT NOT NULL DEFAULT '',
    status    TEXT NOT NULL,                   -- sent | deferred | bounced | expired | discarded
    response  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_dlv_ts ON deliveries(ts);
CREATE INDEX IF NOT EXISTS idx_dlv_status ON deliveries(status, ts);
CREATE INDEX IF NOT EXISTS idx_dlv_msg ON deliveries(msg_id);
CREATE INDEX IF NOT EXISTS idx_dlv_rcpt ON deliveries(recipient);

-- SMTP-time rejections (never entered the queue), e.g. "Relay access denied".
CREATE TABLE IF NOT EXISTS rejects (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    client_host TEXT NOT NULL DEFAULT '',
    client_ip   TEXT NOT NULL DEFAULT '',
    sender      TEXT NOT NULL DEFAULT '',
    recipient   TEXT NOT NULL DEFAULT '',
    code        TEXT NOT NULL DEFAULT '',
    reason      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_rej_ts ON rejects(ts);

-- Relay servers managed by pfhop (source of truth for Postfix routing).
CREATE TABLE IF NOT EXISTS relays (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    slug        TEXT NOT NULL UNIQUE,              -- transport name is pfr_<slug>
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'smtp' CHECK (kind IN ('smtp', 'direct', 'discard')),
    host        TEXT NOT NULL DEFAULT '',
    port        INTEGER NOT NULL DEFAULT 25,
    mx_lookup   INTEGER NOT NULL DEFAULT 0,
    tls_level   TEXT NOT NULL DEFAULT 'may',
    auth_user   TEXT NOT NULL DEFAULT '',
    auth_pass   TEXT NOT NULL DEFAULT '',
    concurrency INTEGER,                           -- NULL = global default
    rate_delay  TEXT NOT NULL DEFAULT '',          -- '' = global default
    is_default  INTEGER NOT NULL DEFAULT 0,
    description TEXT NOT NULL DEFAULT '',
    updated_at  INTEGER NOT NULL
);

-- Who uses which relay: sender address, sender domain or client network.
CREATE TABLE IF NOT EXISTS relay_rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    relay_id    INTEGER NOT NULL REFERENCES relays(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL CHECK (kind IN ('sender', 'domain', 'client')),
    value       TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    UNIQUE (kind, value)
);

-- Allowed (trusted) client networks = Postfix mynetworks, with descriptions.
CREATE TABLE IF NOT EXISTS clients (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    network     TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL
);
"""

# Runtime settings with their defaults. Admins edit these in the UI.
DEFAULT_SETTINGS: dict[str, Any] = {
    "general.title": "PostFix Hop Manager",
    "general.dashboard_refresh_seconds": 5,
    "general.queue_age_warn_minutes": 30,
    "general.queue_age_crit_minutes": 120,
    "general.disk_warn_percent": 80,
    "general.disk_crit_percent": 90,
    "audit.enabled": True,
    "dashboard.queue_rows": 20,
    "dashboard.recent_rows": 20,
    "logs.page_size": 50,
    "logs.retention_days": 90,
    "backup.auto_enabled": True,
    "backup.auto_time": "00:30",
    "backup.auto_keep": 5,
    "mail.system_sender": "",
    "mail.system_sender_name": "PostFix Hop Manager",
    "mail.test_recipient": "",
}


class Database:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_schema()

    def conn(self) -> sqlite3.Connection:
        c = getattr(self._local, "conn", None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=10, isolation_level=None)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA foreign_keys=ON")
            c.execute("PRAGMA busy_timeout=10000")
            self._local.conn = c
        return c

    def _init_schema(self) -> None:
        c = self.conn()
        self._migrate(c)
        c.executescript(SCHEMA)
        c.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )

    @staticmethod
    def _migrate(c: sqlite3.Connection) -> None:
        """Schema upgrades that CREATE TABLE IF NOT EXISTS cannot do."""
        row = c.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'relays'").fetchone()
        if row and "'direct'" not in row[0]:
            # v3: allow kind = 'direct'. SQLite cannot alter a CHECK constraint -> rebuild the table
            # (foreign keys off so relay_rules rows are kept).
            c.execute("PRAGMA foreign_keys=OFF")
            c.executescript("""
                BEGIN;
                CREATE TABLE relays_new (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    slug        TEXT NOT NULL UNIQUE,
                    name        TEXT NOT NULL,
                    kind        TEXT NOT NULL DEFAULT 'smtp' CHECK (kind IN ('smtp', 'direct', 'discard')),
                    host        TEXT NOT NULL DEFAULT '',
                    port        INTEGER NOT NULL DEFAULT 25,
                    mx_lookup   INTEGER NOT NULL DEFAULT 0,
                    tls_level   TEXT NOT NULL DEFAULT 'may',
                    auth_user   TEXT NOT NULL DEFAULT '',
                    auth_pass   TEXT NOT NULL DEFAULT '',
                    concurrency INTEGER,
                    rate_delay  TEXT NOT NULL DEFAULT '',
                    is_default  INTEGER NOT NULL DEFAULT 0,
                    description TEXT NOT NULL DEFAULT '',
                    updated_at  INTEGER NOT NULL
                );
                INSERT INTO relays_new SELECT * FROM relays;
                DROP TABLE relays;
                ALTER TABLE relays_new RENAME TO relays;
                COMMIT;
            """)
            c.execute("PRAGMA foreign_keys=ON")

    # -- helpers -----------------------------------------------------------
    def query(self, sql: str, params: tuple | dict = ()) -> list[sqlite3.Row]:
        return self.conn().execute(sql, params).fetchall()

    def query_one(self, sql: str, params: tuple | dict = ()) -> sqlite3.Row | None:
        return self.conn().execute(sql, params).fetchone()

    def execute(self, sql: str, params: tuple | dict = ()) -> sqlite3.Cursor:
        return self.conn().execute(sql, params)

    # -- settings ----------------------------------------------------------
    def get_setting(self, key: str) -> Any:
        row = self.query_one("SELECT value FROM settings WHERE key = ?", (key,))
        if row is None:
            return DEFAULT_SETTINGS.get(key)
        return json.loads(row["value"])

    def all_settings(self) -> dict[str, Any]:
        values = dict(DEFAULT_SETTINGS)
        for row in self.query("SELECT key, value FROM settings"):
            values[row["key"]] = json.loads(row["value"])
        return values

    def set_setting(self, key: str, value: Any, username: str) -> None:
        self.execute(
            "INSERT INTO settings(key, value, updated_at, updated_by) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
            "updated_at = excluded.updated_at, updated_by = excluded.updated_by",
            (key, json.dumps(value), int(time.time()), username),
        )

    # -- audit -------------------------------------------------------------
    def audit(
        self,
        username: str,
        action: str,
        target: str = "",
        details: str = "",
        client_ip: str = "",
        success: bool = True,
        force: bool = False,
    ) -> None:
        """Write an audit entry unless auditing is disabled in settings.

        `force=True` records the entry regardless (used to log that auditing
        itself was switched off).
        """
        if not force and not self.get_setting("audit.enabled"):
            return
        self.execute(
            "INSERT INTO audit_log(ts, username, client_ip, action, target, details, success) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (int(time.time()), username, client_ip, action, target, details, int(success)),
        )
