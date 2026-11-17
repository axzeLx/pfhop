"""pfhop collector: follows Postfix messages in the systemd journal.

Runs as the `pfhop` user (member of `systemd-journal`). The journal cursor is
stored in the database in the same transaction as the parsed data, so after a
restart it continues exactly where it stopped - no duplicates, no gaps.
"""

from __future__ import annotations

import json
import logging
import queue
import signal
import subprocess
import threading
import time

from ..config import load_config
from ..db import Database
from .parser import parse
from .store import Store

log = logging.getLogger("pfhop.collector")

JOURNALCTL = "/usr/bin/journalctl"
BATCH_LINES = 1000
BATCH_SECONDS = 1.0
PURGE_INTERVAL = 3600

_stop = threading.Event()


def _message_text(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):  # non-UTF-8 payloads come as byte arrays
        return bytes(value).decode("utf-8", errors="replace")
    return ""


def _reader(proc: subprocess.Popen, out: queue.Queue) -> None:
    for line in proc.stdout:
        out.put(line)
    out.put(None)


def follow(db: Database) -> None:
    store = Store(db)
    cursor_row = db.query_one("SELECT value FROM meta WHERE key = 'journal_cursor'")
    cmd = [JOURNALCTL, "--follow", "--output=json", "--no-pager", "--quiet",
           "--output-fields=MESSAGE,SYSLOG_IDENTIFIER", "SYSLOG_FACILITY=2"]
    if cursor_row:
        cmd.append(f"--after-cursor={cursor_row['value']}")
        log.info("resuming after saved journal cursor")
    else:
        cmd.append("--lines=all")
        log.info("no cursor saved - importing everything still in the journal")

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            encoding="utf-8", errors="replace", bufsize=1)
    lines: queue.Queue = queue.Queue(maxsize=20000)
    threading.Thread(target=_reader, args=(proc, lines), daemon=True).start()

    last_purge = 0.0
    total = 0
    try:
        while not _stop.is_set():
            batch: list[str] = []
            deadline = time.monotonic() + BATCH_SECONDS
            eof = False
            while len(batch) < BATCH_LINES:
                try:
                    item = lines.get(timeout=max(0.05, deadline - time.monotonic()))
                except queue.Empty:
                    break
                if item is None:
                    eof = True
                    break
                batch.append(item)
                if time.monotonic() >= deadline:
                    break

            if batch:
                cursor = None
                db.execute("BEGIN IMMEDIATE")
                try:
                    for raw in batch:
                        try:
                            entry = json.loads(raw)
                        except json.JSONDecodeError:
                            continue
                        cursor = entry.get("__CURSOR", cursor)
                        program = entry.get("SYSLOG_IDENTIFIER", "")
                        if not program.startswith("postfix"):
                            continue
                        ev = parse(program, _message_text(entry.get("MESSAGE")))
                        if ev is None:
                            continue
                        ts = int(entry.get("__REALTIME_TIMESTAMP", 0)) / 1_000_000 or time.time()
                        store.apply(ev, ts)
                    if cursor:
                        db.execute(
                            "INSERT OR REPLACE INTO meta(key, value) VALUES ('journal_cursor', ?)",
                            (cursor,),
                        )
                        db.execute(
                            "INSERT OR REPLACE INTO meta(key, value) VALUES ('collector_heartbeat', ?)",
                            (str(int(time.time())),),
                        )
                    db.execute("COMMIT")
                except Exception:
                    db.execute("ROLLBACK")
                    raise
                total += len(batch)
                if total and total % 50000 < len(batch):
                    log.info("processed %d journal entries", total)
            else:
                db.execute(
                    "INSERT OR REPLACE INTO meta(key, value) VALUES ('collector_heartbeat', ?)",
                    (str(int(time.time())),),
                )

            if time.time() - last_purge > PURGE_INTERVAL:
                store.purge(int(db.get_setting("logs.retention_days")))
                last_purge = time.time()

            if eof:
                if _stop.is_set():
                    break
                err = proc.stderr.read() if proc.stderr else ""
                raise RuntimeError(f"journalctl exited ({proc.wait()}): {err.strip()}")
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    signal.signal(signal.SIGTERM, lambda *_: _stop.set())
    signal.signal(signal.SIGINT, lambda *_: _stop.set())
    db = Database(load_config().db_path)
    while not _stop.is_set():
        try:
            follow(db)
        except Exception as exc:  # keep running; systemd also restarts us
            log.error("collector error: %s - restarting in 5s", exc)
            _stop.wait(5)
    log.info("collector stopped")
    return 0
