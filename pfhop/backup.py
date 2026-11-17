"""Manual backups: Postfix configuration (.tar.gz) and pfhop settings (.json)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import time
from datetime import datetime
from pathlib import Path

from . import __version__
from .config import Config
from .db import Database
from .postfix.commands import run_helper

FILENAME_RE = re.compile(r"^pfhop-(postfix|app)-\d{8}-\d{6}(-\d+)?\.(tar\.gz|json)$")


class BackupError(RuntimeError):
    pass


def _target_path(cfg: Config, kind: str, ext: str) -> Path:
    cfg.backup_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(cfg.backup_dir, 0o700)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    path = cfg.backup_dir / f"pfhop-{kind}-{stamp}.{ext}"
    n = 1
    while path.exists():
        path = cfg.backup_dir / f"pfhop-{kind}-{stamp}-{n}.{ext}"
        n += 1
    return path


def _store(cfg: Config, db: Database, kind: str, ext: str, data: bytes, note: str, username: str) -> dict:
    path = _target_path(cfg, kind, ext)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    sha = hashlib.sha256(data).hexdigest()
    db.execute(
        "INSERT INTO backups(kind, filename, size, sha256, note, created_at, created_by) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (kind, path.name, len(data), sha, note.strip()[:200], int(time.time()), username),
    )
    return {"filename": path.name, "size": len(data), "sha256": sha}


def create_postfix_backup(cfg: Config, db: Database, note: str, username: str) -> dict:
    data = run_helper(cfg, "backup-postfix")
    if len(data) < 100 or data[:2] != b"\x1f\x8b":
        raise BackupError("pfhop-helper did not return a valid gzip archive.")
    return _store(cfg, db, "postfix", "tar.gz", data, note, username)


def export_app_config(db: Database) -> dict:
    users = [
        {
            "username": r["username"], "role": r["role"], "full_name": r["full_name"],
            "email": r["email"], "is_active": bool(r["is_active"]),
            "password_hash": r["password_hash"],
        }
        for r in db.query("SELECT * FROM users ORDER BY username")
    ]
    settings = {r["key"]: json.loads(r["value"]) for r in db.query("SELECT key, value FROM settings ORDER BY key")}
    return {
        "type": "pfhop-app-config",
        "format": 1,
        "pfhop_version": __version__,
        "created_at": int(time.time()),
        "hostname": socket.gethostname(),
        "settings": settings,
        "users": users,
    }


def create_app_backup(cfg: Config, db: Database, note: str, username: str) -> dict:
    data = json.dumps(export_app_config(db), indent=2, ensure_ascii=False).encode()
    return _store(cfg, db, "app", "json", data, note, username)


def list_backups(db: Database, kind: str) -> list:
    return db.query("SELECT * FROM backups WHERE kind = ? ORDER BY created_at DESC, id DESC", (kind,))


def backup_file(cfg: Config, db: Database, backup_id: int) -> tuple[dict, Path]:
    row = db.query_one("SELECT * FROM backups WHERE id = ?", (backup_id,))
    if row is None or not FILENAME_RE.match(row["filename"]):
        raise BackupError("Backup not found.")
    path = cfg.backup_dir / row["filename"]
    if not path.is_file():
        raise BackupError("Backup file is missing on disk.")
    return dict(row), path


def delete_backup(cfg: Config, db: Database, backup_id: int) -> dict:
    row = db.query_one("SELECT * FROM backups WHERE id = ?", (backup_id,))
    if row is None or not FILENAME_RE.match(row["filename"]):
        raise BackupError("Backup not found.")
    (cfg.backup_dir / row["filename"]).unlink(missing_ok=True)
    db.execute("DELETE FROM backups WHERE id = ?", (backup_id,))
    return dict(row)


# -- automatic (scheduled) backups -------------------------------------------
AUTO_USER = "scheduler"
AUTO_NOTE = "automatic daily backup"


def prune_auto_backups(cfg: Config, db: Database, keep: int) -> list[str]:
    """Delete automatic backups beyond the newest `keep` per kind. Manual backups are never touched."""
    removed = []
    for kind in ("postfix", "app"):
        rows = db.query(
            "SELECT id, filename FROM backups WHERE kind = ? AND created_by = ? "
            "ORDER BY created_at DESC, id DESC",
            (kind, AUTO_USER),
        )
        for row in rows[keep:]:
            delete_backup(cfg, db, row["id"])
            removed.append(row["filename"])
    return removed


def scheduled_time_today(hhmm: str) -> float:
    hour, minute = (int(x) for x in hhmm.split(":"))
    return datetime.now().replace(hour=hour, minute=minute, second=0, microsecond=0).timestamp()


def run_scheduled(cfg: Config, db: Database, force: bool = False) -> list[str]:
    """Called every few minutes by pfhop-backup.timer.

    Takes both backups once per day, after the configured time, then prunes.
    Returns log lines describing what happened.
    """
    log: list[str] = []
    if not force and not db.get_setting("backup.auto_enabled"):
        return ["automatic backups are disabled"]
    due = scheduled_time_today(db.get_setting("backup.auto_time"))
    if not force:
        if time.time() < due:
            return ["not due yet"]
        done = db.query_one(
            "SELECT COUNT(DISTINCT kind) AS n FROM backups WHERE created_by = ? AND created_at >= ?",
            (AUTO_USER, int(due)),
        )["n"]
        if done >= 2:
            return ["already done today"]
    for kind, func in (("postfix", create_postfix_backup), ("app", create_app_backup)):
        if not force and db.query_one(
            "SELECT 1 FROM backups WHERE kind = ? AND created_by = ? AND created_at >= ?",
            (kind, AUTO_USER, int(due)),
        ):
            continue
        try:
            info = func(cfg, db, AUTO_NOTE, AUTO_USER)
            db.audit(AUTO_USER, f"backup.{kind}.create", info["filename"], f"{info['size']} bytes")
            log.append(f"created {info['filename']}")
        except Exception as exc:  # noqa: BLE001 - log and continue with the other kind
            db.audit(AUTO_USER, f"backup.{kind}.create", details=str(exc), success=False)
            log.append(f"{kind} backup FAILED: {exc}")
    for name in prune_auto_backups(cfg, db, int(db.get_setting("backup.auto_keep"))):
        db.audit(AUTO_USER, "backup.prune", name)
        log.append(f"pruned {name}")
    return log
