"""Password hashing (stdlib scrypt), user management, login throttling."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import threading
import time
from dataclasses import dataclass

from .db import Database

# scrypt parameters (n=2**15, r=8, p=1 => ~32 MiB, ~50-100ms per hash)
_N, _R, _P = 2**15, 8, 1
_MAXMEM = 64 * 1024 * 1024

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,32}$")
MIN_PASSWORD_LEN = 10
ROLES = ("admin", "viewer")


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, maxmem=_MAXMEM, dklen=32)
    b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
    return f"scrypt${_N}${_R}${_P}${b64(salt)}${b64(dk)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt_b64, dk_b64 = stored.split("$")
        if algo != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        dk = hashlib.scrypt(
            password.encode(), salt=salt, n=int(n), r=int(r), p=int(p),
            maxmem=_MAXMEM, dklen=len(expected),
        )
        return hmac.compare_digest(dk, expected)
    except (ValueError, TypeError):
        return False


# A pre-computed hash used to keep timing similar when the user doesn't exist.
_DUMMY_HASH = hash_password(secrets.token_hex(8))


@dataclass
class User:
    id: int
    username: str
    role: str
    full_name: str
    email: str
    is_active: bool
    last_login: int | None

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


def _row_to_user(row) -> User:
    return User(
        id=row["id"], username=row["username"], role=row["role"],
        full_name=row["full_name"], email=row["email"],
        is_active=bool(row["is_active"]), last_login=row["last_login"],
    )


class UserError(ValueError):
    pass


def validate_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LEN:
        raise UserError(f"Password must be at least {MIN_PASSWORD_LEN} characters.")


def get_user(db: Database, user_id: int) -> User | None:
    row = db.query_one("SELECT * FROM users WHERE id = ?", (user_id,))
    return _row_to_user(row) if row else None


def list_users(db: Database) -> list[User]:
    return [_row_to_user(r) for r in db.query("SELECT * FROM users ORDER BY username")]


def count_admins(db: Database) -> int:
    row = db.query_one("SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND is_active = 1")
    return row["n"]


def create_user(db: Database, username: str, password: str, role: str,
                full_name: str = "", email: str = "") -> User:
    username = username.strip()
    if not USERNAME_RE.match(username):
        raise UserError("Username must be 3-32 characters: letters, digits, '.', '_' or '-'.")
    if role not in ROLES:
        raise UserError("Invalid role.")
    validate_password(password)
    if db.query_one("SELECT 1 FROM users WHERE username = ?", (username,)):
        raise UserError(f"User '{username}' already exists.")
    cur = db.execute(
        "INSERT INTO users(username, password_hash, role, full_name, email, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (username, hash_password(password), role, full_name.strip(), email.strip(), int(time.time())),
    )
    return get_user(db, cur.lastrowid)


def set_password(db: Database, user_id: int, password: str) -> None:
    validate_password(password)
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(password), user_id))


def update_user(db: Database, user_id: int, role: str, is_active: bool,
                full_name: str, email: str) -> None:
    if role not in ROLES:
        raise UserError("Invalid role.")
    user = get_user(db, user_id)
    if user is None:
        raise UserError("User not found.")
    losing_admin = user.is_admin and user.is_active and (role != "admin" or not is_active)
    if losing_admin and count_admins(db) <= 1:
        raise UserError("At least one active admin must remain.")
    db.execute(
        "UPDATE users SET role = ?, is_active = ?, full_name = ?, email = ? WHERE id = ?",
        (role, int(is_active), full_name.strip(), email.strip(), user_id),
    )


def delete_user(db: Database, user_id: int) -> None:
    user = get_user(db, user_id)
    if user is None:
        raise UserError("User not found.")
    if user.is_admin and user.is_active and count_admins(db) <= 1:
        raise UserError("At least one active admin must remain.")
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))


def authenticate(db: Database, username: str, password: str) -> User | None:
    row = db.query_one("SELECT * FROM users WHERE username = ?", (username.strip(),))
    if row is None:
        verify_password(password, _DUMMY_HASH)
        return None
    if not verify_password(password, row["password_hash"]) or not row["is_active"]:
        return None
    db.execute("UPDATE users SET last_login = ? WHERE id = ?", (int(time.time()), row["id"]))
    return _row_to_user(row)


class LoginThrottle:
    """In-memory brute-force protection: N failures per IP => lock for a while."""

    def __init__(self, max_failures: int = 5, window: int = 300, lockout: int = 300):
        self.max_failures = max_failures
        self.window = window
        self.lockout = lockout
        self._failures: dict[str, list[float]] = {}
        self._locked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def locked_for(self, ip: str) -> int:
        with self._lock:
            until = self._locked_until.get(ip, 0)
            return max(0, int(until - time.time()))

    def failure(self, ip: str) -> None:
        now = time.time()
        with self._lock:
            hits = [t for t in self._failures.get(ip, []) if now - t < self.window]
            hits.append(now)
            self._failures[ip] = hits
            if len(hits) >= self.max_failures:
                self._locked_until[ip] = now + self.lockout
                self._failures[ip] = []

    def success(self, ip: str) -> None:
        with self._lock:
            self._failures.pop(ip, None)
            self._locked_until.pop(ip, None)
