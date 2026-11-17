"""Command line: run the server and manage users from the shell.

  pfhop serve
  pfhop collect
  pfhop useradd <username> [--role admin|viewer]
  pfhop passwd <username>
  pfhop users
"""

from __future__ import annotations

import argparse
import getpass
import sys

from . import __version__
from . import auth as authmod
from .config import load_config
from .db import Database


def _db() -> Database:
    return Database(load_config().db_path)


def _ask_password() -> str:
    while True:
        pw = getpass.getpass("Password: ")
        if pw != getpass.getpass("Repeat password: "):
            print("Passwords do not match.", file=sys.stderr)
            continue
        try:
            authmod.validate_password(pw)
        except authmod.UserError as exc:
            print(exc, file=sys.stderr)
            continue
        return pw


def cmd_serve(args) -> int:
    import uvicorn

    from .web.app import create_app

    cfg = load_config()
    uvicorn.run(
        create_app(cfg),
        host=args.host or cfg.host,
        port=args.port or cfg.port,
        proxy_headers=False,
        server_header=False,
        log_level="info",
    )
    return 0


def cmd_collect(args) -> int:
    from .collector.run import main as collector_main

    return collector_main()


def cmd_backup(args) -> int:
    from . import backup as backupmod

    cfg = load_config()
    db = Database(cfg.db_path)
    if args.auto:
        lines = backupmod.run_scheduled(cfg, db)
    else:
        lines = backupmod.run_scheduled(cfg, db, force=True)
    for line in lines:
        print(line)
    return 1 if any("FAILED" in line for line in lines) else 0


def cmd_useradd(args) -> int:
    db = _db()
    try:
        user = authmod.create_user(db, args.username, _ask_password(), args.role,
                                   args.full_name or "", args.email or "")
    except authmod.UserError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    db.audit("cli", "user.create", user.username, f"role={user.role}")
    print(f"Created {user.role} '{user.username}'.")
    return 0


def cmd_passwd(args) -> int:
    db = _db()
    row = db.query_one("SELECT id FROM users WHERE username = ?", (args.username,))
    if row is None:
        print(f"error: no such user '{args.username}'", file=sys.stderr)
        return 1
    authmod.set_password(db, row["id"], _ask_password())
    db.audit("cli", "user.password_reset", args.username)
    print("Password updated.")
    return 0


def cmd_users(args) -> int:
    for u in authmod.list_users(_db()):
        state = "active" if u.is_active else "disabled"
        print(f"{u.username:24} {u.role:7} {state}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="pfhop", description="Postfix relay management panel")
    p.add_argument("--version", action="version", version=f"pfhop {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the web server")
    s.add_argument("--host")
    s.add_argument("--port", type=int)
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("collect", help="run the mail log collector (journal follower)")
    s.set_defaults(func=cmd_collect)

    s = sub.add_parser("backup", help="back up Postfix + pfhop settings now (or --auto: scheduled run)")
    s.add_argument("--auto", action="store_true", help="only run if the daily backup is due")
    s.set_defaults(func=cmd_backup)

    s = sub.add_parser("useradd", help="create a user")
    s.add_argument("username")
    s.add_argument("--role", choices=authmod.ROLES, default="viewer")
    s.add_argument("--full-name")
    s.add_argument("--email")
    s.set_defaults(func=cmd_useradd)

    s = sub.add_parser("passwd", help="set a user's password")
    s.add_argument("username")
    s.set_defaults(func=cmd_passwd)

    s = sub.add_parser("users", help="list users")
    s.set_defaults(func=cmd_users)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
