"""Parser + store tests using anonymised Postfix log lines.

Run:  ./venv/bin/python -m pytest tests   (or: ./venv/bin/python tests/test_collector.py)
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pfhop.collector.parser import parse  # noqa: E402
from pfhop.collector.store import Store  # noqa: E402
from pfhop.db import Database  # noqa: E402

LINES = [
    ("postfix/smtpd", "1A2B3C4D5E: client=app01.example.com[192.0.2.10]"),
    ("postfix/cleanup", "1A2B3C4D5E: message-id=<abc@example.com>"),
    ("postfix/qmgr", "1A2B3C4D5E: from=<app@example.com>, size=2602, nrcpt=2 (queue active)"),
    ("postfix/smtp", "1A2B3C4D5E: to=<a@example.net>, relay=relay.example.org[198.51.100.5]:25, "
                     "delay=24, delays=0/0/24/0.07, dsn=4.3.2, status=deferred (host relay.example.org"
                     "[198.51.100.5] said: 451 4.3.2 Temporary server error (in reply to MAIL FROM command))"),
    ("postfix/smtp", "1A2B3C4D5E: to=<a@example.net>, relay=relay.example.org[198.51.100.5]:25, "
                     "delay=60, delays=30/0/1/0.1, dsn=2.6.0, status=sent (250 2.6.0 Queued mail for delivery)"),
    ("postfix/smtp", "1A2B3C4D5E: to=<b@example.net>, relay=relay.example.org[198.51.100.5]:25, "
                     "delay=61, delays=30/0/1/0.1, dsn=5.1.1, status=bounced (550 5.1.1 User unknown)"),
    ("postfix/qmgr", "1A2B3C4D5E: removed"),
    # second message: local pickup, deleted by admin
    ("postfix/pickup", "9F8E7D6C5B: uid=0 from=<root>"),
    ("postfix/qmgr", "9F8E7D6C5B: from=<root@example.com>, size=500, nrcpt=1 (queue active)"),
    ("postfix/postsuper", "9F8E7D6C5B: removed"),
    # discarded null-sender bounce
    ("postfix/smtpd", "AAAABBBBCC: client=_gateway[192.0.2.1]"),
    ("postfix/qmgr", "AAAABBBBCC: from=<>, size=6499, nrcpt=1 (queue active)"),
    ("postfix/discard", "AAAABBBBCC: to=<x@example.com>, relay=none, delay=0, delays=0/0/0/0, dsn=2.0.0, "
                        "status=sent ([relay.example.org]:25)"),
    ("postfix/qmgr", "AAAABBBBCC: removed"),
    # rejection
    ("postfix/smtpd", "NOQUEUE: reject: RCPT from unknown[203.0.113.9]: 454 4.7.1 <x@example.com>: "
                      "Relay access denied; from=<s@example.com> to=<x@example.com> proto=ESMTP helo=<h>"),
    # noise
    ("postfix/smtpd", "connect from unknown[203.0.113.9]"),
]


def test_parse_delivery():
    ev = parse(*LINES[4])
    assert ev["type"] == "delivery" and ev["status"] == "sent"
    assert ev["relay_host"] == "relay.example.org" and ev["delay"] == 60.0
    assert ev["response"].startswith("250 2.6.0")


def test_parse_reject_and_noise():
    ev = parse(*LINES[-2])
    assert ev["type"] == "reject" and ev["ip"] == "203.0.113.9"
    assert ev["reason"] == "<x@example.com>: Relay access denied"
    assert parse(*LINES[-1]) is None


def test_named_transport():
    ev = parse("postfix/pfr_ms365/smtp", LINES[4][1])
    assert ev["type"] == "delivery" and ev["transport"] == "pfr_ms365"


def test_store_lifecycle():
    with tempfile.TemporaryDirectory() as tmp:
        db = Database(Path(tmp) / "t.db")
        store = Store(db)
        for i, (prog, msg) in enumerate(LINES):
            ev = parse(prog, msg)
            if ev:
                store.apply(ev, 1000.0 + i)
        rows = {r["queue_id"]: dict(r) for r in db.query("SELECT * FROM messages")}
        assert rows["1A2B3C4D5E"]["final_status"] == "partial"
        assert rows["1A2B3C4D5E"]["client_ip"] == "192.0.2.10"
        assert rows["1A2B3C4D5E"]["sender"] == "app@example.com"
        assert rows["9F8E7D6C5B"]["final_status"] == "deleted"
        assert rows["AAAABBBBCC"]["final_status"] == "discarded"
        assert db.query_one("SELECT COUNT(*) n FROM deliveries")["n"] == 4
        assert db.query_one("SELECT COUNT(*) n FROM rejects")["n"] == 1
        assert not store.open


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
