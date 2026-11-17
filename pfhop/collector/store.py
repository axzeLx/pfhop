"""Applies parsed log events to the database.

A Postfix queue ID is only unique while the message is in the queue, so each
"life" of a queue ID gets its own row in `messages`. Open (not yet removed)
rows are cached in memory by queue ID.
"""

from __future__ import annotations

import time

from ..db import Database

OK_STATUSES = {"sent", "discarded"}


class Store:
    def __init__(self, db: Database):
        self.db = db
        self.open: dict[str, int] = {}
        for row in db.query("SELECT id, queue_id FROM messages WHERE removed_at IS NULL"):
            self.open[row["queue_id"]] = row["id"]

    # -- message rows ------------------------------------------------------
    def _new(self, qid: str, ts: float, **fields) -> int:
        old = self.open.pop(qid, None)
        if old is not None:
            # A new message re-uses a queue ID whose removal we never saw.
            self.db.execute(
                "UPDATE messages SET removed_at = ?, final_status = 'unknown' WHERE id = ?", (ts, old)
            )
        cols = ["queue_id", "first_seen", *fields.keys()]
        vals = [qid, ts, *fields.values()]
        cur = self.db.execute(
            f"INSERT INTO messages({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})", vals
        )
        self.open[qid] = cur.lastrowid
        return cur.lastrowid

    def _get(self, qid: str, ts: float) -> int:
        mid = self.open.get(qid)
        if mid is None:
            mid = self._new(qid, ts)
        return mid

    def _final_status(self, msg_id: int) -> str:
        row = self.db.query_one("SELECT final_status FROM messages WHERE id = ?", (msg_id,))
        if row and row["final_status"] in ("expired", "deleted"):
            return row["final_status"]
        # Last status per recipient.
        rows = self.db.query(
            "SELECT recipient, status FROM deliveries WHERE msg_id = ? AND status != 'expired' "
            "ORDER BY id", (msg_id,)
        )
        last: dict[str, str] = {}
        for r in rows:
            last[r["recipient"]] = r["status"]
        if not last:
            return "unknown"
        statuses = set(last.values())
        if statuses <= {"discarded"}:
            return "discarded"
        if statuses <= OK_STATUSES:
            return "sent"
        if "bounced" in statuses and statuses & OK_STATUSES:
            return "partial"
        if statuses <= {"bounced"}:
            return "bounced"
        return "partial" if statuses & OK_STATUSES else "bounced"

    # -- event dispatch ----------------------------------------------------
    def apply(self, ev: dict, ts: float) -> None:
        t = ev["type"]
        if t == "client":
            self._new(ev["qid"], ts, client_host=ev["host"], client_ip=ev["ip"], origin="smtp")
        elif t == "pickup":
            self._new(ev["qid"], ts, client_host=f"local (uid {ev['uid']})", origin="local",
                      sender=ev["sender"])
        elif t == "msgid":
            mid = self._get(ev["qid"], ts)
            self.db.execute("UPDATE messages SET message_id = ? WHERE id = ?", (ev["mid"][:250], mid))
        elif t == "from":
            mid = self._get(ev["qid"], ts)
            self.db.execute(
                "UPDATE messages SET sender = ?, size = ?, nrcpt = ? WHERE id = ?",
                (ev["sender"], ev["size"], ev["nrcpt"], mid),
            )
        elif t == "notice":
            mid = self._get(ev["qid"], ts)
            self.db.execute(
                "UPDATE messages SET origin = 'bounce', client_host = ? WHERE id = ?",
                (f"bounce of {ev['orig']}", mid),
            )
        elif t == "delivery":
            mid = self._get(ev["qid"], ts)
            self.db.execute(
                "INSERT INTO deliveries(ts, msg_id, queue_id, recipient, orig_to, transport, relay, "
                "delay, dsn, status, response) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (ts, mid, ev["qid"], ev["to"], ev["orig"], ev["transport"], ev["relay"],
                 ev["delay"], ev["dsn"], ev["status"], ev["response"][:1000]),
            )
        elif t == "expired":
            mid = self._get(ev["qid"], ts)
            self.db.execute("UPDATE messages SET final_status = 'expired' WHERE id = ?", (mid,))
            self.db.execute(
                "INSERT INTO deliveries(ts, msg_id, queue_id, status, response) "
                "VALUES (?, ?, ?, 'expired', 'message expired, returned to sender')",
                (ts, mid, ev["qid"]),
            )
        elif t == "removed":
            mid = self.open.pop(ev["qid"], None)
            if mid is None:
                return
            if ev["by"] == "postsuper":
                self.db.execute("UPDATE messages SET final_status = 'deleted' WHERE id = ?", (mid,))
            self.db.execute(
                "UPDATE messages SET removed_at = ?, final_status = ? WHERE id = ?",
                (ts, self._final_status(mid), mid),
            )
        elif t == "reject":
            self.db.execute(
                "INSERT INTO rejects(ts, client_host, client_ip, sender, recipient, code, reason) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (ts, ev["host"], ev["ip"], ev["sender"], ev["to"], ev["code"], ev["reason"][:500]),
            )
        # hold / release need no storage: the live queue shows the hold state.

    # -- housekeeping ------------------------------------------------------
    def purge(self, retention_days: int) -> None:
        cutoff = time.time() - retention_days * 86400
        self.db.execute("DELETE FROM deliveries WHERE ts < ?", (cutoff,))
        self.db.execute("DELETE FROM rejects WHERE ts < ?", (cutoff,))
        self.db.execute(
            "DELETE FROM messages WHERE first_seen < ? AND removed_at IS NOT NULL", (cutoff,)
        )
