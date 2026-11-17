"""Turns single Postfix log lines into structured events.

parse(program, message) -> dict | None

`program` is the syslog identifier ("postfix/smtp", "postfix/qmgr", ...),
`message` the text after "program[pid]: ".
"""

from __future__ import annotations

import re

_QID = r"(?P<qid>[0-9A-Za-z]{6,20})"
_ADDR = r"<(?P<{name}>[^>]*)>"

RE_CLIENT = re.compile(rf"^{_QID}: client=(?P<host>[^\[\s]*)\[(?P<ip>[^\]]*)\]")
RE_PICKUP = re.compile(rf"^{_QID}: uid=(?P<uid>\d+) from={_ADDR.format(name='sender')}")
RE_MSGID = re.compile(rf"^{_QID}: (?:resent-)?message-id=<?(?P<mid>[^>\s]*)>?")
RE_QMGR_FROM = re.compile(
    rf"^{_QID}: from={_ADDR.format(name='sender')}, size=(?P<size>\d+), nrcpt=(?P<nrcpt>\d+)"
)
RE_EXPIRED = re.compile(rf"^{_QID}: from={_ADDR.format(name='sender')}, status=expired")
RE_DELIVERY = re.compile(
    rf"^{_QID}: to={_ADDR.format(name='to')}, "
    r"(?:orig_to=<(?P<orig>[^>]*)>, )?"
    r"relay=(?P<relay>[^,]+), "
    r"(?:conn_use=\d+, )?"
    r"delay=(?P<delay>[\d.]+), "
    r"delays=[^,]+, "
    r"dsn=(?P<dsn>[\d.]+), "
    r"status=(?P<status>\w+)"
    r"(?: \((?P<resp>.*)\))?$"
)
RE_REMOVED = re.compile(rf"^{_QID}: removed$")
RE_HOLD = re.compile(rf"^{_QID}: (?P<what>placed on hold|released from hold)")
RE_CLEANUP_HOLD = re.compile(rf"^{_QID}: hold: ")
RE_BOUNCE_NOTICE = re.compile(rf"^{_QID}: sender (?:non-delivery|delay|delivery status) notification: (?P<orig>\w+)")
RE_REJECT = re.compile(
    r"^NOQUEUE: reject: (?P<stage>[A-Z]+) from (?P<host>[^\[\s]*)\[(?P<ip>[^\]]*)\]: "
    r"(?P<code>\d{3})(?: [\d.]+)? (?P<reason>.*?); "
    r"from=<(?P<sender>[^>]*)> to=<(?P<to>[^>]*)>"
)


def _relay_host(relay: str) -> str:
    """'host.example[1.2.3.4]:25' -> 'host.example'"""
    return relay.split("[", 1)[0]


def parse(program: str, message: str) -> dict | None:
    parts = program.split("/")
    service = parts[-1]  # smtpd, qmgr, smtp, ...
    # "postfix/pfr_relay/smtp" -> transport "pfr_relay" (set via syslog_name in master.cf)
    transport = parts[1] if len(parts) >= 3 else service

    if service == "smtpd":
        m = RE_CLIENT.match(message)
        if m:
            return {"type": "client", "qid": m["qid"], "host": m["host"], "ip": m["ip"]}
        m = RE_REJECT.match(message)
        if m:
            return {"type": "reject", "host": m["host"], "ip": m["ip"], "code": m["code"],
                    "reason": m["reason"].strip(), "sender": m["sender"], "to": m["to"]}
        return None

    if service == "pickup":
        m = RE_PICKUP.match(message)
        if m:
            return {"type": "pickup", "qid": m["qid"], "uid": m["uid"], "sender": m["sender"]}
        return None

    if service == "cleanup":
        m = RE_MSGID.match(message)
        if m:
            return {"type": "msgid", "qid": m["qid"], "mid": m["mid"]}
        m = RE_CLEANUP_HOLD.match(message)
        if m:
            return {"type": "hold", "qid": m["qid"]}
        return None

    if service == "qmgr":
        m = RE_QMGR_FROM.match(message)
        if m:
            return {"type": "from", "qid": m["qid"], "sender": m["sender"],
                    "size": int(m["size"]), "nrcpt": int(m["nrcpt"])}
        m = RE_EXPIRED.match(message)
        if m:
            return {"type": "expired", "qid": m["qid"], "sender": m["sender"]}
        m = RE_REMOVED.match(message)
        if m:
            return {"type": "removed", "qid": m["qid"], "by": "qmgr"}
        return None

    if service == "postsuper":
        m = RE_REMOVED.match(message)
        if m:
            return {"type": "removed", "qid": m["qid"], "by": "postsuper"}
        m = RE_HOLD.match(message)
        if m:
            return {"type": "hold" if m["what"].startswith("placed") else "release", "qid": m["qid"]}
        return None

    if service == "bounce":
        m = RE_BOUNCE_NOTICE.match(message)
        if m:
            return {"type": "notice", "qid": m["qid"], "orig": m["orig"]}
        return None

    # Delivery agents: smtp, lmtp, local, virtual, pipe, discard, error, retry, relay ...
    m = RE_DELIVERY.match(message)
    if m:
        status = m["status"]
        if service == "discard" and status == "sent":
            status = "discarded"
        return {
            "type": "delivery", "qid": m["qid"], "to": m["to"], "orig": m["orig"] or "",
            "transport": transport, "relay": m["relay"], "relay_host": _relay_host(m["relay"]),
            "delay": float(m["delay"]), "dsn": m["dsn"], "status": status,
            "response": (m["resp"] or "").strip(),
        }
    return None
