"""Minimal MX lookup (stdlib only) for the direct-delivery relay test.

Sends one DNS query over UDP to the resolvers in /etc/resolv.conf.
"""

from __future__ import annotations

import random
import socket
import struct

TYPE_MX = 15


class DNSError(Exception):
    pass


def _nameservers() -> list[str]:
    servers = []
    try:
        with open("/etc/resolv.conf") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    servers.append(parts[1])
    except OSError:
        pass
    return servers or ["127.0.0.1"]


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna")
        if not 0 < len(raw) < 64:
            raise DNSError(f"invalid domain name: {name}")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _read_name(msg: bytes, pos: int) -> tuple[str, int]:
    labels, jumped, end = [], False, pos
    for _ in range(128):
        length = msg[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            ptr = struct.unpack("!H", msg[pos:pos + 2])[0] & 0x3FFF
            if not jumped:
                end = pos + 2
            pos, jumped = ptr, True
            continue
        labels.append(msg[pos + 1:pos + 1 + length].decode("ascii", "replace"))
        pos += 1 + length
    return ".".join(labels), (end if jumped else pos)


def lookup_mx(domain: str, timeout: float = 5.0) -> list[tuple[int, str]]:
    """Return [(preference, host)] sorted by preference. [] = no MX records.

    A null MX ("0 .") is returned as [(0, "")].
    """
    qid = random.randint(0, 0xFFFF)
    query = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + _encode_name(domain) + struct.pack("!HH", TYPE_MX, 1)
    last_error = "no answer"
    for server in _nameservers():
        family = socket.AF_INET6 if ":" in server else socket.AF_INET
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(query, (server, 53))
                msg, _ = sock.recvfrom(4096)
        except OSError as exc:
            last_error = f"{server}: {exc}"
            continue
        rid, flags, qd, an, _, _ = struct.unpack("!HHHHHH", msg[:12])
        if rid != qid:
            continue
        rcode = flags & 0x000F
        if rcode == 3:
            raise DNSError(f"{domain}: domain does not exist (NXDOMAIN)")
        if rcode != 0:
            last_error = f"{server}: DNS error code {rcode}"
            continue
        pos = 12
        for _ in range(qd):
            _, pos = _read_name(msg, pos)
            pos += 4
        records = []
        for _ in range(an):
            _, pos = _read_name(msg, pos)
            rtype, _, _, rdlen = struct.unpack("!HHIH", msg[pos:pos + 10])
            pos += 10
            if rtype == TYPE_MX:
                pref = struct.unpack("!H", msg[pos:pos + 2])[0]
                host, _ = _read_name(msg, pos + 2)
                records.append((pref, host))
            pos += rdlen
        return sorted(records)
    raise DNSError(last_error)
