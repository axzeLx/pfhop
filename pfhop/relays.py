"""Relay servers and who uses them -> Postfix routing configuration.

pfhop owns the Postfix routing once the first change is applied:

  relayhost                               (empty - the next hop lives in default_transport)
  default_transport                       pfr_<default slug>:[host]:port   (or pfr_<slug> for direct delivery)
  sender_dependent_default_transport_maps lmdb:<conf>/pfhop/sender_relay   (sender / @domain rules)
  smtpd_client_restrictions               check_client_access cidr:<conf>/pfhop/client_relay.cidr
                                          (client IP rules, via FILTER)
  mynetworks                              Allowed clients
  master.cf                               one "pfr_<slug>" smtp transport per relay (managed block)
  pfr_<slug>_destination_*                per-relay concurrency / rate delay

Precedence (highest first): client IP/network > sender address > sender domain > default relay.

"@CONF@" in generated values is replaced by the Postfix config directory in pfhop-helper.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

from .db import Database
from .postfix import commands as pf

CONF = "@CONF@"
MAP_DIR = f"{CONF}/pfhop"
SENDER_MAP = f"{MAP_DIR}/sender_relay"
CLIENT_MAP = f"{MAP_DIR}/client_relay.cidr"
SASL_MAP = f"{MAP_DIR}/sasl_passwd"
CLIENT_CHECK = f"check_client_access cidr:{CLIENT_MAP}"

TLS_LEVELS = ("none", "may", "encrypt", "verify", "secure")
RELAY_KINDS = {"smtp": "SMTP relay server", "direct": "Direct delivery (MX)", "discard": "Discard"}
RULE_KINDS = {"sender": "Sender address", "domain": "Sender domain", "client": "Client IP / network"}
ROUTING_PARAMS = ("relayhost", "default_transport", "sender_dependent_default_transport_maps",
                  "smtpd_client_restrictions", "mynetworks")
TRANSPORT_PARAM_RE = re.compile(r"^pfr_[a-z0-9_]{1,24}_destination_(concurrency_limit|rate_delay)$")

HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
EMAIL_RE = re.compile(r"^[^@\s<>]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
DOMAIN_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$")
TIME_RE = re.compile(r"^\d+[smh]?$")


class RelayError(ValueError):
    pass


# -- model --------------------------------------------------------------------

@dataclass
class Relay:
    id: int
    slug: str
    name: str
    kind: str
    host: str
    port: int
    mx_lookup: bool
    tls_level: str
    auth_user: str
    auth_pass: str
    concurrency: int | None
    rate_delay: str
    is_default: bool
    description: str
    rules: list[dict] = field(default_factory=list)

    @property
    def transport(self) -> str:
        return "discard" if self.kind == "discard" else f"pfr_{self.slug}"

    @property
    def nexthop(self) -> str:
        if self.kind in ("discard", "direct"):
            return ""
        return f"{self.host}:{self.port}" if self.mx_lookup else f"[{self.host}]:{self.port}"

    @property
    def route(self) -> str:
        """Value used in sender maps / FILTER: 'pfr_x:[host]:25', 'pfr_x:' (direct) or 'discard:'.

        The trailing ':' matters for direct delivery: 'FILTER pfr_x' (no colon) is ignored by
        Postfix, 'FILTER pfr_x:' delivers to the recipient domain's MX (verified on 3.8)."""
        return "discard:" if self.kind == "discard" else f"{self.transport}:{self.nexthop}"

    @property
    def is_mta(self) -> bool:
        """A relay Postfix delivers through (SMTP server or direct delivery)."""
        return self.kind in ("smtp", "direct")


def _row_to_relay(row) -> Relay:
    return Relay(
        id=row["id"], slug=row["slug"], name=row["name"], kind=row["kind"], host=row["host"],
        port=row["port"], mx_lookup=bool(row["mx_lookup"]), tls_level=row["tls_level"],
        auth_user=row["auth_user"], auth_pass=row["auth_pass"], concurrency=row["concurrency"],
        rate_delay=row["rate_delay"], is_default=bool(row["is_default"]), description=row["description"],
    )


def list_relays(db: Database) -> list[Relay]:
    relays = [_row_to_relay(r) for r in db.query(
        "SELECT * FROM relays ORDER BY is_default DESC, kind = 'discard', name COLLATE NOCASE")]
    rules: dict[int, list[dict]] = {}
    for r in db.query("SELECT * FROM relay_rules ORDER BY kind, value"):
        rules.setdefault(r["relay_id"], []).append(dict(r))
    for relay in relays:
        relay.rules = rules.get(relay.id, [])
    return relays


def get_relay(db: Database, relay_id: int) -> Relay | None:
    for r in list_relays(db):
        if r.id == relay_id:
            return r
    return None


def list_clients(db: Database) -> list[dict]:
    rows = [dict(r) for r in db.query("SELECT * FROM clients")]
    rows.sort(key=lambda r: _net_sort_key(r["network"]))
    return rows


def _net_sort_key(net: str):
    try:
        n = ipaddress.ip_network(net, strict=False)
        return (0, n.version, int(n.network_address), n.prefixlen)
    except ValueError:
        return (1, 0, 0, net)


# -- validation helpers -------------------------------------------------------

def make_slug(db: Database, name: str, exclude_id: int | None = None) -> str:
    base = unicodedata.normalize("NFKD", name.replace("ı", "i").replace("İ", "I"))
    base = base.encode("ascii", "ignore").decode().lower()
    base = re.sub(r"[^a-z0-9]+", "_", base).strip("_")[:18] or "relay"
    slug, n = base, 2
    while db.query_one("SELECT 1 FROM relays WHERE slug = ? AND id != ?", (slug, exclude_id or -1)):
        slug = f"{base[:15]}_{n}"
        n += 1
    return slug


def normalize_rule(kind: str, value: str) -> str:
    value = value.strip()
    if kind == "sender":
        if value == "<>":
            return value
        if not EMAIL_RE.match(value):
            raise RelayError(f"'{value}' is not a valid e-mail address (use <> for the null sender).")
        return value.lower()
    if kind == "domain":
        value = value.lstrip("@").lower()
        if not DOMAIN_RE.match(value):
            raise RelayError(f"'{value}' is not a valid domain.")
        return "@" + value
    if kind == "client":
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise RelayError(f"'{value}' is not a valid IP address or network (e.g. 10.1.2.3 or 10.1.2.0/24).") from None
        return str(net) if net.num_addresses > 1 else str(net.network_address)
    raise RelayError("Unknown rule type.")


def normalize_network(value: str) -> str:
    value = value.strip()
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise RelayError(f"'{value}' is not a valid IP network (e.g. 10.0.0.0/8 or 192.168.1.10).") from None
    return str(net)


def validate_relay_form(form: dict, kind: str = "smtp") -> dict:
    name = form.get("name", "").strip()
    if not name or len(name) > 60:
        raise RelayError("Name is required (max 60 characters).")
    if kind not in ("smtp", "direct"):
        raise RelayError("Invalid relay type.")
    if kind == "direct":
        form = dict(form, host="direct.invalid", port="25", auth_user="", auth_pass="", mx_lookup="")
    host = form.get("host", "").strip().strip("[]")
    if not HOST_RE.match(host):
        try:
            ipaddress.ip_address(host)
        except ValueError:
            raise RelayError("Host must be a valid host name or IP address.") from None
    try:
        port = int(form.get("port", "25"))
        assert 1 <= port <= 65535
    except (ValueError, AssertionError):
        raise RelayError("Port must be between 1 and 65535.") from None
    tls = form.get("tls_level", "may")
    if tls not in TLS_LEVELS:
        raise RelayError("Invalid TLS level.")
    user = form.get("auth_user", "").strip()
    password = form.get("auth_pass", "")
    for v in (user, password):
        if re.search(r"[\x00-\x1f\x7f]", v):
            raise RelayError("User name / password must not contain control characters.")
    if " " in user:
        raise RelayError("User name must not contain spaces.")
    conc = form.get("concurrency", "").strip()
    if conc:
        if not conc.isdigit() or not 1 <= int(conc) <= 100:
            raise RelayError("Parallel connections must be 1-100 (or empty for the default).")
    delay = form.get("rate_delay", "").strip()
    if delay and not TIME_RE.match(delay):
        raise RelayError("Pause between deliveries: use e.g. 1s, 500ms is not supported (or empty).")
    desc = form.get("description", "").strip()[:200]
    if kind == "direct":
        host = ""
    return {
        "kind": kind, "name": name, "host": host, "port": port, "mx_lookup": 1 if form.get("mx_lookup") else 0,
        "tls_level": tls, "auth_user": user, "auth_pass": password,
        "concurrency": int(conc) if conc else None, "rate_delay": delay, "description": desc,
    }


# -- CRUD ---------------------------------------------------------------------

def create_relay(db: Database, data: dict) -> int:
    slug = make_slug(db, data["name"])
    has_default = db.query_one("SELECT 1 FROM relays WHERE is_default = 1 AND kind != 'discard'")
    cur = db.execute(
        "INSERT INTO relays(slug, name, kind, host, port, mx_lookup, tls_level, auth_user, auth_pass, "
        "concurrency, rate_delay, is_default, description, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (slug, data["name"], data["kind"], data["host"], data["port"], data["mx_lookup"], data["tls_level"],
         data["auth_user"], data["auth_pass"], data["concurrency"], data["rate_delay"],
         0 if has_default else 1, data["description"], int(time.time())),
    )
    return cur.lastrowid


def update_relay(db: Database, relay_id: int, data: dict, keep_password: bool) -> None:
    relay = get_relay(db, relay_id)
    if relay is None or not relay.is_mta:
        raise RelayError("Relay not found.")
    password = relay.auth_pass if keep_password else data["auth_pass"]
    if not data["auth_user"]:
        password = ""
    db.execute(
        "UPDATE relays SET name = ?, host = ?, port = ?, mx_lookup = ?, tls_level = ?, auth_user = ?, "
        "auth_pass = ?, concurrency = ?, rate_delay = ?, description = ?, updated_at = ? WHERE id = ?",
        (data["name"], data["host"], data["port"], data["mx_lookup"], data["tls_level"], data["auth_user"],
         password, data["concurrency"], data["rate_delay"], data["description"], int(time.time()), relay_id),
    )


def set_default(db: Database, relay_id: int) -> None:
    relay = get_relay(db, relay_id)
    if relay is None or not relay.is_mta:
        raise RelayError("Discard cannot be the default.")
    db.execute("UPDATE relays SET is_default = (id = ?)", (relay_id,))


def delete_relay(db: Database, relay_id: int) -> Relay:
    relay = get_relay(db, relay_id)
    if relay is None:
        raise RelayError("Relay not found.")
    if relay.kind == "discard":
        raise RelayError("The built-in Discard target cannot be deleted.")
    if relay.is_default:
        raise RelayError("Make another relay the default before deleting this one.")
    db.execute("DELETE FROM relays WHERE id = ?", (relay_id,))
    return relay


def add_rule(db: Database, relay_id: int, kind: str, value: str, description: str) -> str:
    if kind not in RULE_KINDS:
        raise RelayError("Unknown rule type.")
    value = normalize_rule(kind, value)
    relay = get_relay(db, relay_id)
    if relay is None:
        raise RelayError("Relay not found.")
    if relay.kind == "discard" and kind == "client":
        raise RelayError("Client networks cannot be routed to Discard; remove them from Allowed clients instead.")
    other = db.query_one(
        "SELECT r.name FROM relay_rules x JOIN relays r ON r.id = x.relay_id WHERE x.kind = ? AND x.value = ?",
        (kind, value),
    )
    if other:
        raise RelayError(f"{value} already uses relay '{other['name']}'. Remove it there first.")
    db.execute(
        "INSERT INTO relay_rules(relay_id, kind, value, description, created_at) VALUES (?, ?, ?, ?, ?)",
        (relay_id, kind, value, description.strip()[:200], int(time.time())),
    )
    return value


def delete_rule(db: Database, rule_id: int) -> dict:
    row = db.query_one("SELECT * FROM relay_rules WHERE id = ?", (rule_id,))
    if row is None:
        raise RelayError("Rule not found.")
    db.execute("DELETE FROM relay_rules WHERE id = ?", (rule_id,))
    return dict(row)


def add_client(db: Database, network: str, description: str) -> str:
    network = normalize_network(network)
    if db.query_one("SELECT 1 FROM clients WHERE network = ?", (network,)):
        raise RelayError(f"{network} is already in the list.")
    db.execute("INSERT INTO clients(network, description, created_at) VALUES (?, ?, ?)",
               (network, description.strip()[:200], int(time.time())))
    return network


def update_client(db: Database, client_id: int, description: str) -> None:
    db.execute("UPDATE clients SET description = ? WHERE id = ?", (description.strip()[:200], client_id))


def delete_client(db: Database, client_id: int) -> dict:
    row = db.query_one("SELECT * FROM clients WHERE id = ?", (client_id,))
    if row is None:
        raise RelayError("Network not found.")
    db.execute("DELETE FROM clients WHERE id = ?", (client_id,))
    return dict(row)


# -- import from the live configuration ---------------------------------------

def _parse_nexthop(value: str) -> tuple[str, int, bool]:
    """'[host]:25' -> (host, 25, False);  'host:587' -> (host, 587, True)"""
    value = value.strip()
    mx = not value.startswith("[")
    m = re.match(r"^\[?([^\]\[:]+)\]?(?::(\d+))?$", value)
    if not m:
        raise RelayError(f"cannot parse next hop {value!r}")
    return m.group(1), int(m.group(2) or 25), mx


def _relay_name_for(host: str) -> str:
    if host.endswith(".mail.protection.outlook.com") or host.endswith("office365.com"):
        return "Microsoft 365"
    if host.endswith("google.com") or host.endswith("gmail.com"):
        return "Google"
    return host


def _read_map_source(spec: str) -> list[tuple[str, str]]:
    """Read the source text of a 'type:/path' map (readable files only)."""
    if ":" not in spec:
        return []
    mtype, path = spec.split(":", 1)
    if mtype not in ("hash", "lmdb", "btree", "texthash", "cidr"):
        return []
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            entries.append((parts[0], parts[1].strip()))
    return entries


def import_from_live(db: Database) -> list[str]:
    """Populate relays / rules / clients from the current Postfix config (only if empty)."""
    notes: list[str] = []
    if db.query_one("SELECT 1 FROM relays"):
        return notes
    live = pf.postconf_get(*ROUTING_PARAMS, "smtp_tls_security_level", "transport_maps",
                           "sender_dependent_relayhost_maps")
    now = int(time.time())
    db.execute("BEGIN IMMEDIATE")
    try:
        db.execute(
            "INSERT INTO relays(slug, name, kind, is_default, description, updated_at) "
            "VALUES ('discard', 'Discard', 'discard', 0, 'Silently drop the message (no delivery, no bounce).', ?)",
            (now,),
        )
        tls = live.get("smtp_tls_security_level") or "may"
        if tls not in TLS_LEVELS:
            tls = "may"
        relay_ids: dict[tuple, int] = {}

        def ensure_relay(host: str, port: int, mx: bool, default: bool) -> int:
            key = (host.lower(), port, mx)
            if key in relay_ids:
                if default:
                    db.execute("UPDATE relays SET is_default = 1 WHERE id = ?", (relay_ids[key],))
                return relay_ids[key]
            name = _relay_name_for(host)
            if db.query_one("SELECT 1 FROM relays WHERE name = ?", (name,)):
                name = f"{name} ({host}:{port})"
            cur = db.execute(
                "INSERT INTO relays(slug, name, kind, host, port, mx_lookup, tls_level, is_default, "
                "updated_at) VALUES (?, ?, 'smtp', ?, ?, ?, ?, ?, ?)",
                (make_slug(db, name), name, host, port, int(mx), tls, int(default), now),
            )
            relay_ids[key] = cur.lastrowid
            return cur.lastrowid

        if live.get("relayhost"):
            host, port, mx = _parse_nexthop(live["relayhost"].split(",")[0])
            ensure_relay(host, port, mx, True)
            notes.append(f"Default relay imported from relayhost: {live['relayhost']}")
        else:
            db.execute(
                "INSERT INTO relays(slug, name, kind, tls_level, is_default, description, updated_at) "
                "VALUES (?, 'Direct delivery', 'direct', ?, 1, "
                "'Postfix looks up the recipient domain MX and delivers itself.', ?)",
                (make_slug(db, "direct"), "may" if tls in ("none", "encrypt", "verify", "secure") else tls, now),
            )
            notes.append("No relayhost is set: imported 'Direct delivery' as the default.")

        discard_id = db.query_one("SELECT id FROM relays WHERE kind = 'discard'")["id"]
        sdm = live.get("sender_dependent_default_transport_maps", "")
        for spec in sdm.replace(",", " ").split():
            for key, value in _read_map_source(spec):
                kind = "domain" if key.startswith("@") else "sender"
                try:
                    norm = normalize_rule(kind, key)
                except RelayError:
                    notes.append(f"Skipped sender rule {key!r} (not a plain address or domain).")
                    continue
                if value.startswith("discard"):
                    rid = discard_id
                else:
                    transport, _, nexthop = value.partition(":")
                    if not nexthop:
                        notes.append(f"Skipped sender rule {key} -> {value} (no next hop).")
                        continue
                    host, port, mx = _parse_nexthop(nexthop)
                    rid = ensure_relay(host, port, mx, False)
                db.execute(
                    "INSERT OR IGNORE INTO relay_rules(relay_id, kind, value, description, created_at) "
                    "VALUES (?, ?, ?, 'imported', ?)", (rid, kind, norm, now),
                )
                notes.append(f"Imported sender rule {norm} -> {value}")

        for net in live.get("mynetworks", "").replace(",", " ").split():
            try:
                norm = normalize_network(net.strip("[]"))
            except RelayError:
                notes.append(f"Skipped allowed client {net!r} (not a plain network).")
                continue
            desc = "localhost" if norm.startswith("127.") or norm == "::1/128" else ""
            db.execute("INSERT OR IGNORE INTO clients(network, description, created_at) VALUES (?, ?, ?)",
                       (norm, desc, now))
        for p in ("transport_maps", "sender_dependent_relayhost_maps"):
            if live.get(p):
                notes.append(f"Note: {p} = {live[p]} is not managed by pfhop and stays as it is.")
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise
    return notes


def reset_from_live(db: Database) -> list[str]:
    db.execute("DELETE FROM relay_rules")
    db.execute("DELETE FROM relays")
    db.execute("DELETE FROM clients")
    return import_from_live(db)


# -- generation ---------------------------------------------------------------

@dataclass
class Desired:
    params: dict[str, str]                # name -> value ('' never used; unset goes to `unset`)
    unset: list[str]
    files: dict[str, str]                 # file name in <conf>/pfhop -> content
    transports: list[dict]                # managed master.cf entries
    secret_hash: str                      # hash of sasl_passwd (file is root-only)


def generate(db: Database, live: dict[str, str] | None = None) -> Desired:
    relays = list_relays(db)
    mta_relays = [r for r in relays if r.is_mta]
    smtp_relays = [r for r in relays if r.kind == "smtp"]
    default = next((r for r in mta_relays if r.is_default), None)
    live = live if live is not None else pf.postconf_get(*ROUTING_PARAMS)

    params: dict[str, str] = {}
    unset: list[str] = []

    # default relay: the next hop goes into default_transport and relayhost stays empty, so that
    # a direct-delivery route (no next hop) is not redirected to the relayhost.
    unset.append("relayhost")
    if default:
        params["default_transport"] = default.route.rstrip(":") if default.kind == "direct" else default.route
    else:
        unset.append("default_transport")

    # sender / domain rules
    lines = ["# Managed by pfhop - do not edit by hand.", "# sender or @domain    transport:nexthop"]
    for r in relays:
        for rule in r.rules:
            if rule["kind"] in ("sender", "domain"):
                lines.append(f"{rule['value']}\t{r.route}")
    sender_map = "\n".join(lines) + "\n"
    params["sender_dependent_default_transport_maps"] = f"lmdb:{SENDER_MAP}"

    # client network rules (most specific network first)
    client_rules = []
    for r in relays:
        for rule in r.rules:
            if rule["kind"] == "client":
                client_rules.append((rule["value"], r))
    client_rules.sort(key=lambda x: -ipaddress.ip_network(x[0], strict=False).prefixlen)
    lines = ["# Managed by pfhop - do not edit by hand.", "# client network    FILTER transport:nexthop"]
    for net, r in client_rules:
        lines.append(f"{net}\tFILTER {r.route}")
    client_map = "\n".join(lines) + "\n"

    restrictions = _strip_client_check(live.get("smtpd_client_restrictions", ""))
    if client_rules:
        restrictions = CLIENT_CHECK + (" " + restrictions if restrictions else "")
    if restrictions:
        params["smtpd_client_restrictions"] = restrictions
    else:
        unset.append("smtpd_client_restrictions")

    # mynetworks
    nets = [c["network"] for c in list_clients(db)]
    params["mynetworks"] = " ".join(nets) if nets else "127.0.0.0/8"

    # SASL credentials
    lines = ["# Managed by pfhop - do not edit by hand."]
    for r in smtp_relays:
        if r.auth_user:
            lines.append(f"{r.nexthop}\t{r.auth_user}:{r.auth_pass}")
    sasl = "\n".join(lines) + "\n"

    # per-relay transports
    transports = []
    for r in mta_relays:
        opts = {"syslog_name": f"postfix/{r.transport}", "smtp_tls_security_level": r.tls_level}
        if r.port == 465:
            opts["smtp_tls_wrappermode"] = "yes"
            if r.tls_level in ("none", "may"):
                opts["smtp_tls_security_level"] = "encrypt"
        if r.auth_user:
            opts.update({
                "smtp_sasl_auth_enable": "yes",
                "smtp_sasl_password_maps": f"lmdb:{SASL_MAP}",
                "smtp_sasl_security_options": "noanonymous",
                "smtp_sasl_tls_security_options": "noanonymous",
            })
        else:
            opts["smtp_sasl_auth_enable"] = "no"
        transports.append({"name": r.transport, "options": opts})
        conc_p = f"{r.transport}_destination_concurrency_limit"
        delay_p = f"{r.transport}_destination_rate_delay"
        if r.concurrency:
            params[conc_p] = str(r.concurrency)
        else:
            unset.append(conc_p)
        if r.rate_delay:
            params[delay_p] = r.rate_delay
        else:
            unset.append(delay_p)

    # transport params of relays that no longer exist
    for name in _live_transport_params():
        if name not in params and name not in unset:
            unset.append(name)

    return Desired(
        params=params, unset=unset,
        files={"sender_relay": sender_map, "client_relay.cidr": client_map, "sasl_passwd": sasl},
        transports=transports,
        secret_hash=hashlib.sha256(sasl.encode()).hexdigest(),
    )


def _strip_client_check(value: str) -> str:
    """Remove pfhop's own check_client_access entry from a restriction list."""
    tokens = [t for t in re.split(r"[\s,]+", value) if t]
    out, i = [], 0
    while i < len(tokens):
        if tokens[i] == "check_client_access" and i + 1 < len(tokens) \
                and tokens[i + 1].endswith("pfhop/client_relay.cidr"):
            i += 2
            continue
        out.append(tokens[i])
        i += 1
    return " ".join(out)


def _live_transport_params() -> list[str]:
    """pfr_* parameters in main.cf (read directly: postconf -n hides unused ones)."""
    try:
        conf = pf.postconf_get("config_directory").get("config_directory", "/etc/postfix")
        text = Path(conf, "main.cf").read_text(encoding="utf-8", errors="replace")
    except (pf.CommandError, OSError):
        return []
    return [m.group(1) for m in re.finditer(r"^([A-Za-z0-9_]+)\s*=", text, re.M)
            if TRANSPORT_PARAM_RE.match(m.group(1))]


# -- compare with the live configuration ---------------------------------------

MANAGED_BEGIN = "# BEGIN pfhop managed transports - do not edit by hand"
MANAGED_END = "# END pfhop managed transports"


def render_master_block(transports: list[dict]) -> str:
    lines = [MANAGED_BEGIN]
    for t in transports:
        lines.append(f"{t['name']} unix - - n - - smtp")
        for k, v in t["options"].items():
            lines.append(f"  -o {k}={v}")
    lines.append(MANAGED_END)
    return "\n".join(lines)


def live_master_block(config_dir: str) -> str:
    try:
        text = Path(config_dir, "master.cf").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    start = text.find(MANAGED_BEGIN)
    end = text.find(MANAGED_END)
    if start == -1 or end == -1:
        return ""
    return text[start:end + len(MANAGED_END)]


@dataclass
class Change:
    what: str
    old: str
    new: str


def pending_changes(db: Database) -> tuple[list[Change], Desired]:
    """Differences between what pfhop would write and what Postfix currently uses."""
    config_dir = pf.postconf_get("config_directory").get("config_directory", "/etc/postfix")
    live_all = pf.postconf_get(*ROUTING_PARAMS)
    desired = generate(db, live_all)
    changes: list[Change] = []

    def resolve(v: str) -> str:
        return v.replace(CONF, config_dir)

    live_n = pf.postconf_n()
    for name, value in desired.params.items():
        new = resolve(value)
        old = live_n.get(name, "")
        if name in ROUTING_PARAMS:
            old = live_all.get(name, old)
        if old.split() != new.split():
            changes.append(Change(name, old or "(not set)", new))
    for name in desired.unset:
        if name in live_n:
            changes.append(Change(name, live_n[name], "(remove)"))

    for fname, content in desired.files.items():
        if fname == "sasl_passwd":
            # The file is root-only; compare with the hash stored at the last apply.
            row = db.query_one("SELECT value FROM meta WHERE key = 'sasl_hash'")
            has_creds = any(r.auth_user for r in list_relays(db))
            if (row is None and has_creds) or (row is not None and row["value"] != desired.secret_hash):
                changes.append(Change("relay credentials (sasl_passwd)", "(hidden)", "updated (hidden)"))
            continue
        path = Path(config_dir, "pfhop", fname)
        try:
            old = path.read_text(encoding="utf-8")
        except OSError:
            old = ""
        if _summ(old) != _summ(content):
            changes.append(Change(f"file pfhop/{fname}", _summ(old), _summ(content)))

    old_block = live_master_block(config_dir)
    new_block = resolve(render_master_block(desired.transports))
    if old_block.strip() != new_block.strip():
        changes.append(Change("master.cf relay transports", old_block or "(none)", new_block))
    return changes, desired


def _summ(text: str) -> str:
    body = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
    return "\n".join(body) if body else "(empty)"


def build_bundle(desired: Desired) -> dict:
    return {
        "set": desired.params,
        "unset": desired.unset,
        "files": desired.files,
        "master_block": desired.transports,
    }


# -- routing prediction / labels ---------------------------------------------

class RelayIndex:
    """Maps log/queue data to relay names."""

    def __init__(self, db: Database):
        self.relays = list_relays(db)
        self.by_transport = {r.transport: r for r in self.relays}
        self.by_host = {r.host.lower(): r for r in self.relays if r.kind == "smtp" and r.host}
        self.default = next((r for r in self.relays if r.is_default), None)
        self.sender_rules: dict[str, Relay] = {}
        self.client_rules: list[tuple[ipaddress._BaseNetwork, Relay]] = []
        for r in self.relays:
            for rule in r.rules:
                if rule["kind"] in ("sender", "domain"):
                    self.sender_rules[rule["value"]] = r
                else:
                    self.client_rules.append((ipaddress.ip_network(rule["value"], strict=False), r))
        self.client_rules.sort(key=lambda x: -x[0].prefixlen)

    def for_delivery(self, transport: str, relay: str) -> Relay | None:
        if transport in self.by_transport:
            return self.by_transport[transport]
        if transport == "discard":
            return self.by_transport.get("discard")
        host = (relay or "").split("[", 1)[0].lower()
        return self.by_host.get(host)

    def predict(self, sender: str | None, client_ip: str | None) -> Relay | None:
        if client_ip:
            try:
                addr = ipaddress.ip_address(client_ip)
                for net, r in self.client_rules:
                    if addr in net:
                        return r
            except ValueError:
                pass
        s = (sender or "").lower()
        key = s if s else "<>"
        if key in self.sender_rules:
            return self.sender_rules[key]
        if "@" in s:
            dom = "@" + s.split("@", 1)[1]
            if dom in self.sender_rules:
                return self.sender_rules[dom]
        return self.default


def client_rule_allowed(db: Database, value: str) -> bool:
    """True when a client rule's network lies inside one of the Allowed clients (mynetworks)."""
    rule = ipaddress.ip_network(value, strict=False)
    for c in list_clients(db):
        net = ipaddress.ip_network(c["network"], strict=False)
        if rule.version == net.version and rule.subnet_of(net):
            return True
    return False


def is_managed() -> bool:
    """True once pfhop has applied its routing configuration to Postfix at least once."""
    conf = pf.postconf_get("config_directory").get("config_directory", "/etc/postfix")
    return bool(live_master_block(conf))
