"""Editable Postfix parameters, grouped into Configuration tabs.

Each entry: name, label, type, help (+ options for "choice").
Types:
  text     free text (single line)
  int      non-negative integer
  bool     yes / no
  choice   one of `options`
  time     Postfix time value: number + optional unit s/m/h/d/w (e.g. 30s, 5d)
  size_mb  bytes in main.cf, shown and edited in MB
  size_kb  bytes in main.cf, shown and edited in KB

pfhop-helper keeps its own copy of the allowed names (EDITABLE_PARAMS);
tests/test_config.py checks the two lists stay in sync.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

TABS = {
    "general": "General",
    "relays": "Relay servers",
    "clients": "Allowed clients",
    "message": "Message & MIME",
    "security": "Security & TLS",
    "queue": "Queue & delivery",
    "advanced": "Advanced",
}

# Tabs backed by the parameter catalog below (relays/clients/advanced are custom pages).
PARAM_TABS = ("general", "message", "security", "queue")

CATALOG: dict[str, list[dict]] = {
    "general": [
        {"name": "myhostname", "label": "Server host name", "type": "text",
         "help": "Fully qualified name this server announces in SMTP (HELO/EHLO) and in headers."},
        {"name": "mydomain", "label": "Domain", "type": "text",
         "help": "The internet domain of this server."},
        {"name": "myorigin", "label": "Origin domain", "type": "text",
         "help": "Domain appended to locally posted mail that has no domain (e.g. from cron)."},
        {"name": "inet_interfaces", "label": "Listen on", "type": "text",
         "help": "Interfaces that accept SMTP: all, loopback-only, or a list of IP addresses. "
                 "Changing this needs a Postfix restart."},
        {"name": "inet_protocols", "label": "IP protocols", "type": "choice",
         "options": ["ipv4", "ipv6", "all"], "help": "Use IPv4, IPv6 or both."},
        {"name": "smtpd_banner", "label": "SMTP greeting banner", "type": "text",
         "help": "Text after the 220 code when a client connects. Must start with $myhostname."},
    ],
    "message": [
        {"name": "message_size_limit", "label": "Maximum message size", "type": "size_mb",
         "help": "Largest accepted message including attachments (base64 adds ~37% to file sizes)."},
        {"name": "header_size_limit", "label": "Maximum header size", "type": "size_kb",
         "help": "Largest allowed size of a single message header."},
        {"name": "smtpd_recipient_limit", "label": "Maximum recipients per message", "type": "int",
         "help": "Recipients accepted in one SMTP transaction."},
        {"name": "smtputf8_enable", "label": "SMTPUTF8 (international addresses)", "type": "bool",
         "help": "Allow non-ASCII characters in e-mail addresses (e.g. ö, ş in the local part)."},
        {"name": "disable_mime_input_processing", "label": "Disable MIME input processing", "type": "bool",
         "help": "When yes, Postfix does not parse MIME structure (mime/body checks see raw text)."},
        {"name": "disable_mime_output_conversion", "label": "Disable 8bit → 7bit conversion", "type": "bool",
         "help": "When yes, 8-bit messages are never converted to quoted-printable for 7-bit servers."},
        {"name": "strict_rfc821_envelopes", "label": "Strict RFC 821 addresses", "type": "bool",
         "help": "Reject MAIL FROM / RCPT TO addresses that are not enclosed in <>."},
        {"name": "always_add_missing_headers", "label": "Add missing headers", "type": "bool",
         "help": "Add From, To, Date, Message-ID headers when a message lacks them."},
        {"name": "header_checks", "label": "Header checks table", "type": "text",
         "help": "Lookup table with rules applied to message headers, e.g. regexp:/etc/postfix/header_checks."},
        {"name": "mime_header_checks", "label": "MIME header checks table", "type": "text",
         "help": "Rules applied to MIME part headers (attachment names, content types)."},
        {"name": "body_checks", "label": "Body checks table", "type": "text",
         "help": "Rules applied to message body lines."},
    ],
    "security": [
        {"name": "smtpd_tls_security_level", "label": "Inbound TLS (clients → this server)", "type": "choice",
         "options": ["none", "may", "encrypt"],
         "help": "may = offer STARTTLS, encrypt = require it. Needs a certificate and key."},
        {"name": "smtpd_tls_cert_file", "label": "Server certificate file", "type": "text",
         "help": "PEM certificate (chain) used for inbound TLS."},
        {"name": "smtpd_tls_key_file", "label": "Server private key file", "type": "text",
         "help": "PEM private key for the certificate above."},
        {"name": "smtpd_tls_protocols", "label": "Inbound TLS protocols", "type": "text",
         "help": "e.g. >=TLSv1.2 to refuse old protocols."},
        {"name": "smtp_tls_security_level", "label": "Outbound TLS default", "type": "choice",
         "options": ["none", "may", "encrypt", "dane", "verify", "secure"],
         "help": "Default for deliveries. Each relay can override this in the Relay servers tab."},
        {"name": "smtp_tls_CAfile", "label": "Trusted CA bundle", "type": "text",
         "help": "CA certificates used to verify relay servers."},
        {"name": "smtp_tls_protocols", "label": "Outbound TLS protocols", "type": "text",
         "help": "e.g. >=TLSv1.2"},
        {"name": "smtpd_helo_required", "label": "Require HELO/EHLO", "type": "bool",
         "help": "Clients must greet with HELO/EHLO before sending mail."},
        {"name": "disable_vrfy_command", "label": "Disable VRFY", "type": "bool",
         "help": "Prevent address probing with the SMTP VRFY command."},
        {"name": "smtpd_client_connection_count_limit", "label": "Max parallel connections per client",
         "type": "int", "help": "0 = no limit. Clients in Allowed clients are exempt by default."},
        {"name": "smtpd_client_connection_rate_limit", "label": "Max connections per client per time unit",
         "type": "int", "help": "0 = no limit."},
        {"name": "smtpd_client_message_rate_limit", "label": "Max messages per client per time unit",
         "type": "int", "help": "0 = no limit."},
        {"name": "smtpd_client_recipient_rate_limit", "label": "Max recipients per client per time unit",
         "type": "int", "help": "0 = no limit."},
        {"name": "anvil_rate_time_unit", "label": "Rate limit time unit", "type": "time",
         "help": "Time window for the rate limits above, e.g. 60s."},
    ],
    "queue": [
        {"name": "maximal_queue_lifetime", "label": "Give up after", "type": "time",
         "help": "How long a deferred message is retried before it is returned to the sender."},
        {"name": "bounce_queue_lifetime", "label": "Give up on bounces after", "type": "time",
         "help": "Same, for bounce (non-delivery) messages."},
        {"name": "delay_warning_time", "label": "Warn sender after", "type": "time",
         "help": "Send a 'still trying' notice to the sender after this delay. 0 = never."},
        {"name": "minimal_backoff_time", "label": "Minimum retry interval", "type": "time",
         "help": "Shortest wait before retrying a deferred message."},
        {"name": "maximal_backoff_time", "label": "Maximum retry interval", "type": "time",
         "help": "Longest wait between retries."},
        {"name": "queue_run_delay", "label": "Queue scan interval", "type": "time",
         "help": "How often the deferred queue is scanned."},
        {"name": "default_destination_concurrency_limit", "label": "Parallel deliveries per destination (default)",
         "type": "int", "help": "Default for all transports."},
        {"name": "smtp_destination_concurrency_limit", "label": "Parallel SMTP deliveries per destination",
         "type": "int", "help": "Each relay can override this in the Relay servers tab."},
        {"name": "smtp_destination_rate_delay", "label": "Pause between deliveries", "type": "time",
         "help": "Delay between deliveries to the same destination; helps against '421 too many "
                 "connections'. 0s = off. Each relay can override this."},
        {"name": "smtp_connect_timeout", "label": "Connect timeout", "type": "time",
         "help": "Give up connecting to a relay after this long."},
        {"name": "queue_minfree", "label": "Minimum free disk space", "type": "size_mb",
         "help": "Refuse new mail when the queue file system has less free space than this. 0 = off."},
    ],
}

ALL_PARAMS = {f["name"]: f for fields in CATALOG.values() for f in fields}

TIME_RE = re.compile(r"^\d+[smhdw]?$")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


@dataclass
class FieldValue:
    field: dict
    value: str          # effective value in main.cf terms
    display: str        # value as shown in the form
    default: str
    is_set: bool        # explicitly set in main.cf

    @property
    def name(self) -> str:
        return self.field["name"]


def to_display(field: dict, value: str) -> str:
    t = field["type"]
    if t in ("size_mb", "size_kb"):
        try:
            n = int(value)
        except ValueError:
            return value
        div = 1048576 if t == "size_mb" else 1024
        shown = n / div
        return f"{shown:.2f}".rstrip("0").rstrip(".") if n else "0"
    return value


class ValueError_(ValueError):
    pass


def from_form(field: dict, raw: str) -> str | None:
    """Convert a submitted form value to a main.cf value. '' = reset to default (None)."""
    raw = raw.strip()
    if raw == "":
        return None
    t = field["type"]
    label = field["label"]
    if _CTRL.search(raw):
        raise ValueError_(f"{label}: control characters are not allowed.")
    if t == "int":
        if not raw.isdigit():
            raise ValueError_(f"{label}: must be a whole number.")
        return str(int(raw))
    if t == "bool":
        if raw not in ("yes", "no"):
            raise ValueError_(f"{label}: must be yes or no.")
        return raw
    if t == "choice":
        if raw not in field["options"]:
            raise ValueError_(f"{label}: invalid choice.")
        return raw
    if t == "time":
        if not TIME_RE.match(raw):
            raise ValueError_(f"{label}: use a number with optional unit s/m/h/d/w, e.g. 30s or 5d.")
        return raw
    if t in ("size_mb", "size_kb"):
        try:
            num = float(raw.replace(",", "."))
        except ValueError:
            raise ValueError_(f"{label}: must be a number.") from None
        if num < 0 or num > 100000:
            raise ValueError_(f"{label}: out of range.")
        return str(int(round(num * (1048576 if t == "size_mb" else 1024))))
    if len(raw) > 1000:
        raise ValueError_(f"{label}: too long.")
    return raw


def validate_raw(field: dict, value: str) -> str:
    """Validate a value that is already in main.cf form (used when applying a preview)."""
    if field["type"] in ("size_mb", "size_kb"):
        if not value.isdigit():
            raise ValueError_(f"{field['label']}: invalid size.")
        return value
    result = from_form(field, value)
    if result is None:
        raise ValueError_(f"{field['label']}: empty value.")
    return result
