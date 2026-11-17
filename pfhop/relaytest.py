"""Step-by-step SMTP test of a relay server (runs as the unprivileged pfhop user).

By default no mail is sent: the session stops after RCPT TO (RSET + QUIT).
With send=True a short test message is delivered through the relay.
"""

from __future__ import annotations

import dataclasses
import socket
import ssl
import smtplib
import time
from dataclasses import dataclass, field
from datetime import datetime
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid

from . import __version__
from .dnsmx import DNSError, lookup_mx
from .relays import Relay

TIMEOUT = 15


@dataclass
class Step:
    name: str
    status: str = "ok"        # ok | warn | fail | skip
    detail: str = ""
    ms: int = 0


@dataclass
class TestResult:
    steps: list[Step] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(s.status != "fail" for s in self.steps)

    def add(self, name: str, status: str, detail: str, started: float) -> Step:
        step = Step(name, status, detail, int((time.monotonic() - started) * 1000))
        self.steps.append(step)
        return step


def _reply(code, msg) -> str:
    text = msg.decode(errors="replace") if isinstance(msg, bytes) else str(msg)
    return f"{code} {' '.join(text.split())}"


def _connect(relay: Relay, helo: str, implicit_tls: bool, context: ssl.SSLContext | None, address: str):
    if implicit_tls:
        smtp = smtplib.SMTP_SSL(timeout=TIMEOUT, local_hostname=helo, context=context)
    else:
        smtp = smtplib.SMTP(timeout=TIMEOUT, local_hostname=helo)
    smtp._host = relay.host  # used as TLS server_hostname (SNI + certificate check)
    code, msg = smtp.connect(address, relay.port)
    return smtp, code, msg


def _cert_summary(sock) -> str:
    try:
        cert = sock.getpeercert()
    except (ValueError, AttributeError):
        cert = None
    parts = []
    if hasattr(sock, "version"):
        parts.append(f"{sock.version()} {sock.cipher()[0] if sock.cipher() else ''}".strip())
    if cert:
        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        parts.append(f"certificate CN={subject.get('commonName', '?')}")
        parts.append(f"issuer {issuer.get('organizationName') or issuer.get('commonName', '?')}")
        if cert.get("notAfter"):
            expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            days = (expires - datetime.utcnow()).days
            parts.append(f"valid until {expires:%Y-%m-%d} ({days} days)")
    return ", ".join(parts)


def run_test(relay: Relay, helo: str, sender: str, recipient: str, send: bool,
             ca_file: str | None = None, from_name: str = "", inet_protocols: str = "all") -> TestResult:
    res = TestResult()
    if relay.kind == "discard":
        res.add("Relay", "skip", "Discard has nothing to test.", time.monotonic())
        return res
    if relay.kind == "direct":
        # Direct delivery: find the recipient domain's mail server like Postfix would.
        domain = recipient.rsplit("@", 1)[-1]
        t = time.monotonic()
        try:
            mxs = lookup_mx(domain)
        except DNSError as exc:
            res.add(f"MX lookup {domain}", "fail", str(exc), t)
            return res
        if mxs == [(0, "")]:
            res.add(f"MX lookup {domain}", "fail", "Null MX: this domain does not accept mail.", t)
            return res
        target = mxs[0][1] if mxs else domain
        detail = ", ".join(f"{p} {h}" for p, h in mxs[:4]) if mxs else f"no MX record - using {domain} itself"
        res.add(f"MX lookup {domain}", "ok", detail + f" → testing {target}", t)
        relay = dataclasses.replace(relay, host=target, port=25, auth_user="", auth_pass="")
    implicit_tls = relay.port == 465

    # 1. DNS
    t = time.monotonic()
    try:
        family = {"ipv4": socket.AF_INET, "ipv6": socket.AF_INET6}.get(inet_protocols, socket.AF_UNSPEC)
        infos = socket.getaddrinfo(relay.host, relay.port, family=family, type=socket.SOCK_STREAM)
        addrs = sorted({i[4][0] for i in infos})
        address = infos[0][4][0]
        note = " (Postfix will look up MX records; this test uses the host's own address)" if relay.mx_lookup else ""
        res.add("DNS lookup", "ok", ", ".join(addrs[:6]) + (" …" if len(addrs) > 6 else "") + note, t)
    except socket.gaierror as exc:
        res.add("DNS lookup", "fail", f"{relay.host}: {exc.strerror}", t)
        return res

    def verified_context() -> ssl.SSLContext:
        ctx = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
        return ctx

    def unverified_context() -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    smtp = None
    verified = True
    for attempt in (1, 2):
        ctx = verified_context() if verified else unverified_context()
        # 2. Connect
        t = time.monotonic()
        try:
            smtp, code, msg = _connect(relay, helo, implicit_tls, ctx if implicit_tls else None, address)
        except ssl.SSLCertVerificationError as exc:
            if relay.tls_level in ("verify", "secure"):
                res.add("Connect (TLS)", "fail", f"certificate not trusted: {exc.verify_message}", t)
                return res
            verified = False
            continue
        except (OSError, smtplib.SMTPException) as exc:
            hint = ""
            if isinstance(exc, (TimeoutError, socket.timeout)) and relay.port == 25:
                hint = " - outgoing port 25 is probably blocked by a firewall"
            res.add(f"Connect {relay.host}:{relay.port}", "fail", (str(exc) or exc.__class__.__name__) + hint, t)
            return res
        if code != 220:
            res.add(f"Connect {relay.host}:{relay.port}", "fail", _reply(code, msg), t)
            smtp.close()
            return res
        if attempt == 1 or not res.steps or not res.steps[-1].name.startswith("Connect"):
            res.add(f"Connect {relay.host}:{relay.port}", "ok", f"via {address}: " + _reply(code, msg), t)

        # 3. EHLO
        t = time.monotonic()
        code, msg = smtp.ehlo(helo)
        if code != 250:
            res.add("EHLO", "fail", _reply(code, msg), t)
            smtp.close()
            return res
        features = sorted(k.upper() for k in smtp.esmtp_features)
        size = smtp.esmtp_features.get("size", "").strip()
        detail = ", ".join(features)
        if size.isdigit():
            detail += f" (max size {int(size) / 1048576:.0f} MB)"
        if attempt == 1:
            res.add("EHLO", "ok", detail, t)

        # 4. TLS
        if implicit_tls:
            res.add("TLS (port 465)", "ok" if verified else "warn",
                    _cert_summary(smtp.sock) + ("" if verified else " - certificate NOT verified"), t)
            break
        if relay.tls_level == "none":
            res.add("STARTTLS", "skip", "TLS is disabled for this relay.", time.monotonic())
            break
        if not smtp.has_extn("starttls"):
            status = "warn" if relay.tls_level == "may" else "fail"
            res.add("STARTTLS", status, "The server does not offer STARTTLS.", time.monotonic())
            if status == "fail":
                smtp.close()
                return res
            break
        t = time.monotonic()
        try:
            code, msg = smtp.starttls(context=ctx)
        except ssl.SSLCertVerificationError as exc:
            smtp.close()
            if relay.tls_level in ("verify", "secure"):
                res.add("STARTTLS", "fail", f"certificate not trusted: {exc.verify_message}", t)
                return res
            res.add("STARTTLS", "warn", f"certificate not trusted ({exc.verify_message}); "
                                        f"retrying without verification (allowed for TLS level '{relay.tls_level}')", t)
            verified = False
            continue
        except (OSError, ValueError, smtplib.SMTPException) as exc:
            res.add("STARTTLS", "fail", str(exc), t)
            return res
        if code != 220:
            res.add("STARTTLS", "fail", _reply(code, msg), t)
            smtp.close()
            return res
        res.add("STARTTLS", "ok" if verified else "warn",
                _cert_summary(smtp.sock) + ("" if verified else " - certificate NOT verified"), t)
        smtp.ehlo(helo)
        break

    if smtp is None:
        return res

    try:
        # 5. AUTH
        if relay.auth_user:
            t = time.monotonic()
            try:
                code, msg = smtp.login(relay.auth_user, relay.auth_pass)
                res.add(f"AUTH as {relay.auth_user}", "ok", _reply(code, msg), t)
            except smtplib.SMTPAuthenticationError as exc:
                res.add(f"AUTH as {relay.auth_user}", "fail", _reply(exc.smtp_code, exc.smtp_error), t)
                return res
            except smtplib.SMTPNotSupportedError:
                res.add(f"AUTH as {relay.auth_user}", "fail", "The server does not offer AUTH (TLS first?).", t)
                return res
        # 6. MAIL FROM / RCPT TO
        t = time.monotonic()
        code, msg = smtp.mail(sender)
        res.add(f"MAIL FROM:<{sender}>", "ok" if code == 250 else "fail", _reply(code, msg), t)
        if code != 250:
            return res
        t = time.monotonic()
        code, msg = smtp.rcpt(recipient)
        res.add(f"RCPT TO:<{recipient}>", "ok" if code in (250, 251) else "fail", _reply(code, msg), t)
        if code not in (250, 251):
            return res
        # 7. DATA (optional)
        t = time.monotonic()
        if send:
            em = EmailMessage()
            em["From"] = formataddr((from_name, sender)) if from_name else sender
            em["To"] = recipient
            em["Subject"] = f"pfhop relay test: {relay.name}"
            em["Date"] = formatdate(localtime=True)
            em["Message-ID"] = make_msgid(domain=helo)
            em.set_content(
                f"This is a test message sent by pfhop {__version__} on {helo}.\n\n"
                f"Relay:  {relay.name} ({relay.host}:{relay.port})\n"
                f"TLS:    {relay.tls_level}\n"
                f"Time:   {datetime.now():%Y-%m-%d %H:%M:%S}\n\n"
                "If you received this, the relay accepted and delivered the message.\n"
            )
            code, msg = smtp.data(em.as_bytes())
            res.add("DATA (test message sent)", "ok" if code == 250 else "fail", _reply(code, msg), t)
        else:
            smtp.rset()
            res.add("DATA", "skip", "Not sent (dry run). Tick 'Send a real test e-mail' to deliver one.", t)
    except (OSError, smtplib.SMTPException) as exc:
        res.add("SMTP session", "fail", str(exc), time.monotonic())
    finally:
        try:
            smtp.quit()
        except (OSError, smtplib.SMTPException):
            smtp.close()
    return res
