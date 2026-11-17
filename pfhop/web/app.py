"""FastAPI application: routes, auth, CSRF, templates."""

from __future__ import annotations

import hmac
import re
import secrets
import time
import socket
from pathlib import Path
from urllib.parse import quote

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .. import __version__
from .. import auth as authmod
from .. import backup as backupmod
from .. import relays as relaymod
from .. import relaytest
from .. import stats
from ..config import Config, load_config
from ..db import Database
from ..postfix import commands as pf
from ..postfix import catalog
from ..postfix.params import DESCRIPTIONS
from ..system import sysinfo
from . import helpers as h

HERE = Path(__file__).parent

# Editable runtime settings shown on the Settings page.
SETTINGS_FORM = [
    {"section": "General", "key": "general.title", "label": "Title", "type": "str", "max": 60,
     "help": "Shown in the top bar of every page and in reports."},
    {"section": "General", "key": "general.dashboard_refresh_seconds", "label": "Auto-refresh (seconds)",
     "type": "int", "min": 2, "max": 300, "help": "How often the dashboard and queue refresh themselves."},
    {"section": "General", "key": "general.queue_age_warn_minutes", "label": "Queue age warning (minutes)",
     "type": "int", "min": 1, "max": 10080, "help": "Messages older than this are highlighted yellow."},
    {"section": "General", "key": "general.queue_age_crit_minutes", "label": "Queue age critical (minutes)",
     "type": "int", "min": 1, "max": 10080, "help": "Messages older than this are highlighted red."},
    {"section": "General", "key": "general.disk_warn_percent", "label": "Usage warning (%)", "type": "int",
     "min": 1, "max": 100, "help": "Disk, RAM and CPU bars turn yellow above this."},
    {"section": "General", "key": "general.disk_crit_percent", "label": "Usage critical (%)", "type": "int",
     "min": 1, "max": 100, "help": "Disk, RAM and CPU bars turn red above this."},
    {"section": "Dashboard", "key": "dashboard.queue_rows", "label": "Queue table rows", "type": "int",
     "min": 5, "max": 500, "help": "Maximum rows in the dashboard queue table (scrolls inside)."},
    {"section": "Dashboard", "key": "dashboard.recent_rows", "label": "Recent e-mails rows", "type": "int",
     "min": 5, "max": 500, "help": "How many of the latest outgoing e-mails the dashboard shows."},
    {"section": "Logs", "key": "logs.page_size", "label": "Rows per page", "type": "int",
     "min": 10, "max": 500, "help": "Rows per page on the Logs page."},
    {"section": "Logs", "key": "logs.retention_days", "label": "Keep history (days)", "type": "int",
     "min": 1, "max": 3650, "help": "Collected mail history older than this is deleted."},
    {"section": "Backups", "key": "backup.auto_enabled", "label": "Automatic daily backup", "type": "bool",
     "help": "Back up the Postfix configuration and the pfhop settings every day."},
    {"section": "Backups", "key": "backup.auto_time", "label": "Backup time (HH:MM)", "type": "time",
     "help": "Server local time. The backup runs within 15 minutes after this time."},
    {"section": "Backups", "key": "backup.auto_keep", "label": "Keep automatic backups", "type": "int",
     "min": 1, "max": 365, "help": "Older automatic backups are deleted. Manual backups are never deleted automatically."},
    {"section": "E-mail", "key": "mail.system_sender", "label": "System sender address", "type": "email",
     "optional": True, "help": "From address of every e-mail pfhop sends (reports, relay tests). "
     "Use an address your relays accept, e.g. pfhop@yourdomain."},
    {"section": "E-mail", "key": "mail.system_sender_name", "label": "System sender name", "type": "str",
     "max": 80, "help": "Display name for the address above."},
    {"section": "E-mail", "key": "mail.test_recipient", "label": "Default test recipient", "type": "email",
     "optional": True, "help": "Pre-filled recipient in the relay test (can be changed for each test)."},
    {"section": "Audit", "key": "audit.enabled", "label": "Audit log enabled", "type": "bool",
     "help": "Record logins and admin actions (who, what, when, from which IP). "
             "Switching it off is itself recorded as the last entry."},
]

_BRACKETS = re.compile(r"\s*\[[^\]]*\]")


def _short_reason(reason: str) -> str:
    return " ".join(_BRACKETS.sub("", reason).split())[:160]


class AuthRequired(Exception):
    pass


class Forbidden(Exception):
    pass


class CsrfError(Exception):
    pass


def create_app(cfg: Config | None = None) -> FastAPI:
    cfg = cfg or load_config()
    db = Database(cfg.db_path)
    throttle = authmod.LoginThrottle()

    app = FastAPI(title="pfhop", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.cfg = cfg
    app.state.db = db

    templates = Jinja2Templates(directory=str(HERE / "templates"))
    env = templates.env
    # Templates change only together with the code (on service restart), never mid-flight.
    env.auto_reload = False
    env.filters.update(filesize=h.filesize, duration=h.duration, ts=h.fmt_ts, ago=h.ago)
    env.globals.update(version=__version__, level=h.level)

    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")

    # -- middleware --------------------------------------------------------
    @app.middleware("http")
    async def security(request: Request, call_next):
        ip = h.client_ip(request, cfg.trusted_proxies)
        request.state.client_ip = ip
        if not h.ip_allowed(ip, cfg.allowed_networks):
            return Response("Forbidden", status_code=403)
        response = await call_next(request)
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; frame-ancestors 'none'; form-action 'self'",
        )
        if not request.url.path.startswith("/static"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    app.add_middleware(
        SessionMiddleware,
        secret_key=cfg.secret_key,
        session_cookie="pfhop_session",
        max_age=cfg.session_hours * 3600,
        same_site="strict",
        https_only=cfg.cookie_secure,
    )

    # -- helpers -----------------------------------------------------------
    def csrf_token(request: Request) -> str:
        tok = request.session.get("csrf")
        if not tok:
            tok = secrets.token_urlsafe(32)
            request.session["csrf"] = tok
        return tok

    async def csrf_check(request: Request) -> None:
        expected = request.session.get("csrf", "")
        sent = request.headers.get("x-csrf-token", "")
        if not sent:
            form = await request.form()
            sent = str(form.get("csrf", ""))
        if not expected or not hmac.compare_digest(expected, sent):
            raise CsrfError()

    def flash(request: Request, message: str, kind: str = "ok") -> None:
        # Flash messages live in the (4 KB) session cookie: keep them short.
        if len(message) > 400:
            message = message[:400] + " …"
        flashes = request.session.setdefault("flash", [])
        flashes.append([kind, message])
        del flashes[:-5]

    def apply_summary(result: dict) -> str:
        """Short, user-facing summary of a pfhop-helper apply result."""
        log = [x for x in result.get("log", []) if not x.startswith("postfix check:")]
        warnings = [x for x in result.get("log", []) if x.startswith("postfix check:")]
        text = " · ".join(log)
        if warnings:
            text += " · postfix check reported warnings (see Audit log)"
        return text

    def current_user(request: Request) -> authmod.User:
        uid = request.session.get("uid")
        login_at = request.session.get("login_at", 0)
        if not uid or time.time() - login_at > cfg.session_hours * 3600:
            request.session.pop("uid", None)
            raise AuthRequired()
        user = authmod.get_user(db, uid)
        if user is None or not user.is_active:
            request.session.clear()
            raise AuthRequired()
        request.state.user = user
        return user

    def admin_user(user: authmod.User = Depends(current_user)) -> authmod.User:
        if not user.is_admin:
            raise Forbidden()
        return user

    header_cache: dict = {"t": 0.0, "v": {}}

    def header_info() -> dict:
        """Host name, IP and Postfix version for the top bar (cached for a minute)."""
        if time.time() - header_cache["t"] > 60:
            try:
                version = pf.postconf_get("mail_version").get("mail_version", "")
            except pf.CommandError:
                version = ""
            header_cache["v"] = {"hostname": socket.gethostname(), "ip": sysinfo.primary_ip(),
                                 "postfix_version": version}
            header_cache["t"] = time.time()
        return header_cache["v"]

    def render(request: Request, name: str, ctx: dict | None = None, status: int = 200) -> HTMLResponse:
        ctx = dict(ctx or {})
        settings = db.all_settings()
        ctx.update(
            user=getattr(request.state, "user", None),
            csrf=csrf_token(request),
            flashes=request.session.pop("flash", []),
            settings=settings,
            title=settings["general.title"],
            header=header_info(),
            path=request.url.path,
            collector_age=stats.collector_age(db),
            sidebar_collapsed=request.cookies.get("pfhop_sb") == "1",
            ridx=relaymod.RelayIndex(db),
        )
        return templates.TemplateResponse(request, name, ctx, status_code=status)

    def audit(request: Request, action: str, target: str = "", details: str = "", success: bool = True):
        user = getattr(request.state, "user", None)
        db.audit(user.username if user else "-", action, target, details,
                 request.state.client_ip, success)

    def redirect(url: str) -> RedirectResponse:
        return RedirectResponse(url, status_code=303)

    # -- error handlers ----------------------------------------------------
    @app.exception_handler(AuthRequired)
    async def _auth_required(request: Request, exc: AuthRequired):
        if request.headers.get("hx-request"):
            return Response(status_code=401, headers={"HX-Redirect": "/login"})
        nxt = request.url.path
        return redirect("/login" + (f"?next={quote(nxt)}" if nxt not in ("/", "/login") else ""))

    @app.exception_handler(Forbidden)
    async def _forbidden(request: Request, exc: Forbidden):
        return render(request, "error.html", {"title": "Forbidden",
                      "message": "This action requires the admin role."}, status=403)

    @app.exception_handler(CsrfError)
    async def _csrf(request: Request, exc: CsrfError):
        return render(request, "error.html", {"title": "Session expired",
                      "message": "Your form was stale or invalid. Please go back, reload and try again."},
                      status=400)

    @app.exception_handler(404)
    async def _not_found(request: Request, exc):
        return render(request, "error.html", {"title": "Not found",
                      "message": "The page you requested does not exist."}, status=404)

    # -- auth routes -------------------------------------------------------
    @app.get("/login")
    def login_page(request: Request, next: str = "/"):
        if request.session.get("uid"):
            return redirect("/")
        no_users = db.query_one("SELECT COUNT(*) AS n FROM users")["n"] == 0
        return render(request, "login.html", {"next": next, "no_users": no_users})

    @app.post("/login", dependencies=[Depends(csrf_check)])
    def login_submit(request: Request, username: str = Form(""), password: str = Form(""),
                     next: str = Form("/")):
        ip = request.state.client_ip
        locked = throttle.locked_for(ip)
        if locked:
            flash(request, f"Too many failed attempts. Try again in {locked} seconds.", "error")
            return redirect("/login")
        user = authmod.authenticate(db, username, password)
        if user is None:
            throttle.failure(ip)
            db.audit(username[:64] or "-", "login", details="invalid credentials", client_ip=ip, success=False)
            flash(request, "Invalid username or password.", "error")
            return redirect("/login")
        throttle.success(ip)
        request.session.clear()
        request.session.update(uid=user.id, login_at=int(time.time()), csrf=secrets.token_urlsafe(32))
        db.audit(user.username, "login", client_ip=ip)
        if not next.startswith("/") or next.startswith("//"):
            next = "/"
        return redirect(next)

    @app.post("/logout", dependencies=[Depends(csrf_check)])
    def logout(request: Request):
        uid = request.session.get("uid")
        user = authmod.get_user(db, uid) if uid else None
        if user:
            db.audit(user.username, "logout", client_ip=request.state.client_ip)
        request.session.clear()
        return redirect("/login")

    # -- dashboard ---------------------------------------------------------
    def queue_rows(limit: int | None = None) -> dict:
        settings = db.all_settings()
        queue = pf.queue_summary()
        msgs = sorted(queue.messages, key=lambda m: m.arrival_time)
        meta = stats.queue_meta(db, [m.queue_id for m in msgs])
        warn = settings["general.queue_age_warn_minutes"] * 60
        crit = settings["general.queue_age_crit_minutes"] * 60
        rows = []
        for m in msgs:
            age_level = "crit" if m.age >= crit else "warn" if m.age >= warn else "ok"
            rows.append({"m": m, "meta": meta.get(m.queue_id, {}), "age_level": age_level,
                         "reason": _short_reason(m.delay_reason)})
        shown = rows[:limit] if limit else rows
        return {"queue": queue, "qrows": shown, "qtotal": len(rows)}

    def dashboard_top() -> dict:
        settings = db.all_settings()
        sysi = sysinfo.collect()
        overview = pf.postfix_overview()
        queue = pf.queue_summary()
        queue_dir = overview.get("queue_directory") or "/var/spool/postfix"
        mount = sysinfo.mount_for(queue_dir)
        return {
            "sys": sysi,
            "pf": overview,
            "service": pf.service_status("postfix"),
            "queue": queue,
            "today": stats.today_counts(db),
            "top_senders": stats.top_senders(db, 10),
            "bounces": stats.bounces_today(db, 10),
            "queue_disk": next((d for d in sysi["disks"] if d.mount == mount), None),
            "warn_pct": settings["general.disk_warn_percent"],
            "crit_pct": settings["general.disk_crit_percent"],
            "today_from": time.strftime("%Y-%m-%dT00:00"),
        }

    @app.get("/")
    def dashboard(request: Request, user=Depends(current_user)):
        settings = db.all_settings()
        ctx = dashboard_top()
        ctx.update(queue_rows(settings["dashboard.queue_rows"]))
        ctx["recent"] = stats.recent_deliveries(db, settings["dashboard.recent_rows"])
        ctx["refresh"] = settings["general.dashboard_refresh_seconds"]
        return render(request, "dashboard.html", ctx)

    @app.get("/partials/dash-top")
    def dash_top(request: Request, user=Depends(current_user)):
        return render(request, "partials/dash_top.html", dashboard_top())

    @app.get("/partials/queue-rows")
    def queue_rows_partial(request: Request, full: int = 0, user=Depends(current_user)):
        limit = None if full else db.get_setting("dashboard.queue_rows")
        ctx = queue_rows(limit)
        ctx["full"] = bool(full)
        return render(request, "partials/queue_rows.html", ctx)

    @app.get("/partials/recent-rows")
    def recent_rows_partial(request: Request, user=Depends(current_user)):
        return render(request, "partials/recent_rows.html",
                      {"recent": stats.recent_deliveries(db, db.get_setting("dashboard.recent_rows"))})

    # -- queue page --------------------------------------------------------
    @app.get("/queue")
    def queue_page(request: Request, user=Depends(current_user)):
        ctx = queue_rows(None)
        ctx["full"] = True
        ctx["refresh"] = db.get_setting("general.dashboard_refresh_seconds")
        return render(request, "queue.html", ctx)

    # -- logs page ---------------------------------------------------------
    @app.get("/logs")
    def logs_page(request: Request, q: str = "", sender: str = "", recipient: str = "", ip: str = "",
                  status: str = "", relay: str = "", date_from: str = "", date_to: str = "",
                  period: str = "", page: int = 1, user=Depends(current_user)):
        flt = stats.LogFilter(q=q.strip(), sender=sender.strip(), recipient=recipient.strip(),
                              ip=ip.strip(), status=status, relay=relay.strip(),
                              date_from=date_from, date_to=date_to, period=period)
        page_size = db.get_setting("logs.page_size")
        page = max(1, page)
        rows, total = stats.search_deliveries(db, flt, page, page_size)
        pages = max(1, (total + page_size - 1) // page_size)
        params = {k: v for k, v in {"q": flt.q, "sender": flt.sender, "recipient": flt.recipient,
                  "ip": flt.ip, "status": flt.status, "relay": flt.relay,
                  "period": flt.period, "date_from": flt.date_from,
                  "date_to": flt.date_to}.items() if v}
        return render(request, "logs.html", {
            "rows": rows, "total": total, "page": page, "pages": pages, "f": flt,
            "params": params, "statuses": stats.DELIVERY_STATUSES, "page_size": page_size,
            "periods": stats.DATE_PERIODS,
        })

    # -- reports -----------------------------------------------------------
    @app.get("/reports")
    def reports_page(request: Request, user=Depends(current_user)):
        return render(request, "reports.html")

    # -- actions -----------------------------------------------------------
    def _back(next_url: str, default: str = "/") -> RedirectResponse:
        if not next_url.startswith("/") or next_url.startswith("//"):
            next_url = default
        return redirect(next_url)

    @app.post("/actions/service/{action}", dependencies=[Depends(csrf_check)])
    def action_service(request: Request, action: str, next: str = Form("/"), user=Depends(admin_user)):
        try:
            msg = pf.service_action(cfg, action)
        except pf.CommandError as exc:
            audit(request, f"postfix.{action}", details=str(exc), success=False)
            flash(request, f"Postfix {action} failed: {exc}", "error")
            return _back(next)
        audit(request, f"postfix.{action}")
        flash(request, msg)
        return _back(next)

    @app.post("/actions/queue/flush", dependencies=[Depends(csrf_check)])
    def action_flush(request: Request, next: str = Form("/"), user=Depends(admin_user)):
        try:
            msg = pf.flush_queue()
        except pf.CommandError as exc:
            audit(request, "queue.flush", details=str(exc), success=False)
            flash(request, f"Flush failed: {exc}", "error")
            return _back(next)
        audit(request, "queue.flush")
        flash(request, msg)
        return _back(next)

    @app.post("/actions/queue/{action}", dependencies=[Depends(csrf_check)])
    async def action_queue(request: Request, action: str, user=Depends(admin_user)):
        form = await request.form()
        ids = [str(v) for v in form.getlist("id")]
        next_url = str(form.get("next", "/"))
        if action not in pf.QUEUE_ACTIONS:
            flash(request, "Unknown action.", "error")
            return _back(next_url)
        if not ids:
            flash(request, "No messages selected.", "error")
            return _back(next_url)
        target = ", ".join(ids[:20]) + (f" (+{len(ids) - 20} more)" if len(ids) > 20 else "")
        try:
            msg = pf.queue_action(cfg, action, ids)
        except pf.CommandError as exc:
            audit(request, f"queue.{action}", target, str(exc), success=False)
            flash(request, f"{action.capitalize()} failed: {exc}", "error")
            return _back(next_url)
        audit(request, f"queue.{action}", target, msg)
        flash(request, msg)
        return _back(next_url)

    # -- configuration ------------------------------------------------------
    def cfg_ctx(tab: str, **extra) -> dict:
        return {"tabs": catalog.TABS, "tab": tab, **extra}

    @app.get("/postfix/config")
    def postfix_config_old(request: Request, user=Depends(current_user)):
        return redirect("/config/advanced")

    @app.get("/config")
    def config_root(request: Request, user=Depends(current_user)):
        return redirect("/config/general")

    @app.get("/config/advanced")
    def config_advanced(request: Request, user=Depends(current_user)):
        error = ""
        params: dict[str, str] = {}
        defaults: dict[str, str] = {}
        master: list = []
        try:
            params = pf.postconf_n()
            defaults = pf.postconf_defaults(*params.keys()) if params else {}
            master = pf.postconf_master()
        except pf.CommandError as exc:
            error = str(exc)
        rows = [
            {"name": k, "value": v, "default": defaults.get(k, ""), "desc": DESCRIPTIONS.get(k, "")}
            for k, v in sorted(params.items())
        ]
        return render(request, "config_advanced.html",
                      cfg_ctx("advanced", rows=rows, master=master, error=error))

    def param_values(tab: str) -> list[catalog.FieldValue]:
        """Current values for a tab. Text fields keep $variables; typed fields are expanded."""
        fields = catalog.CATALOG[tab]
        names = [f["name"] for f in fields]
        raw = pf.postconf_get(*names)
        expanded = pf.postconf_get(*names, expand=True)
        d_raw = pf._parse_postconf(pf._run([pf.POSTCONF, "-d", *names]))
        d_exp = pf._parse_postconf(pf._run([pf.POSTCONF, "-d", "-x", *names]))
        explicit = pf.postconf_n()
        values = []
        for f in fields:
            n = f["name"]
            text = f["type"] == "text"
            value = (raw if text else expanded).get(n, "")
            default = (d_raw if text else d_exp).get(n, "")
            values.append(catalog.FieldValue(
                field=f, value=value, display=catalog.to_display(f, value),
                default=catalog.to_display(f, default), is_set=n in explicit,
            ))
        return values

    @app.get("/config/{tab}")
    def config_tab(request: Request, tab: str, user=Depends(current_user)):
        if tab == "relays":
            return config_relays(request)
        if tab == "clients":
            return config_clients(request)
        if tab not in catalog.PARAM_TABS:
            return render(request, "error.html", {"title": "Not found", "message": "Unknown tab."}, 404)
        try:
            values = param_values(tab)
        except pf.CommandError as exc:
            flash(request, f"Could not read the Postfix configuration: {exc}", "error")
            values = []
        return render(request, "config_params.html", cfg_ctx(tab, values=values))

    @app.post("/config/{tab}/preview", dependencies=[Depends(csrf_check)])
    async def config_preview(request: Request, tab: str, user=Depends(admin_user)):
        if tab not in catalog.PARAM_TABS:
            return redirect("/config")
        form = await request.form()
        changes, errors = [], []
        for fv in param_values(tab):
            raw = str(form.get(fv.name, "")).strip()
            if raw == fv.display:
                continue  # untouched
            try:
                new = catalog.from_form(fv.field, raw)
            except catalog.ValueError_ as exc:
                errors.append(str(exc))
                continue
            if new is None:  # field cleared -> back to the Postfix default
                if fv.is_set:
                    changes.append({"fv": fv, "new": None, "new_display": f"default ({fv.default or 'empty'})"})
            elif new != fv.value:
                changes.append({"fv": fv, "new": new, "new_display": catalog.to_display(fv.field, new)})
        if errors:
            for e in errors:
                flash(request, e, "error")
            return redirect(f"/config/{tab}")
        if not changes:
            flash(request, "No changes.")
            return redirect(f"/config/{tab}")
        return render(request, "config_preview.html", cfg_ctx(tab, changes=changes))

    @app.post("/config/{tab}/apply", dependencies=[Depends(csrf_check)])
    async def config_apply(request: Request, tab: str, user=Depends(admin_user)):
        if tab not in catalog.PARAM_TABS:
            return redirect("/config")
        form = await request.form()
        allowed = {f["name"]: f for f in catalog.CATALOG[tab]}
        sets, unset, details = {}, [], []
        for key, raw in form.multi_items():
            if not key.startswith("p:"):
                continue
            name = key[2:]
            if name not in allowed:
                continue
            raw = str(raw)
            if raw == "__default__":
                unset.append(name)
                details.append(f"{name} -> default")
                continue
            try:
                value = catalog.validate_raw(allowed[name], raw)
            except catalog.ValueError_ as exc:
                flash(request, str(exc), "error")
                return redirect(f"/config/{tab}")
            sets[name] = value
            details.append(f"{name} = {value}")
        if not sets and not unset:
            return redirect(f"/config/{tab}")
        result = pf.apply_config(cfg, {"set": sets, "unset": unset})
        if result.get("ok"):
            audit(request, "postfix.config", catalog.TABS[tab], "; ".join(details + result.get("log", [])))
            flash(request, "Applied: " + "; ".join(details) + ". " + apply_summary(result))
        else:
            audit(request, "postfix.config", catalog.TABS[tab], f"{'; '.join(details)} -> {result.get('error')}",
                  success=False)
            flash(request, f"Not applied (configuration restored): {result.get('error')}", "error")
        return redirect(f"/config/{tab}")

    # -- relays ------------------------------------------------------------
    def relay_today_stats() -> dict[int, dict[str, int]]:
        ridx = relaymod.RelayIndex(db)
        out: dict[int, dict[str, int]] = {}
        rows = db.query(
            "SELECT transport, relay, status, COUNT(*) AS n FROM deliveries WHERE ts >= ? "
            "GROUP BY transport, relay, status", (stats.day_start(),))
        for r in rows:
            relay = ridx.for_delivery(r["transport"], r["relay"])
            if relay:
                d = out.setdefault(relay.id, {})
                d[r["status"]] = d.get(r["status"], 0) + r["n"]
        return out

    def config_relays(request: Request):
        notes = relaymod.import_from_live(db)
        for n in notes:
            flash(request, n)
        relays = relaymod.list_relays(db)
        try:
            pending = len(relaymod.pending_changes(db)[0])
            managed = relaymod.is_managed()
        except (pf.CommandError, OSError) as exc:
            pending, managed = 0, True
            flash(request, f"Could not compare with the live configuration: {exc}", "error")
        settings = db.all_settings()
        return render(request, "config_relays.html", cfg_ctx(
            "relays", relays=relays, pending=pending, managed=managed, today=relay_today_stats(),
            rule_kinds=relaymod.RULE_KINDS, tls_levels=relaymod.TLS_LEVELS, relay_kinds=relaymod.RELAY_KINDS,
            test_sender=settings["mail.system_sender"], test_recipient=settings["mail.test_recipient"],
            allowed_check=lambda v: relaymod.client_rule_allowed(db, v),
        ))

    def relay_action(request: Request, func, ok_message: str, action: str, target: str = ""):
        try:
            result = func()
        except relaymod.RelayError as exc:
            flash(request, str(exc), "error")
            return redirect("/config/relays")
        audit(request, action, target or (result if isinstance(result, str) else ""), "pending apply")
        flash(request, ok_message.format(result=result) + " Changes are pending - review and apply them above.")
        return redirect("/config/relays")

    @app.post("/config/relays/new", dependencies=[Depends(csrf_check)])
    async def relay_create(request: Request, user=Depends(admin_user)):
        form = {k: str(v) for k, v in (await request.form()).items()}
        def go():
            data = relaymod.validate_relay_form(form, form.get("kind", "smtp"))
            relaymod.create_relay(db, data)
            return data["name"]
        return relay_action(request, go, "Relay '{result}' added.", "relay.create")

    @app.post("/config/relays/{relay_id}/update", dependencies=[Depends(csrf_check)])
    async def relay_update(request: Request, relay_id: int, user=Depends(admin_user)):
        form = {k: str(v) for k, v in (await request.form()).items()}
        def go():
            relay = relaymod.get_relay(db, relay_id)
            if relay is None:
                raise relaymod.RelayError("Relay not found.")
            data = relaymod.validate_relay_form(form, relay.kind)
            relaymod.update_relay(db, relay_id, data, keep_password=not form.get("auth_pass"))
            return data["name"]
        return relay_action(request, go, "Relay '{result}' updated.", "relay.update")

    @app.post("/config/relays/{relay_id}/default", dependencies=[Depends(csrf_check)])
    def relay_default(request: Request, relay_id: int, user=Depends(admin_user)):
        def go():
            relaymod.set_default(db, relay_id)
            return relaymod.get_relay(db, relay_id).name
        return relay_action(request, go, "'{result}' is now the default relay.", "relay.default")

    @app.post("/config/relays/{relay_id}/delete", dependencies=[Depends(csrf_check)])
    def relay_delete(request: Request, relay_id: int, user=Depends(admin_user)):
        return relay_action(request, lambda: relaymod.delete_relay(db, relay_id).name,
                            "Relay '{result}' deleted.", "relay.delete")

    @app.post("/config/relays/{relay_id}/rules", dependencies=[Depends(csrf_check)])
    def rule_add(request: Request, relay_id: int, kind: str = Form(""), value: str = Form(""),
                 description: str = Form(""), user=Depends(admin_user)):
        relay = relaymod.get_relay(db, relay_id)
        response = relay_action(request, lambda: relaymod.add_rule(db, relay_id, kind, value, description),
                                "{result} now uses " + (relay.name if relay else "the relay") + ".",
                                "relay.rule.add", f"{kind}:{value} -> {relay.name if relay else relay_id}")
        if kind == "client":
            try:
                norm = relaymod.normalize_rule("client", value)
                if not relaymod.client_rule_allowed(db, norm):
                    flash(request, f"Warning: {norm} is not in Allowed clients, so Postfix will refuse to relay "
                                   "its mail (Relay access denied). Add it under Allowed clients too.", "error")
            except relaymod.RelayError:
                pass
        return response

    @app.post("/config/rules/{rule_id}/delete", dependencies=[Depends(csrf_check)])
    def rule_delete(request: Request, rule_id: int, user=Depends(admin_user)):
        return relay_action(request, lambda: relaymod.delete_rule(db, rule_id)["value"],
                            "Rule for {result} removed.", "relay.rule.delete")

    @app.post("/config/relays/{relay_id}/test", dependencies=[Depends(csrf_check)])
    def relay_test(request: Request, relay_id: int, sender: str = Form(""), recipient: str = Form(""),
                   send: str = Form(""), user=Depends(admin_user)):
        relay = relaymod.get_relay(db, relay_id)
        error = ""
        if relay is None:
            error = "Relay not found."
        elif not relaymod.EMAIL_RE.match(sender.strip()) or not relaymod.EMAIL_RE.match(recipient.strip()):
            error = "Enter a valid sender and recipient address."
        if error:
            return render(request, "partials/relay_test_result.html", {"error": error, "result": None})
        info = pf.postconf_get("myhostname", "smtp_tls_CAfile", "inet_protocols")
        result = relaytest.run_test(
            relay, info.get("myhostname") or socket.gethostname(), sender.strip(), recipient.strip(),
            bool(send), info.get("smtp_tls_CAfile") or None, db.get_setting("mail.system_sender_name"),
            info.get("inet_protocols", "all"),
        )
        audit(request, "relay.test", relay.name,
              f"{sender} -> {recipient}{' (sent)' if send else ''}: {'ok' if result.ok else 'failed'}",
              success=result.ok)
        return render(request, "partials/relay_test_result.html",
                      {"error": "", "result": result, "relay": relay, "sent": bool(send)})

    # -- allowed clients ---------------------------------------------------
    def client_usage() -> dict[str, dict]:
        import ipaddress
        nets = [(ipaddress.ip_network(c["network"], strict=False), c["network"]) for c in relaymod.list_clients(db)]
        nets.sort(key=lambda x: -x[0].prefixlen)
        usage: dict[str, dict] = {}
        rows = db.query(
            "SELECT client_ip, COUNT(*) AS total, SUM(first_seen >= ?) AS today, MAX(first_seen) AS last "
            "FROM messages WHERE client_ip != '' GROUP BY client_ip", (stats.day_start(),))
        for r in rows:
            try:
                addr = ipaddress.ip_address(r["client_ip"])
            except ValueError:
                continue
            for net, key in nets:
                if addr in net:
                    u = usage.setdefault(key, {"today": 0, "last": 0, "hosts": 0})
                    u["today"] += r["today"] or 0
                    u["last"] = max(u["last"], r["last"] or 0)
                    u["hosts"] += 1
                    break
        return usage

    def config_clients(request: Request):
        for n in relaymod.import_from_live(db):
            flash(request, n)
        try:
            pending = len(relaymod.pending_changes(db)[0])
            managed = relaymod.is_managed()
        except (pf.CommandError, OSError):
            pending, managed = 0, True
        return render(request, "config_clients.html", cfg_ctx(
            "clients", clients=relaymod.list_clients(db), usage=client_usage(), pending=pending, managed=managed))

    def client_action(request: Request, func, ok_message: str, action: str):
        try:
            result = func()
        except relaymod.RelayError as exc:
            flash(request, str(exc), "error")
            return redirect("/config/clients")
        audit(request, action, result if isinstance(result, str) else "", "pending apply")
        flash(request, ok_message.format(result=result) + " Changes are pending - review and apply them above.")
        return redirect("/config/clients")

    @app.post("/config/clients/new", dependencies=[Depends(csrf_check)])
    def client_add(request: Request, network: str = Form(""), description: str = Form(""),
                   user=Depends(admin_user)):
        return client_action(request, lambda: relaymod.add_client(db, network, description),
                             "{result} added.", "clients.add")

    @app.post("/config/clients/{client_id}/update", dependencies=[Depends(csrf_check)])
    def client_update(request: Request, client_id: int, description: str = Form(""),
                      user=Depends(admin_user)):
        relaymod.update_client(db, client_id, description)
        flash(request, "Description saved.")
        return redirect("/config/clients")

    @app.post("/config/clients/{client_id}/delete", dependencies=[Depends(csrf_check)])
    def client_delete(request: Request, client_id: int, user=Depends(admin_user)):
        return client_action(request, lambda: relaymod.delete_client(db, client_id)["network"],
                             "{result} removed.", "clients.delete")

    # -- pending relay/client changes --------------------------------------
    @app.get("/routing/review")
    def pending_review(request: Request, user=Depends(current_user)):
        relaymod.import_from_live(db)
        changes, _ = relaymod.pending_changes(db)
        first = not relaymod.live_master_block(
            pf.postconf_get("config_directory").get("config_directory", "/etc/postfix"))
        return render(request, "config_pending.html", cfg_ctx("relays", changes=changes, first_takeover=first))

    @app.post("/routing/apply", dependencies=[Depends(csrf_check)])
    def pending_apply(request: Request, user=Depends(admin_user)):
        changes, desired = relaymod.pending_changes(db)
        if not changes:
            flash(request, "Nothing to apply.")
            return redirect("/config/relays")
        result = pf.apply_config(cfg, relaymod.build_bundle(desired))
        summary = "; ".join(c.what for c in changes)
        if result.get("ok"):
            db.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('sasl_hash', ?)", (desired.secret_hash,))
            audit(request, "postfix.routing.apply", details="; ".join([summary] + result.get("log", [])))
            flash(request, "Relay configuration applied. " + apply_summary(result))
        else:
            audit(request, "postfix.routing.apply", details=f"{summary} -> {result.get('error')}", success=False)
            flash(request, f"Not applied (configuration restored): {result.get('error')}", "error")
        return redirect("/config/relays")

    @app.post("/routing/discard", dependencies=[Depends(csrf_check)])
    def pending_discard(request: Request, user=Depends(admin_user)):
        notes = relaymod.reset_from_live(db)
        audit(request, "postfix.routing.discard", details="reloaded from live configuration")
        flash(request, "Relays and allowed clients were re-imported from the current Postfix configuration. "
                       + " ".join(notes))
        return redirect("/config/relays")

    # -- backups -----------------------------------------------------------
    @app.get("/backups")
    def backups_page(request: Request, user=Depends(admin_user)):
        return render(request, "backups.html", {
            "postfix_backups": backupmod.list_backups(db, "postfix"),
            "app_backups": backupmod.list_backups(db, "app"),
            "backup_dir": str(cfg.backup_dir),
        })

    @app.post("/backups/{kind}", dependencies=[Depends(csrf_check)])
    def backup_create(request: Request, kind: str, note: str = Form(""), user=Depends(admin_user)):
        try:
            if kind == "postfix":
                info = backupmod.create_postfix_backup(cfg, db, note, user.username)
            elif kind == "app":
                info = backupmod.create_app_backup(cfg, db, note, user.username)
            else:
                raise backupmod.BackupError("Unknown backup type.")
        except (backupmod.BackupError, pf.CommandError, OSError) as exc:
            audit(request, f"backup.{kind}.create", details=str(exc), success=False)
            flash(request, f"Backup failed: {exc}", "error")
            return redirect("/backups")
        audit(request, f"backup.{kind}.create", info["filename"], f"{info['size']} bytes")
        flash(request, f"Backup created: {info['filename']} ({h.filesize(info['size'])})")
        return redirect("/backups")

    @app.get("/backups/{backup_id}/download")
    def backup_download(request: Request, backup_id: int, user=Depends(admin_user)):
        try:
            row, path = backupmod.backup_file(cfg, db, backup_id)
        except backupmod.BackupError as exc:
            flash(request, str(exc), "error")
            return redirect("/backups")
        audit(request, f"backup.{row['kind']}.download", row["filename"])
        media = "application/gzip" if row["filename"].endswith(".tar.gz") else "application/json"
        return FileResponse(path, media_type=media, filename=row["filename"])

    @app.post("/backups/{backup_id}/delete", dependencies=[Depends(csrf_check)])
    def backup_delete(request: Request, backup_id: int, user=Depends(admin_user)):
        try:
            row = backupmod.delete_backup(cfg, db, backup_id)
        except backupmod.BackupError as exc:
            flash(request, str(exc), "error")
            return redirect("/backups")
        audit(request, f"backup.{row['kind']}.delete", row["filename"])
        flash(request, f"Deleted {row['filename']}.")
        return redirect("/backups")

    # -- application settings ---------------------------------------------
    @app.get("/settings")
    def settings_page(request: Request, user=Depends(current_user)):
        return render(request, "settings.html", {"fields": SETTINGS_FORM})

    @app.post("/settings", dependencies=[Depends(csrf_check)])
    async def settings_save(request: Request, user=Depends(admin_user)):
        form = await request.form()
        errors, values = [], {}
        for f in SETTINGS_FORM:
            raw = str(form.get(f["key"], "")).strip()
            if f["type"] == "bool":
                val = raw in ("1", "on", "true")
            elif f["type"] == "time":
                m = re.fullmatch(r"([01]?\d|2[0-3]):([0-5]\d)", raw)
                if not m:
                    errors.append(f"{f['label']}: use HH:MM, e.g. 00:30.")
                    continue
                val = f"{int(m.group(1)):02d}:{m.group(2)}"
            elif f["type"] == "int":
                try:
                    val = int(raw)
                except ValueError:
                    errors.append(f"{f['label']}: must be a number.")
                    continue
                if not f["min"] <= val <= f["max"]:
                    errors.append(f"{f['label']}: must be between {f['min']} and {f['max']}.")
                    continue
            elif f["type"] == "email":
                val = raw.strip()
                if val and not relaymod.EMAIL_RE.match(val):
                    errors.append(f"{f['label']}: not a valid e-mail address.")
                    continue
                if not val and not f.get("optional"):
                    errors.append(f"{f['label']}: cannot be empty.")
                    continue
            else:
                val = raw[: f["max"]]
                if not val:
                    errors.append(f"{f['label']}: cannot be empty.")
                    continue
            values[f["key"]] = val
        if not errors:
            if values["general.queue_age_warn_minutes"] > values["general.queue_age_crit_minutes"]:
                errors.append("Queue age warning must not be greater than critical.")
            if values["general.disk_warn_percent"] > values["general.disk_crit_percent"]:
                errors.append("Usage warning must not be greater than critical.")
        if errors:
            for e in errors:
                flash(request, e, "error")
            return redirect("/settings")
        current = db.all_settings()
        changed = {k: v for k, v in values.items() if current.get(k) != v}
        details = ", ".join(f"{k}={v}" for k, v in changed.items())
        if changed.get("audit.enabled") is False:
            # Log before switching off, so the audit trail shows who disabled it.
            db.audit(user.username, "settings.update", details=details,
                     client_ip=request.state.client_ip, force=True)
        for k, v in changed.items():
            db.set_setting(k, v, user.username)
        if changed and changed.get("audit.enabled") is not False:
            audit(request, "settings.update", details=details)
        flash(request, "Settings saved." if changed else "No changes.")
        return redirect("/settings")

    # -- users -------------------------------------------------------------
    @app.get("/users")
    def users_page(request: Request, user=Depends(admin_user)):
        return render(request, "users.html", {"users": authmod.list_users(db),
                                              "min_len": authmod.MIN_PASSWORD_LEN})

    @app.post("/users", dependencies=[Depends(csrf_check)])
    def user_create(request: Request, username: str = Form(""), password: str = Form(""),
                    role: str = Form("viewer"), full_name: str = Form(""), email: str = Form(""),
                    user=Depends(admin_user)):
        try:
            new = authmod.create_user(db, username, password, role, full_name, email)
        except authmod.UserError as exc:
            flash(request, str(exc), "error")
            return redirect("/users")
        audit(request, "user.create", new.username, f"role={new.role}")
        flash(request, f"User '{new.username}' created.")
        return redirect("/users")

    @app.post("/users/{user_id}/update", dependencies=[Depends(csrf_check)])
    def user_update(request: Request, user_id: int, role: str = Form(...), is_active: str = Form(""),
                    full_name: str = Form(""), email: str = Form(""), user=Depends(admin_user)):
        target = authmod.get_user(db, user_id)
        try:
            authmod.update_user(db, user_id, role, bool(is_active), full_name, email)
        except authmod.UserError as exc:
            flash(request, str(exc), "error")
            return redirect("/users")
        audit(request, "user.update", target.username if target else str(user_id),
              f"role={role} active={bool(is_active)}")
        flash(request, "User updated.")
        return redirect("/users")

    @app.post("/users/{user_id}/password", dependencies=[Depends(csrf_check)])
    def user_password(request: Request, user_id: int, password: str = Form(""), user=Depends(admin_user)):
        target = authmod.get_user(db, user_id)
        if target is None:
            flash(request, "User not found.", "error")
            return redirect("/users")
        try:
            authmod.set_password(db, user_id, password)
        except authmod.UserError as exc:
            flash(request, str(exc), "error")
            return redirect("/users")
        audit(request, "user.password_reset", target.username)
        flash(request, f"Password for '{target.username}' changed.")
        return redirect("/users")

    @app.post("/users/{user_id}/delete", dependencies=[Depends(csrf_check)])
    def user_delete(request: Request, user_id: int, user=Depends(admin_user)):
        target = authmod.get_user(db, user_id)
        if target and target.id == user.id:
            flash(request, "You cannot delete your own account.", "error")
            return redirect("/users")
        try:
            authmod.delete_user(db, user_id)
        except authmod.UserError as exc:
            flash(request, str(exc), "error")
            return redirect("/users")
        audit(request, "user.delete", target.username if target else str(user_id))
        flash(request, "User deleted.")
        return redirect("/users")

    # -- own account -------------------------------------------------------
    @app.get("/account")
    def account_page(request: Request, user=Depends(current_user)):
        return render(request, "account.html", {"min_len": authmod.MIN_PASSWORD_LEN})

    @app.post("/account/password", dependencies=[Depends(csrf_check)])
    def account_password(request: Request, current: str = Form(""), new: str = Form(""),
                         confirm: str = Form(""), user=Depends(current_user)):
        if authmod.authenticate(db, user.username, current) is None:
            flash(request, "Current password is wrong.", "error")
        elif new != confirm:
            flash(request, "New passwords do not match.", "error")
        else:
            try:
                authmod.set_password(db, user.id, new)
                audit(request, "account.password_change", user.username)
                flash(request, "Password changed.")
            except authmod.UserError as exc:
                flash(request, str(exc), "error")
        return redirect("/account")

    # -- audit log ---------------------------------------------------------
    @app.get("/audit")
    def audit_page(request: Request, q: str = "", user=Depends(admin_user)):
        if q:
            like = f"%{q}%"
            rows = db.query(
                "SELECT * FROM audit_log WHERE username LIKE ? OR action LIKE ? OR target LIKE ? "
                "OR details LIKE ? OR client_ip LIKE ? ORDER BY id DESC LIMIT 500",
                (like, like, like, like, like),
            )
        else:
            rows = db.query("SELECT * FROM audit_log ORDER BY id DESC LIMIT 500")
        return render(request, "audit.html", {"rows": rows, "q": q})

    return app
