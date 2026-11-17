"""Configuration catalog / helper whitelist / relay generation tests (no Postfix needed)."""

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pfhop.postfix import catalog  # noqa: E402
from pfhop import relays  # noqa: E402


def _helper_editable() -> set:
    tree = ast.parse((ROOT / "helper" / "pfhop-helper").read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "EDITABLE_PARAMS" for t in node.targets):
            return set(ast.literal_eval(node.value))
    raise AssertionError("EDITABLE_PARAMS not found in helper")


def test_catalog_matches_helper_whitelist():
    allowed = _helper_editable()
    missing = set(catalog.ALL_PARAMS) - allowed
    assert not missing, f"catalog params not allowed by helper: {missing}"
    assert set(relays.ROUTING_PARAMS) <= allowed


def test_size_roundtrip():
    f = catalog.ALL_PARAMS["message_size_limit"]
    assert catalog.from_form(f, "20") == str(20 * 1048576)
    assert catalog.to_display(f, str(20 * 1048576)) == "20"
    assert catalog.from_form(f, "") is None
    assert catalog.validate_raw(f, "10240000") == "10240000"


def test_time_and_bool_validation():
    t = catalog.ALL_PARAMS["maximal_queue_lifetime"]
    assert catalog.from_form(t, "5d") == "5d"
    for bad in ("5 days", "-1", "1x"):
        try:
            catalog.from_form(t, bad)
        except catalog.ValueError_:
            continue
        raise AssertionError(f"accepted {bad!r}")
    b = catalog.ALL_PARAMS["disable_vrfy_command"]
    assert catalog.from_form(b, "yes") == "yes"


def test_rule_normalisation():
    assert relays.normalize_rule("sender", "User@Example.com") == "user@example.com"
    assert relays.normalize_rule("domain", "Example.COM") == "@example.com"
    assert relays.normalize_rule("client", "10.1.2.3") == "10.1.2.3"
    assert relays.normalize_rule("client", "10.1.2.7/24") == "10.1.2.0/24"
    assert relays.normalize_rule("sender", "<>") == "<>"


def test_strip_client_check():
    v = "check_client_access cidr:/etc/postfix/pfhop/client_relay.cidr permit_mynetworks reject"
    assert relays._strip_client_check(v) == "permit_mynetworks reject"


def test_route_strings():
    """Direct delivery routes must end with ':' (FILTER without it is ignored by Postfix)."""
    base = dict(id=1, slug="x", name="X", host="smtp.example.com", port=587, mx_lookup=False, tls_level="may",
                auth_user="", auth_pass="", concurrency=None, rate_delay="", is_default=False, description="")
    assert relays.Relay(kind="smtp", **base).route == "pfr_x:[smtp.example.com]:587"
    assert relays.Relay(kind="direct", **dict(base, host="")).route == "pfr_x:"
    assert relays.Relay(kind="discard", **base).route == "discard:"


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
