"""Endpoints for the generated client configs, the profile one-click and Reality ops.

The base64 body is the contract with every app on earth, so two of these tests pin
it: one proves a client that sends no `Accept`/no `format` still gets byte-identical
output, the other proves an unknown `?format=` falls back to it instead of answering
JSON. Everything else here is about the *new* surfaces.
"""
import base64
import json

import pytest

TUNING_KEYS = ("operator_profile", "vision_enabled", "sockopt_enabled", "xhttp_mode",
               "xhttp_padding", "xhttp_xmux", "client_fragment_enabled", "fragment_enabled")


@pytest.fixture()
def restore_settings(db):
    snapshot = {k: db.get_settings().get(k) for k in TUNING_KEYS}
    yield
    db.set_settings({k: v for k, v in snapshot.items() if v is not None})


def test_singbox_config_is_served_for_a_user(client, make_user):
    u = make_user(name="sb-user", protocol="vless", transport="xhttp", security="tls")
    r = client.get(f"/sub/{u['uid']}/singbox.json")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("application/json")
    assert 'attachment; filename="titan-' in r.headers["content-disposition"]
    doc = json.loads(r.text)
    tags = [o["tag"] for o in doc["outbounds"]]
    assert "proxy" in tags and "direct" in tags
    entry = next(o for o in doc["outbounds"] if o.get("server"))
    assert entry["uuid"] == u["uuid"]
    assert entry["tls"]["enabled"] is True
    assert entry["transport"]["type"] == "http"           # sing-box name for xhttp
    assert "flow" not in entry, "Vision must not appear on a non-TCP transport"
    assert doc["route"]["rules"][0]["action"] == "sniff"


def test_headers_say_private(client, make_user):
    u = make_user(name="sb-hdr")
    r = client.get(f"/sub/{u['uid']}/xray.json")
    assert r.headers["Cache-Control"] == "no-store"
    assert "noindex" in r.headers["X-Robots-Tag"]
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    # the usage header still travels: it is what the app shows after an import
    assert "Subscription-Userinfo" in r.headers


def test_base64_body_is_untouched_by_the_new_routes(client, make_user):
    u = make_user(name="b64-intact", protocol="vless", transport="ws", security="tls")
    plain = client.get(f"/sub/{u['uid']}")
    assert plain.status_code == 200
    assert plain.headers["content-type"].startswith("text/plain")
    body = base64.b64decode(plain.text).decode().splitlines()
    assert any(l.startswith("vless://") for l in body)
    # The base64 body is the JSON view's links plus the usage-remark line and
    # nothing else - the exact bytes every app has always parsed.
    js = client.get(f"/sub/{u['uid']}/json").json()
    assert [l for l in body if "00000000-0000-0000-0000" not in l] == js["links"]
    assert len(body) == len(js["links"]) + 1
    # and the generated file must not turn that decoration into an outbound
    doc = client.get(f"/sub/{u['uid']}/singbox.json").json()
    assert all(o.get("server") != "127.0.0.1" for o in doc["outbounds"]), doc["outbounds"]


@pytest.mark.parametrize("bad", ["xml", "yaml", "", "singbox.json"])
def test_unknown_format_falls_back_to_the_subscription_body(client, make_user, bad):
    u = make_user(name="b64-fallback")
    r = client.get(f"/sub/{u['uid']}?format={bad}")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    assert base64.b64decode(r.text).decode().strip()


def test_profile_query_changes_the_file_not_the_database(client, db, make_user,
                                                         restore_settings):
    u = make_user(name="prof-user", protocol="vless", transport="xhttp", security="tls")
    before = db.get_settings()["operator_profile"]
    cl_gen = client.get(f"/sub/{u['uid']}/clash.yaml").text
    cl_mci = client.get(f"/sub/{u['uid']}/clash.yaml?profile=mci").text
    assert "ipv6: true" in cl_gen, cl_gen[:200]
    assert "ipv6: false" in cl_mci, cl_mci[:200]
    # a query param must never write: the stored profile is exactly what it was
    assert db.get_settings()["operator_profile"] == before
    sb = client.get(f"/sub/{u['uid']}/singbox.json?profile=irancell").json()
    tls = sb["outbounds"][1]["tls"]
    assert tls["fragment"] is True and tls["record_fragment"] is True


def test_group_subscription_gets_the_same_formats(client, make_user, admin):
    members = [make_user(name=f"g-{i}", protocol="vless", transport="ws", security="tls")
               for i in range(2)]
    r = admin.post("/api/subscriptions", headers={"Origin": "http://testserver"},
                   json={"name": "tuning group", "member_uids": [m["uid"] for m in members]})
    assert r.status_code == 200, r.text
    skey = r.json()["subscription"]["skey"]
    sid = r.json()["subscription"]["id"]
    try:
        doc = client.get(f"/sub/{skey}/singbox.json").json()
        assert len([o for o in doc["outbounds"] if o.get("server")]) == 2
        assert client.get(f"/sub/{skey}/clash.yaml").status_code == 200
    finally:
        admin.delete(f"/api/subscriptions/{sid}")


def test_tuning_api_describes_and_applies(admin, db, restore_settings):
    d = admin.get("/api/tuning").json()
    assert set(d) >= {"profile", "sockopt", "xhttp", "fragment", "vision", "warn"}
    assert "tcpMss" not in json.dumps(d)

    r = admin.post("/api/tuning/apply", headers={"Origin": "http://testserver"},
                   json={"profile": "mci", "sockopt_enabled": True})
    assert r.status_code == 200, r.text
    assert db.get_settings()["operator_profile"] == "mci"
    assert r.json()["applied"]["sockopt"]["domainStrategy"] == "UseIPv4"

    bad = admin.post("/api/tuning/apply", headers={"Origin": "http://testserver"},
                     json={"profile": "ttp"})
    assert bad.status_code == 400


def test_settings_rejects_junk_tuning_values(admin, db, restore_settings):
    r = admin.post("/api/settings", headers={"Origin": "http://testserver"}, json={
        "operator_profile": "sky", "xhttp_mode": "teleport", "tcp_congestion": "bbq",
        "xhttp_padding": "; rm -rf", "tcp_keepalive_idle": "not-a-number",
    })
    assert r.status_code == 200
    s = r.json()["settings"]
    assert s["operator_profile"] != "sky"
    assert s["xhttp_mode"] not in ("teleport",)
    assert s["tcp_congestion"] in ("bbr", "cubic", "reno", "")
    assert s["xhttp_padding"] in ("", None)
    assert int(s["tcp_keepalive_idle"]) == int(s["tcp_keepalive_idle"])


def test_reality_status_and_rotate(admin, db):
    st = admin.get("/api/reality/status").json()
    assert set(st) >= {"pub", "sid", "sni", "dest", "accepting_sids", "candidates"}
    assert st["candidates"], "the UI needs at least one suggestion"
    saved_sid = db.get_meta("reality_sid")
    saved_list = db.get_meta("reality_sids")
    try:
        r = admin.post("/api/reality/rotate", headers={"Origin": "http://testserver"},
                       json={"count": 1})
        assert r.status_code == 200, r.text
        assert r.json()["short_id"]["sid"] in r.json()["short_id"]["accepting"]
        nothing = admin.post("/api/reality/rotate", headers={"Origin": "http://testserver"},
                              json={})
        assert nothing.status_code == 400
    finally:
        db.set_meta("reality_sid", saved_sid or "")
        db.set_meta("reality_sids", saved_list or "")


def test_probe_never_hangs_on_a_dead_dest(client, admin):
    """`suggest()` is a network call: it must answer, not wedge the request."""
    from app import reality
    out = reality._raw_probe("127.0.0.1", 1, timeout=0.5)
    assert out["ok"] is False and out["reason"]
    res = admin.post("/api/reality/suggest", headers={"Origin": "http://testserver"}, json={})
    assert res.status_code == 200
    assert isinstance(res.json()["results"], list)


def test_config_routes_are_reachable_without_login(client):
    """A subscriber must never be asked to authenticate for their own file."""
    assert client.get("/sub/nosuchkey/singbox.json").status_code == 404


def test_tuning_requires_auth(client):
    client.cookies.clear()
    assert client.get("/api/tuning").status_code in (401, 403)
