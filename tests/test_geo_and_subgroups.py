"""Node auto-location (app/geo.py) and subscription groups (/sub/<skey>).

The conftest autouse fixture blocks real DNS + HTTP for every test, so these
tests stub `geo.http_json` / `geo.resolve_ip` explicitly - which is also how a
provider outage is simulated.
"""
import base64
import json

import pytest

from app import geo

from fastapi.testclient import TestClient


def anon_client():
    """A client with no session cookie, for the public /sub links."""
    from app.main import app
    return TestClient(app)

# --------------------------------------------------------------------- helpers
def _stub_network(monkeypatch, *, ip="185.12.84.10", payload=None, raise_on=None):
    """Deterministic resolve + provider answers."""
    answers = payload if payload is not None else {
        "https://ipwho.is/185.12.84.10": {"success": True, "city": "Frankfurt",
                                         "country": "Germany", "country_code": "DE",
                                         "connection": {"isp": "Hetzner"}}}

    def fake_resolve(host, timeout=2.5):
        return ip

    def fake_http_json(url, timeout=4.0, headers=None):
        if raise_on and raise_on in url:
            raise AssertionError("provider down")
        if url in answers:
            return answers[url]
        raise AssertionError(f"unexpected url {url}")

    monkeypatch.setattr(geo, "resolve_ip", fake_resolve)
    monkeypatch.setattr(geo, "http_json", fake_http_json)


# ------------------------------------------------------------------ primitives
def test_clean_host_strips_scheme_userinfo_and_port():
    assert geo.clean_host("  https://u:p@FR1.Hetzner.COM:8443/path?x=1 ") == "fr1.hetzner.com"
    assert geo.clean_host("http://[2001:db8::1]:443") == "2001:db8::1"
    assert geo.clean_host("plain.example.com") == "plain.example.com"
    assert geo.clean_host(None) == ""


def test_flag_from_code_only_accepts_real_codes():
    assert geo.flag_from_code("de") == "🇩🇪"
    assert geo.flag_from_code("IR") == "🇮🇷"
    assert geo.flag_from_code("iran") == "🏳️"
    assert geo.flag_from_code("") == "🏳️"


def test_private_and_loopback_addresses_are_never_queried(monkeypatch):
    calls = []
    monkeypatch.setattr(geo, "http_json",
                        lambda *a, **k: calls.append(a) or {})
    for bad in ("127.0.0.1", "10.0.0.5", "192.168.1.9", "169.254.1.1", "localhost"):
        out = geo.detect(bad)
        assert out.get("error") in ("non-public-ip", "unresolved"), (bad, out)
    assert calls == []


def test_invalid_input_is_an_error_not_a_crash():
    for bad in ("", None, "not a host !!", "http://", "a..b"):
        assert "error" in geo.detect(bad) or geo.detect(bad).get("country_code")


# ------------------------------------------------------------------- detection
def test_detect_fills_city_country_flag_from_the_first_provider(monkeypatch):
    _stub_network(monkeypatch)
    out = geo.detect("fr1.hetzner.example", force=True)
    assert out["country_code"] == "DE"
    assert out["city"] == "Frankfurt" and out["country"] == "Germany"
    assert out["flag"] == "🇩🇪"
    assert out["source"] == "ip:ipwho.is" and out["ip"] == "185.12.84.10"
    assert out["notes"] == []


def test_detect_falls_through_to_the_next_provider(monkeypatch):
    _stub_network(monkeypatch, raise_on="ipwho.is", payload={
        "http://ip-api.com/json/185.12.84.10?fields=status,country,countryCode,city,connection": {
            "status": "success", "country": "Germany", "countryCode": "DE", "city": "Nuremberg"}})
    out = geo.detect("fr1.hetzner.example", force=True)
    assert out["country_code"] == "DE" and out["city"] == "Nuremberg"
    assert out["source"] == "ip:ip-api"


def test_when_every_provider_fails_the_caller_gets_an_error(monkeypatch):
    _stub_network(monkeypatch, payload={})
    monkeypatch.setattr(geo, "http_json", lambda *a, **k: (_ for _ in ()).throw(OSError("down")))
    out = geo.detect("fr1.hetzner.example", force=True)
    assert out == {"error": "provider-failed", "ip": "185.12.84.10",
                   "host": "fr1.hetzner.example", "notes": []}


def test_a_platform_domain_answer_is_flagged_as_untrustworthy(monkeypatch):
    """The bug this whole layer exists for: *.up.railway.app resolves to Railway's
    anycast, so 'US' is the platform's location, not the node's."""
    _stub_network(monkeypatch, payload={
        "https://ipwho.is/185.12.84.10": {"success": True, "city": "San Francisco",
                                        "country": "United States", "country_code": "US",
                                        "connection": {"isp": "Railway"}}})
    out = geo.detect("kind-spider-42.up.railway.app", force=True)
    assert out["country_code"] == "US"
    assert any("پلتفرم" in n for n in out["notes"]), out["notes"]


def test_a_cdn_origin_is_flagged_too(monkeypatch):
    _stub_network(monkeypatch, payload={
        "https://ipwho.is/185.12.84.10": {"success": True, "city": "Ashburn",
                                        "country": "United States", "country_code": "US",
                                        "connection": {"isp": "Cloudflare, Inc."}}})
    out = geo.detect("vpn.example.com", force=True)
    assert any("CDN" in n for n in out["notes"]), out["notes"]


def test_the_node_itself_wins_over_geoip(monkeypatch):
    """`GET /api/geo-self` on the node is ground truth - and it is tried first."""
    seen = []

    def fake_http_json(url, timeout=4.0, headers=None):
        seen.append((url, (headers or {}).get("X-Node-Token")))
        if url.endswith("/api/geo-self"):
            return {"city": "Helsinki", "country": "Finland", "country_code": "FI",
                    "ip": "198.51.100.9"}
        raise AssertionError("must not ask a provider when the node answers")

    monkeypatch.setattr(geo, "http_json", fake_http_json)
    out = geo.detect("node.example.com", token="tok-1", force=True)
    assert out["source"] == "node" and out["country_code"] == "FI"
    assert out["ip"] == "198.51.100.9"
    assert ("https://node.example.com/api/geo-self", "tok-1") in seen


def test_results_are_cached_per_host(monkeypatch, db):
    hits = []

    def fake_resolve(host, timeout=2.5):
        return "185.12.84.10"

    def fake_http_json(url, timeout=4.0, headers=None):
        hits.append(url)
        return {"success": True, "city": "Frankfurt", "country": "Germany",
                "country_code": "DE", "connection": {"isp": "Hetzner"}}

    monkeypatch.setattr(geo, "resolve_ip", fake_resolve)
    monkeypatch.setattr(geo, "http_json", fake_http_json)
    db.set_meta("geo:cached-host.example", json.dumps({"ts": __import__("time").time(),
                                                        "geo": {"country_code": "NL",
                                                                "country": "Netherlands",
                                                                "city": "Amsterdam",
                                                                "flag": "🇳🇱"}}))
    out = geo.detect("cached-host.example")
    assert out["country_code"] == "NL" and "cached" in out["source"]
    assert hits == []


# ------------------------------------------------------- node endpoints
def test_creating_a_node_auto_fills_the_flag(monkeypatch, admin):
    from app import main

    monkeypatch.setattr(main, "geo_detect", lambda *a, **k: {
        "city": "Frankfurt", "country": "Germany", "country_code": "DE", "flag": "🇩🇪",
        "source": "ip:ipwho.is", "notes": []})
    r = admin.post("/api/nodes", json={"name": "de-1", "address": "de1.example.com"},
                   headers={"Origin": "http://testserver"})
    assert r.status_code == 200, r.text
    node = r.json()["node"]
    assert node["country_code"] == "DE" and node["flag"] == "🇩🇪"
    assert node["city"] == "Frankfurt"
    admin.delete(f"/api/nodes/{node['id']}")


def test_an_explicit_country_code_wins_over_detection(monkeypatch, admin):
    from app import main

    def boom(*a, **k):
        raise AssertionError("must not query geo when the admin set a country")

    monkeypatch.setattr(main, "geo_detect", boom)
    r = admin.post("/api/nodes", json={"name": "ir-1", "address": "ir1.example.com",
                                      "country_code": "ir", "city": "Tehran"},
                   headers={"Origin": "http://testserver"})
    assert r.status_code == 200
    node = r.json()["node"]
    assert node["country_code"] == "IR" and node["flag"] == "🇮🇷"
    admin.delete(f"/api/nodes/{node['id']}")


def test_detect_endpoint_previews_without_writing(monkeypatch, admin):
    from app import main

    monkeypatch.setattr(main, "geo_detect", lambda *a, **k: {
        "city": "Paris", "country": "France", "country_code": "FR", "flag": "🇫🇷",
        "notes": ["a note"]})
    r = admin.post("/api/nodes/detect", json={"address": "https://par1.example.com:443/"},
                   headers={"Origin": "http://testserver"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True and body["geo"]["country_code"] == "FR"
    assert body["geo"]["host"] == "par1.example.com"
    assert body["geo"]["notes"] == ["a note"]
    assert admin.post("/api/nodes/detect", json={}, headers={"Origin": "http://testserver"}
                      ).status_code == 400


def test_relocate_endpoint_persists(monkeypatch, admin):
    from app import main

    created = admin.post("/api/nodes", json={"name": "old-loc", "address": "a.example.com",
                                            "country_code": "US"},
                         headers={"Origin": "http://testserver"})
    node_id = created.json()["node"]["id"]
    try:
        monkeypatch.setattr(main, "geo_detect", lambda *a, **k: {
            "city": "Tallinn", "country": "Estonia", "country_code": "EE", "flag": "🇪🇪",
            "notes": []})
        r = admin.post(f"/api/nodes/{node_id}/geo", json={},
                       headers={"Origin": "http://testserver"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["ok"] is True
        assert body["node"]["country_code"] == "EE" and body["node"]["flag"] == "🇪🇪"
    finally:
        admin.delete(f"/api/nodes/{node_id}")


def test_relocate_reports_when_it_cannot_find_anything(monkeypatch, admin):
    from app import main

    node_id = admin.post("/api/nodes", json={"name": "quiet", "address": "b.example.com",
                                            "country_code": "US"},
                         headers={"Origin": "http://testserver"}).json()["node"]["id"]
    try:
        monkeypatch.setattr(main, "geo_detect", lambda *a, **k: {"error": "provider-failed",
                                                                "notes": []})
        r = admin.post(f"/api/nodes/{node_id}/geo", json={}, headers={"Origin": "http://testserver"})
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is False and body["geo_notes"] == ["geo: provider-failed"]
        assert body["node"]["country_code"] == "US"      # nothing was overwritten
    finally:
        admin.delete(f"/api/nodes/{node_id}")


def test_geo_self_needs_the_node_credential_and_reports_the_node(admin, monkeypatch):
    from app import config

    monkeypatch.setattr(config, "NODE_TOKEN", "node-secret-1")
    monkeypatch.setattr(geo, "detect_self",
                        lambda: {"city": "Helsinki", "country": "Finland",
                                 "country_code": "FI", "flag": "\U0001F1EB\U0001F1EE",
                                 "ip": "198.51.100.9", "source": "ip:ipwho.is"})
    with anon_client() as anon:
        assert anon.get("/api/geo-self").status_code == 401
        assert anon.get("/api/geo-self", headers={"X-Node-Token": "wrong"}).status_code == 401
        r = anon.get("/api/geo-self", headers={"X-Node-Token": "node-secret-1"})
        assert r.status_code == 200, r.text
        assert r.json()["country_code"] == "FI" and r.json()["ip"] == "198.51.100.9"


# --------------------------------------------------------- subscription groups
@pytest.fixture()
def two_users(make_user):
    a = make_user(name="grp-a", protocol="vless", transport="ws", security="tls")
    b = make_user(name="grp-b", protocol="trojan", transport="ws", security="tls")
    return [a, b]


def test_group_endpoints_crud_and_public_link(admin, two_users):
    uids = [u["uid"] for u in two_users]
    r = admin.post("/api/subscriptions", json={"name": "Family", "member_uids": uids},
                   headers={"Origin": "http://testserver"})
    assert r.status_code == 200, r.text
    sub = r.json()["subscription"]
    assert sub["skey"].startswith("sg") and len(sub["skey"]) == 14
    url = r.json()["url"]
    assert url == f"/sub/{sub['skey']}"

    listing = admin.get("/api/subscriptions").json()
    row = next(x for x in listing["subscriptions"] if x["id"] == sub["id"])
    assert {m["name"] for m in row["members"]} == {"grp-a", "grp-b"}

    with anon_client() as anon:
        # the public link carries BOTH users' configs, with no login at all
        text = anon.get(url).text.strip()
        decoded = base64.b64decode(text + "=" * (-len(text) % 4)).decode()
        links = [l for l in decoded.splitlines() if l]
        assert any(l.startswith("vless://") for l in links), links
        assert any(l.startswith("trojan://") for l in links), links
        # one status/dummy line per member, so a client can show usage per config
        assert sum(1 for l in links if l.startswith("vless://00000000")) == 2, links

        info = anon.get(f"{url}/json").json()
        assert info["kind"] == "group" and len(info["links"]) == 2, info
        assert {m["name"] for m in info["members"]} == {"grp-a", "grp-b"}
        assert anon.get(f"{url}/base64").status_code == 200

    admin.delete(f"/api/subscriptions/{sub['id']}")
    with anon_client() as anon:
        assert anon.get(url).status_code == 404      # deleted group = dead link


def test_group_link_is_deduplicated_and_can_drop_info_lines(admin, make_user):
    from app import db

    # the same user twice must not produce the link twice
    u = make_user(name="dup", protocol="vless", transport="ws", security="tls")
    sub = admin.post("/api/subscriptions",
                     json={"name": "Dup", "member_uids": [u["uid"], u["uid"]],
                           "include_info": False},
                     headers={"Origin": "http://testserver"}).json()["subscription"]
    try:
        text = admin.get(f"/sub/{sub['skey']}").text.strip()
        body = base64.b64decode(text + "=" * (-len(text) % 4)).decode()
        lines = [l for l in body.splitlines() if l]
        assert len(lines) == 1, lines
        assert not any("00000000-0000" in l for l in lines)      # info lines off
    finally:
        admin.delete(f"/api/subscriptions/{sub['id']}")
    assert db.get_subscription(sub["id"]) is None


def test_disabled_member_and_disabled_group(admin, two_users):
    from app import db

    uids = [u["uid"] for u in two_users]
    sub = admin.post("/api/subscriptions", json={"name": "G", "member_uids": uids},
                     headers={"Origin": "http://testserver"}).json()["subscription"]
    try:
        db.update_user(two_users[1]["uid"], {"enabled": 0})
        names = {m["name"] for m in admin.get(f"/sub/{sub['skey']}/json").json()["members"]}
        assert names == {"grp-a"}                                # disabled member skipped

        db.update_subscription(sub["id"], {"enabled": 0})
        assert admin.get(f"/sub/{sub['skey']}").status_code == 404
    finally:
        db.update_user(two_users[1]["uid"], {"enabled": 1})
        admin.delete(f"/api/subscriptions/{sub['id']}")


def test_group_validation(admin, make_user):
    r = admin.post("/api/subscriptions", json={"member_uids": []},
                   headers={"Origin": "http://testserver"})
    assert r.status_code == 400 and "name-required" in r.text
    r = admin.post("/api/subscriptions", json={"name": "X", "member_uids": ["nope1234567890"]},
                   headers={"Origin": "http://testserver"})
    assert r.status_code == 400 and "unknown-users" in r.text
    r = admin.patch("/api/subscriptions/99999", json={"name": "x"},
                    headers={"Origin": "http://testserver"})
    assert r.status_code == 404


def test_rotating_the_key_kills_the_old_link(admin, two_users):
    sub = admin.post("/api/subscriptions",
                     json={"name": "Rot", "member_uids": [u["uid"] for u in two_users]},
                     headers={"Origin": "http://testserver"}).json()["subscription"]
    old = sub["skey"]
    try:
        new = admin.post(f"/api/subscriptions/{sub['id']}/rotate", json={},
                         headers={"Origin": "http://testserver"}).json()["subscription"]
        assert new["skey"] != old and len(new["skey"]) == 14
        with anon_client() as anon:
            assert anon.get(f"/sub/{old}").status_code == 404
            assert anon.get(f"/sub/{new['skey']}").status_code == 200
    finally:
        admin.delete(f"/api/subscriptions/{sub['id']}")


def test_a_user_subscription_still_works_and_cannot_be_shadowed(admin, make_user):
    u = make_user(name="solo", protocol="vless", transport="ws", security="tls")
    body = admin.get(f"/sub/{u['uid']}/json").json()
    assert body["protocol"] == "vless" and "kind" not in body       # plain user, unchanged shape
    assert body["links"]


def test_public_group_link_needs_no_auth_even_when_login_is_enforced(admin, two_users):
    sub = admin.post("/api/subscriptions",
                     json={"name": "Public", "member_uids": [u["uid"] for u in two_users]},
                     headers={"Origin": "http://testserver"}).json()["subscription"]
    try:
        # an unauthenticated client must still get the configs (that is the point
        # of a subscription link), and the headers clients read must be there
        with anon_client() as anon:
            r = anon.get(f"/sub/{sub['skey']}")
            assert r.status_code == 200, r.text
            assert "Subscription-Userinfo" in r.headers
            assert r.headers["Profile-Title"].startswith("base64:")
            assert "Public" in base64.b64decode(r.headers["Profile-Title"].split(":", 1)[1]).decode()
            # and the admin-only endpoints must still refuse it
            assert anon.get("/api/subscriptions").status_code == 401
    finally:
        admin.delete(f"/api/subscriptions/{sub['id']}")


def test_a_persian_group_name_still_serves_a_link(admin, make_user):
    """HTTP headers are latin-1: a Persian group name used to raise
    UnicodeEncodeError inside the response and the public link answered 500.

    This is the case the English-only tests could not see, so both the group name
    and the user name are non-ASCII here on purpose.
    """
    u = make_user(name="علی-مشتری", protocol="vless", transport="ws", security="tls")
    sub = admin.post("/api/subscriptions",
                     json={"name": "خانوادهٔ ما", "remark": "اشتراک مهمان", "member_uids": [u["uid"]]},
                     headers={"Origin": "http://testserver"}).json()["subscription"]
    try:
        with anon_client() as anon:
            r = anon.get(f"/sub/{sub['skey']}")
            assert r.status_code == 200, (r.status_code, r.text[:120])
            assert r.headers["Content-Type"].startswith("text/plain")
            title = base64.b64decode(r.headers["Profile-Title"].split(":", 1)[1]).decode()
            assert title == "خانوادهٔ ما"
            body = base64.b64decode(r.text.strip() + "=" * (-len(r.text.strip()) % 4)).decode()
            assert body.splitlines()                       # at least the config itself
            j = anon.get(f"/sub/{sub['skey']}/json").json()
            assert j["members"][0]["name"] == "علی-مشتری"
    finally:
        admin.delete(f"/api/subscriptions/{sub['id']}")
