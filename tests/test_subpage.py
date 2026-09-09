"""The public subscription page - the browser view of /sub/<key> and /sub/<key>/page.

Two invariants are worth locking down:

1. the split. A client that asks for a subscription must keep receiving base64;
   the HTML only appears when the visitor really asks for it.
2. the page shows nothing the base64 body does not already carry: no member
   roster, no user ids, no admin endpoints, no third-party asset.
"""
import base64

from fastapi.testclient import TestClient


def anon_client():
    """A client with no session cookie - what a subscriber's browser is."""
    from app.main import app
    return TestClient(app)


def _group(admin, make_user, **kw):
    users = kw.pop("users", None)
    if users is None:
        users = [make_user(name="sub-a", protocol="vless", transport="ws", security="tls")]
    r = admin.post("/api/subscriptions",
                   json={"name": kw.get("name", "صفحهٔ تست"), "member_uids": [u["uid"] for u in users],
                         "remark": kw.get("remark", "")},
                   headers={"Origin": "http://testserver"})
    assert r.status_code == 200, r.text
    return r.json()["subscription"], users


# --------------------------------------------------------------------- the split
def test_a_client_still_gets_base64_and_only_a_browser_gets_html(admin, make_user):
    sub, _ = _group(admin, make_user)
    key = sub["skey"]
    try:
        with anon_client() as anon:
            plain = anon.get(f"/sub/{key}")                      # Accept: */* (curl, apps)
            assert plain.status_code == 200
            assert plain.headers["content-type"].startswith("text/plain")
            base64.b64decode(plain.text.strip() + "==")          # still valid base64

            page = anon.get(f"/sub/{key}", headers={"Accept": "text/html,application/xhtml+xml"})
            assert page.status_code == 200
            assert page.headers["content-type"].startswith("text/html")
            assert 'dir="rtl"' in page.text
    finally:
        admin.delete(f"/api/subscriptions/{sub['id']}")


def test_page_route_works_for_a_group_and_for_a_single_user(admin, make_user):
    u = make_user(name="solo-viewer", protocol="trojan", transport="ws", security="tls")
    with anon_client() as anon:
        assert anon.get(f"/sub/{u['uid']}/page").status_code == 200
    sub, _ = _group(admin, make_user, users=[u])
    try:
        with anon_client() as anon:
            r = anon.get(f"/sub/{sub['skey']}/page")
            assert r.status_code == 200, r.text
            assert "solo-viewer" in r.text
            assert "noindex" in r.text
            # ... and the JSON sibling must announce JSON, not text/plain
            j = anon.get(f"/sub/{sub['skey']}/json")
            assert j.headers["content-type"].startswith("application/json"), j.headers.get("content-type")
    finally:
        admin.delete(f"/api/subscriptions/{sub['id']}")


# ------------------------------------------------------------------- what it hides
def test_page_shows_no_member_uids_and_no_admin_endpoints(admin, make_user):
    """A uid doubles as that member's own subscription key: printing it into a
    page that everyone in the group opens would hand out extra links."""
    users = [make_user(name=f"member-{i}", protocol="vless", transport="ws", security="tls")
             for i in range(3)]
    sub, _ = _group(admin, make_user, users=users)
    try:
        with anon_client() as anon:
            page = anon.get(f"/sub/{sub['skey']}/page").text
            for u in users:
                assert u["uid"] not in page, f"member key leaked into the page: {u['uid']}"
            assert "/api/" not in page                      # no admin endpoint to poke
            assert "flagcdn.com" not in page and "googleapis" not in page   # no third party
            assert 'src="/static/img/emblem.svg"' in page   # self-hosted assets only
    finally:
        admin.delete(f"/api/subscriptions/{sub['id']}")


def test_page_does_not_list_the_status_dummy_line_as_a_config(admin, make_user):
    """The base64 body carries one fake `vless://00000000...@127.0.0.1` line per
    member so clients can display usage; it is not a server anyone should dial."""
    sub, _ = _group(admin, make_user,
                    users=[make_user(name="d1", protocol="vless", transport="ws", security="tls"),
                           make_user(name="d2", protocol="vless", transport="ws", security="tls")])
    try:
        with anon_client() as anon:
            page = anon.get(f"/sub/{sub['skey']}/page").text
            assert "127.0.0.1:10001" not in page
            assert page.count('class="cfg"') == 2, page.count('class="cfg"')
    finally:
        admin.delete(f"/api/subscriptions/{sub['id']}")


def test_page_escapes_a_hostile_remark(admin, make_user):
    """Names and remarks end up in the link fragment and in the card title.

    Jinja escapes them, but this is the one place the panel prints admin-typed
    text to an unauthenticated audience, so the property is asserted, not trusted.
    """
    hostile = '<script>alert(1)</script>'
    u = make_user(name=hostile, protocol="vless", transport="ws", security="tls")
    sub, _ = _group(admin, make_user, users=[u], name=hostile)
    try:
        with anon_client() as anon:
            page = anon.get(f"/sub/{sub['skey']}/page").text
            assert "<script>alert(1)</script>" not in page
            assert "&lt;script&gt;" in page
    finally:
        admin.delete(f"/api/subscriptions/{sub['id']}")


# --------------------------------------------------------------------- the numbers
def test_page_shows_quota_and_expiry_from_the_same_data(admin, make_user):
    u = make_user(name="quota-view", protocol="vless", transport="ws", security="tls",
                  quota_gb=10, expire_days=30)
    sub, _ = _group(admin, make_user, users=[u])
    try:
        with anon_client() as anon:
            page = anon.get(f"/sub/{sub['skey']}/page").text
            assert "10.00 GB" in page                      # total, formatted server-side
            assert "data-ts=" in page                       # expiry handed to JS as a stamp
            info = anon.get(f"/sub/{sub['skey']}/json").json()
            assert info["total_bytes"] == 10 * 1024 ** 3
            assert info["days_left"] and info["days_left"] <= 30
    finally:
        admin.delete(f"/api/subscriptions/{sub['id']}")


def test_page_marks_a_group_without_live_members_inactive(admin, make_user):
    """Expired members are disabled by a background task; the badge must not wait
    for it, because the subscriber reads this page to find out if they ran out."""
    from app import db
    u = make_user(name="expired-view", protocol="vless", transport="ws", security="tls",
                  expire_days=1)
    db.update_user(u["uid"], {"expire_at": 1})            # already in the past
    sub, _ = _group(admin, make_user, users=[u])
    try:
        with anon_client() as anon:
            page = anon.get(f"/sub/{sub['skey']}/page").text
            assert "غیرفعال" in page
            assert 'class="chip r"' in page
    finally:
        db.update_user(u["uid"], {"expire_at": None})
        admin.delete(f"/api/subscriptions/{sub['id']}")


# ----------------------------------------------------------------------- failures
def test_unknown_or_rotated_key_gets_a_readable_404_page(admin):
    with anon_client() as anon:
        r = anon.get("/sub/sghostkey00000/page", headers={"Accept": "text/html"})
        assert r.status_code == 404
        assert r.headers["content-type"].startswith("text/html")
        assert "لینک" in r.text and "معتبر نیست" in r.text


def test_disabled_group_has_no_page(admin, make_user):
    from app import db
    sub, _ = _group(admin, make_user)
    try:
        db.update_subscription(sub["id"], {"enabled": 0})
        with anon_client() as anon:
            assert anon.get(f"/sub/{sub['skey']}/page").status_code == 404
    finally:
        admin.delete(f"/api/subscriptions/{sub['id']}")


def test_page_survives_a_missing_qrcode_library(admin, make_user, monkeypatch):
    """QR is a nicety; without Pillow/qrcode the link page must still work."""
    from app import subpage
    monkeypatch.setattr(subpage, "_qrcode", None)
    sub, _ = _group(admin, make_user)
    try:
        with anon_client() as anon:
            r = anon.get(f"/sub/{sub['skey']}/page")
            assert r.status_code == 200, r.text[:200]
            assert "data:image/png;base64," not in r.text
            assert "کپی لینک اشتراک" in r.text
    finally:
        admin.delete(f"/api/subscriptions/{sub['id']}")


def test_empty_group_page_explains_itself(admin):
    r = admin.post("/api/subscriptions", json={"name": "خالی", "member_uids": []},
                   headers={"Origin": "http://testserver"})
    sub = r.json()["subscription"]
    try:
        with anon_client() as anon:
            page = anon.get(f"/sub/{sub['skey']}/page").text
            assert "کانفیگی برای این لینک ساخته نشده" in page
    finally:
        admin.delete(f"/api/subscriptions/{sub['id']}")
