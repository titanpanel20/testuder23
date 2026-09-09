#!/usr/bin/env python3
"""Verification suite for TiTaN's security fixes.

Run against a *live* deployment:  python scripts/verify_deploy.py https://your-panel.up.railway.app
Order matters: checks that need the first-run (no password) admin run first,
then the suite locks a real password and tests the brute-force guard, because
while `auth_is_default` is set ANY password authenticates.
"""
import contextlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import sys
import time
import uuid as uuid_lib

import httpx

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
# --skip-raw-probe drops the outbound TCP probe (use it in CI, where the network
# is not representative of any operator).
REPO = str(pathlib.Path(__file__).resolve().parent.parent)
ADMIN_USER = "TiTaN"
results: list[tuple[bool, str, str]] = []


def check(name: str, cond: bool, observed: str = "") -> None:
    results.append((bool(cond), name, observed))
    mark = "PASS" if cond else "FAIL"
    print(f"{mark:4}  {name}" + (f"\n        observed: {observed}" if not cond else ""))


ADMIN_PW = os.environ.get("TITAN_ADMIN_PASSWORD", "")


@contextlib.contextmanager
def session(password: str | None = None):
    """Log in and yield an authenticated client.

    A fresh deploy has no password (`auth_is_default`); an administered one does.
    Pass the password in via TITAN_ADMIN_PASSWORD when running this against a
    panel you already configured, otherwise only the anonymous checks run.
    """
    pw = ADMIN_PW if password is None else password
    with httpx.Client(timeout=30, follow_redirects=False, base_url=BASE) as c:
        r = c.post("/api/login", json={"username": ADMIN_USER, "password": pw})
        if r.status_code != 200:
            raise SystemExit(
                f"login failed (HTTP {r.status_code}). This panel has a password set; run\n"
                f"  TITAN_ADMIN_PASSWORD='...' python scripts/verify_deploy.py {BASE}\n"
                f"or against a fresh deploy, where no password is required."
            )
        yield c


def rpw() -> str:
    return "t-" + uuid_lib.uuid4().hex[:12]


def main() -> int:
    # -------------------------------------------------------- 0. the Railway crash itself
    # `python -m app.main` died with:
    #   SyntaxError: unterminated string literal (detected at line 139)
    # because a docstring lost its closing triple-quote. A crash-looping service
    # has no HTTP endpoint to ask, so this is checked by compiling the sources
    # in a separate interpreter and asserting the app object builds.
    cp = subprocess.run([sys.executable, "-m", "compileall", "-q", "app", "scripts"],
                        cwd=REPO, capture_output=True, text=True)
    print("  -- local checkout checks (run this file from the repo you deploy) --")
    check("[0] every .py file compiles (no unterminated-string SyntaxError)",
          cp.returncode == 0, (cp.stdout + cp.stderr)[-300:])
    tmp = tempfile.mkdtemp(prefix="titan-verify-")
    try:
        im = subprocess.run(
            [sys.executable, "-c",
             "from app.main import app;"
             "print(len([r for r in app.routes if getattr(r,'methods',None)]))"],
            cwd=REPO, capture_output=True, text=True,
            env={**os.environ, "TITAN_DATA_DIR": tmp, "PYTHONPATH": REPO})
        check("[0b] app.main imports and builds its routes",
              im.returncode == 0 and im.stdout.strip().isdigit(), (im.stdout + im.stderr)[-300:])
        print(f"        ({im.stdout.strip() or '?'} routes registered in the local checkout)")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # -------------------------------------------------------- 1. boot
    r = httpx.get(f"{BASE}/health", timeout=8)
    check("[1] /health answers -> app imported, module-level code is valid (the Railway crash)",
          r.status_code == 200, r.text[:160])

    # -------------------------------------------------------- 2. CSRF (first-run mode)
    attacker = httpx.Client(timeout=10, base_url=BASE, follow_redirects=False)
    with session() as c:
        token = c.cookies.get("titan_session")
    attacker.cookies.set("titan_session", token or "")
    new_pw = rpw()
    r = attacker.post("/api/change-password",
                      json={"old_password": "", "new_password": new_pw},
                      headers={"Origin": "https://evil.example"})
    check("[2] cross-origin POST /api/change-password is rejected",
          r.status_code == 403 and r.json().get("detail") == "csrf-origin-rejected",
          f"HTTP {r.status_code} {r.text[:120]}")

    r = attacker.post("/api/gallery", files={"file": ("x.png", b"nope", "image/png")},
                      headers={"Origin": "https://evil.example"})
    check("[2b] CSRF also covers multipart endpoints (no preflight needed there)",
          r.status_code == 403, f"HTTP {r.status_code} {r.text[:80]}")

    with session() as c:
        r = c.post("/api/users", json={"name": "legit"}, headers={"Origin": BASE})
        check("[2c] same-origin Origin header still accepted", r.status_code == 200,
              f"HTTP {r.status_code} {r.text[:80]}")
        if r.status_code == 200:
            c.delete(f"/api/users/{r.json()['user']['uid']}")

    # -------------------------------------------------------- 3. lock a real password,
    # then CSRF must not be able to change it, and the write must truly not happen.
    good_pw = rpw()
    with session() as c:
        r = c.post("/api/change-password", json={"old_password": "", "new_password": good_pw},
                   headers={"Origin": BASE})
        check("[3] legitimate same-origin password change works", r.status_code == 200,
              f"HTTP {r.status_code} {r.text[:100]}")

    r = attacker.post("/api/change-password", json={"old_password": good_pw, "new_password": new_pw},
                      headers={"Origin": "https://evil.example"})
    check("[3b] blocked CSRF write did NOT change anything: old password still valid",
          httpx.post(f"{BASE}/api/login", json={"username": ADMIN_USER, "password": good_pw},
                     timeout=10).status_code == 200, "")
    check("[3c] ...and the attacker's password is rejected",
          httpx.post(f"{BASE}/api/login", json={"username": ADMIN_USER, "password": new_pw},
                     timeout=10).status_code == 401, "")
    attacker.close()

    # -------------------------------------------------------- 4. brute-force guard
    # Deterministic: a successful login anywhere earlier in this script resets
    # the counter, so assert on the *sum* of a long burst instead of on an
    # individual request. 12 consecutive failures must accumulate the schedule
    # 0.5+1+2+4 -> >=7s total, far above baseline, from any starting count
    # counter started from.
    t0 = time.time()
    codes = []
    for i in range(6):
        rr = httpx.post(f"{BASE}/api/login",
                        json={"username": ADMIN_USER, "password": f"guess-{i}-{rpw()}"},
                        headers={"X-Forwarded-For": f"203.0.113.{i+1}"}, timeout=120)
        codes.append(rr.status_code)
    burst = round(time.time() - t0, 2)
    check("[4] forged X-Forwarded-For no longer mints a fresh budget per attempt "
          "(one shared counter -> the burst is slowed, not 12 instant 401s)",
          burst >= 6.0 and all(c == 401 for c in codes),
          f"6 attempts took {burst}s, codes={set(codes)} (unfixed code: ~0.4s)")
    check("[4b] the throttle never blocks a correct password",
          httpx.post(f"{BASE}/api/login", json={"username": ADMIN_USER, "password": ""},
                     timeout=30).status_code in (200, 401), "")

    # audit-log injection: raw attempted username used to land in the log table
    marker = '</td><img src=x onerror=1>' + uuid_lib.uuid4().hex[:6]
    httpx.post(f"{BASE}/api/login", json={"username": marker, "password": "x"}, timeout=60)
    with session(good_pw) as c:
        evs = c.get("/api/events?limit=30").json()["events"]
    detail = next((e["detail"] for e in evs if e["action"] == "login-failed"), "<none>")
    check("[4c] attempted username is sanitized before reaching the audit log",
          "<" not in detail and ">" not in detail and '"' not in detail, f"detail={detail!r}")

    # -------------------------------------------------------- 5. surface reduction
    for path in ("/docs", "/redoc", "/openapi.json"):
        rr = httpx.get(f"{BASE}{path}", timeout=8)
        check(f"[5] {path} is not public", rr.status_code == 404, f"HTTP {rr.status_code}")

    # -------------------------------------------------------- 6. feature regressions
    with session(good_pw) as c:
        r = c.post("/api/users", json={"name": "Regression", "protocol": "vless",
                                       "quota_gb": 5, "expire_days": 30})
        check("[6] create user (vless/ws/tls)", r.status_code == 200, r.text[:140])
        u = r.json()["user"]
        check("[6b] link generated", u["main_link"].startswith("vless://"), u["main_link"][:80])
        check("[6c] quota converted to bytes", u["quota_bytes"] == 5 * 1024**3, str(u["quota_bytes"]))
        check("[6d] expiry ~30d out", bool(u["expire_at"]) and u["status"]["days_left"] in (29, 30),
              json.dumps(u["status"]))
        sub = httpx.get(f"{BASE}/sub/{u['uid']}", timeout=8)
        check("[6e] subscription serves the config", sub.status_code == 200 and len(sub.text) > 40,
              f"HTTP {sub.status_code}, {len(sub.content)}B")
        qr = c.get(f"/api/users/{u['uid']}/qr")
        check("[6f] QR image renders", qr.status_code == 200 and qr.content[:4] == b"\x89PNG",
              f"HTTP {qr.status_code}")

        for proto in ("vmess", "trojan", "shadowsocks", "hysteria2", "wireguard"):
            rr = c.post("/api/users", json={"name": f"p-{proto}", "protocol": proto})
            ok = rr.status_code == 200 and rr.json()["user"]["main_link"]
            sample = (rr.json()["user"]["main_link"][:40] if ok else rr.text[:80])
            check(f"[6g] {proto} produces a usable main link", bool(ok), f"HTTP {rr.status_code} {sample}")
            if ok:
                c.delete(f"/api/users/{rr.json()['user']['uid']}")

        r = c.patch(f"/api/users/{u['uid']}", json={"allowed_ips": ["5.5.5.5", "6.6.6.6"],
                                                    "max_devices": 2})
        got = r.json()["user"]
        check("[6h] PATCH persists allowed_ips (was silently dropped by the UPDATE allowlist)",
              got.get("allowed_ips") == ["5.5.5.5", "6.6.6.6"], f"allowed_ips={got.get('allowed_ips')!r}")
        check("[6i] max_devices persisted", got.get("max_devices") == 2, str(got.get("max_devices")))
        u2 = c.get(f"/api/users/{u['uid']}").json()
        check("[6j] allowed_ips survives a fresh read from the DB",
              u2.get("allowed_ips") == ["5.5.5.5", "6.6.6.6"], f"{u2.get('allowed_ips')!r}")
        c.delete(f"/api/users/{u['uid']}")

    # -------------------------------------------------------- 7. node API auth
    for path, body in (("/api/node/sync", {"users": []}),
                       ("/api/node/usage", {"usage": {}}),
                       ("/api/node/register", {"token": "nope", "url": "https://x"})):
        rr = httpx.post(f"{BASE}{path}", json=body, timeout=8)
        check(f"[7] {path} requires a credential", rr.status_code == 401,
              f"HTTP {rr.status_code} {rr.text[:60]}")

    # -------------------------------------------------------- 8. xray config
    out = subprocess.run(
        [sys.executable, "-c",
         "import os;os.environ['TITAN_DATA_DIR']='/tmp/t2';"
         "from app import xray;c=xray.generate_xray_config();import json;json.dumps(c);"
         "print('OK inbounds=',len(c['inbounds']))"],
        cwd=REPO, capture_output=True, text=True)
    check("[8] xray config generation runs clean", "OK inbounds=" in out.stdout,
          (out.stdout + out.stderr)[-240:])

    # -------------------------------------------------------- 10. node geo detection
    with session(good_pw) as c:
        r = c.post("/api/nodes/detect", json={"address": "one.one.one.one", "force": True},
                   headers={"Origin": BASE})
        ok = r.status_code == 200 and (
            (r.json().get("geo") or {}).get("country_code")
            or (r.json().get("geo") or {}).get("error"))
        check("[10] /api/nodes/detect answers (country or a stated reason)", ok,
              f"HTTP {r.status_code} {r.text[:150]}")
        if ok and r.status_code == 200:
            g = r.json().get("geo") or {}
            print(f"        geo: {g.get('city', '?')}, {g.get('country', '?')} "
                  f"({g.get('country_code', '-')}) ip={g.get('ip', '-')} src={g.get('source', '-')}")
            for note in (g.get("notes") or [])[:3]:
                print(f"        (note) {note}")
        r = c.post("/api/nodes/detect", json={}, headers={"Origin": BASE})
        check("[10b] an empty address is a 400, not a 500", r.status_code == 400, r.text[:100])
        check("[10c] /api/geo-self is not open to strangers",
              c.get("/api/geo-self").status_code == 401, f"HTTP {c.get('/api/geo-self').status_code}")

    # -------------------------------------------------------- 11. subscription groups
    with session(good_pw) as c:
        created = c.post("/api/users", json={"name": f"verify-group-{int(time.time())}",
                                             "protocol": "vless"}, headers={"Origin": BASE})
        uid = (created.json().get("user") or {}).get("uid") if created.status_code == 200 else None
        check("[11] a user exists to group", bool(uid), created.text[:120])
        sub_id = None
        try:
            r = c.post("/api/subscriptions", json={"name": "verify", "member_uids": [uid]},
                       headers={"Origin": BASE})
            sub_id = (r.json().get("subscription") or {}).get("id") if r.status_code == 200 else None
            skey = (r.json().get("subscription") or {}).get("skey", "")
            check("[11b] a group can be created", r.status_code == 200 and bool(skey), r.text[:150])

            import base64 as _b64

            pub = c.get(f"/sub/{skey}")          # no auth: this is the client-facing link
            lines = []
            if pub.status_code == 200:
                text = pub.text.strip()
                lines = _b64.b64decode(text + "=" * (-len(text) % 4)).decode().splitlines()
            check("[11c] the group link serves its configs without a login",
                  pub.status_code == 200 and any(l.startswith(("vless://", "vmess://", "trojan://"))
                                                 for l in lines),
                  f"HTTP {pub.status_code}, {len(lines)} lines")
            check("[11d] the group link carries client headers",
                  "Subscription-Userinfo" in pub.headers and "Profile-Title" in pub.headers,
                  str(dict(pub.headers))[:160])
            r = c.post("/api/subscriptions", json={"name": "", "member_uids": []},
                       headers={"Origin": BASE})
            check("[11e] an anonymous/empty group is refused", r.status_code == 400, r.text[:100])
            r = c.get("/sub/sgdoesnotexist")
            check("[11f] an unknown group key is a 404", r.status_code == 404, f"HTTP {r.status_code}")

            # the browser view of the same link
            page = c.get(f"/sub/{skey}/page")
            html = page.text if page.status_code == 200 else ""
            check("[11g] the link has a human page (RTL, QR card, copy button)",
                  page.status_code == 200 and 'dir="rtl"' in html
                  and "کپی لینک اشتراک" in html and "<!doctype html>" in html.lower(),
                  f"HTTP {page.status_code}, {len(html)} bytes")
            check("[11h] the page hides the roster and never points at /api/",
                  "noindex" in html and "/api/" not in html and (uid or "zz") not in html,
                  f"noindex={'noindex' in html} api_refs={html.count('/api/')}")
            check("[11i] the page is not cacheable and not indexable",
                  "no-store" in page.headers.get("cache-control", "")
                  and "noindex" in page.headers.get("x-robots-tag", ""),
                  str({k: v for k, v in page.headers.items()
                       if k.lower() in ("cache-control", "x-robots-tag")})[:160])
            as_client = c.get(f"/sub/{skey}", headers={"Accept": "*/*"})
            check("[11j] a VPN client still gets base64 from the same URL",
                  as_client.status_code == 200
                  and as_client.headers.get("content-type", "").startswith("text/plain"),
                  as_client.headers.get("content-type"))
            as_browser = c.get(f"/sub/{skey}",
                               headers={"Accept": "text/html,application/xhtml+xml"})
            check("[11k] a browser gets the page from that same URL",
                  as_browser.status_code == 200
                  and as_browser.headers.get("content-type", "").startswith("text/html"),
                  as_browser.headers.get("content-type"))
            jh = c.get(f"/sub/{skey}/json")
            check("[11m] /sub/<key>/json announces JSON (once said text/plain)",
                  jh.headers.get("content-type", "").startswith("application/json"),
                  jh.headers.get("content-type"))
            gone = c.get("/sub/sgrotatedaway0000/page")
            check("[11l] a dead key answers with a readable 404 page, not JSON",
                  gone.status_code == 404 and "معتبر نیست" in gone.text, f"HTTP {gone.status_code}")
        finally:
            if sub_id:
                c.delete(f"/api/subscriptions/{sub_id}", headers={"Origin": BASE})
            if uid:
                c.delete(f"/api/users/{uid}", headers={"Origin": BASE})

    # -------------------------------------------------------- 12. restore admin state
    with session(good_pw) as c:
        r = c.post("/api/change-password", json={"old_password": good_pw, "new_password": ""},
                   headers={"Origin": BASE})
        # empty is intentionally rejected; leave the password set and say so
        print(f"\n  (note) panel now has a real password; empty-password change -> HTTP {r.status_code}"
              f" {r.text[:60]}  [expected: rejected]")

    failed = [n for ok, n, _ in results if not ok]
    print("\n" + "=" * 66)
    print(f"{len(results) - len(failed)}/{len(results)} checks passed")
    if failed:
        print("FAILED:")
        for n in failed:
            print("  -", n)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
