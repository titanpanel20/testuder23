"""First-run credentials: who may log in before a password exists, and for how long.

The panel still creates `TiTaN` with no password so a fresh deploy is reachable
(that was an explicit product decision), but these tests pin the three things
that make it survivable on a public URL:

* the default login accepts *only* an empty password, never "any password";
* the window is bounded by TITAN_DEFAULT_LOGIN_HOURS and measured from the
  moment the default admin was created, so nobody gets a fresh grace period by
  redeploying an unclaimed panel;
* TITAN_ADMIN_PASSWORD closes the window at boot and doubles as the way back in.
"""
import os
import time

import pytest


@pytest.fixture()
def first_run_state(client, db):
    """Put the panel in exactly the fresh-deploy state and restore it after."""
    from app import security

    def _reset():
        empty = security.hash_password("")
        db.set_admin("TiTaN", empty["hash"], empty["salt"])
        db.set_meta("auth_is_default", "1")
        db.set_meta("auth_default_since", str(time.time()))
        for key in [k for (k,) in db._connect().execute(
                "SELECT key FROM meta WHERE key LIKE 'login_attempts%'")]:
            db.set_meta(key, '{"count": 0, "locked_until": 0}')
        client.cookies.clear()

    _reset()
    yield client
    _reset()


def test_default_login_accepts_only_an_empty_password(first_run_state):
    c = first_run_state
    assert c.post("/api/login", json={"username": "TiTaN", "password": ""}).status_code == 200
    # "any password worked" was the bug: the documented username alone was enough
    r = c.post("/api/login", json={"username": "TiTaN", "password": "hunter2"})
    assert r.status_code == 401, r.text
    assert c.post("/api/login", json={"username": "root", "password": ""}).status_code == 401


def test_window_closes_after_the_configured_hours(first_run_state, db, monkeypatch):
    from app import config

    monkeypatch.setattr(config, "DEFAULT_LOGIN_HOURS", 24.0)
    db.set_meta("auth_default_since", str(time.time() - 25 * 3600))
    r = first_run_state.post("/api/login", json={"username": "TiTaN", "password": ""})
    assert r.status_code == 403, r.text
    assert "TITAN_ADMIN_PASSWORD" in r.text
    # a redeploy must not hand out a fresh grace period
    assert db.get_meta("auth_default_since") and float(db.get_meta("auth_default_since")) < time.time() - 24 * 3600


def test_hours_zero_means_no_default_login_at_all(first_run_state, monkeypatch):
    from app import config
    monkeypatch.setattr(config, "DEFAULT_LOGIN_HOURS", 0.0)
    r = first_run_state.post("/api/login", json={"username": "TiTaN", "password": ""})
    assert r.status_code == 403, r.text


def test_negative_hours_keeps_the_legacy_open_window(first_run_state, monkeypatch):
    from app import config
    monkeypatch.setattr(config, "DEFAULT_LOGIN_HOURS", -1.0)
    assert first_run_state.post("/api/login", json={"username": "TiTaN", "password": ""}).status_code == 200


def test_env_password_closes_the_window_and_recovers_access(first_run_state, db, monkeypatch):
    from app import config

    monkeypatch.setattr(config, "ADMIN_PASSWORD", "a-long-enough-pass")
    assert db.apply_env_admin_password() is True
    assert db.get_meta("auth_is_default") == "0"
    c = first_run_state
    c.cookies.clear()
    assert c.post("/api/login", json={"username": "TiTaN", "password": ""}).status_code == 401
    assert c.post("/api/login", json={"username": "TiTaN",
                                       "password": "a-long-enough-pass"}).status_code == 200
    # and the empty env value never touches anything
    monkeypatch.setattr(config, "ADMIN_PASSWORD", "")
    assert db.apply_env_admin_password() is False


def test_a_short_env_password_is_refused_not_applied(first_run_state, db, monkeypatch):
    """A 3-character password reached through the same public URL is worse than
    the window it would close, so it is ignored (and logged) instead."""
    from app import config
    monkeypatch.setattr(config, "ADMIN_PASSWORD", "abc")
    assert db.apply_env_admin_password() is False
    assert db.get_meta("auth_is_default") == "1"
    assert first_run_state.post("/api/login", json={"username": "TiTaN", "password": ""}).status_code == 200


def test_setup_claim_works_only_inside_the_window(first_run_state, db):
    c = first_run_state
    c.cookies.clear()
    r = c.post("/api/setup", json={"username": "owner_1", "password": "picked-a-real-pass"})
    assert r.status_code == 200, r.text
    assert db.get_meta("auth_is_default") == "0"
    assert c.post("/api/login", json={"username": "owner_1",
                                      "password": "picked-a-real-pass"}).status_code == 200
    # claimed panels cannot be re-claimed
    db.set_meta("auth_is_default", "1")
    db.set_meta("auth_default_since", str(time.time() - 99 * 3600))
    assert c.post("/api/setup", json={"username": "attacker",
                                      "password": "another-pass"}).status_code == 403


def test_setup_status_and_me_tell_the_truth(first_run_state, db):
    c = first_run_state
    st = c.get("/api/setup-status").json()
    assert st["needs_setup"] is True and st["default_auth"] is True
    assert st["default_login_open"] is True
    assert st["default_login_seconds_left"] and st["default_login_seconds_left"] > 23 * 3600
    me = c.get("/api/me").json()
    assert me["default_auth"] is True and me["default_login_open"] is True

    db.set_meta("auth_default_since", str(time.time() - 25 * 3600))
    st = c.get("/api/setup-status").json()
    assert st["needs_setup"] is True and st["default_login_open"] is False
    assert st["default_login_seconds_left"] == 0
    # login.js reveals the password field off this flag, so a closed window must
    # not leave the operator with a form that cannot type a password
    assert c.get("/api/me").json()["default_login_open"] is False


def test_hours_env_typo_does_not_break_the_boot():
    """A bad number in the environment must not kill startup.

    Import-time exceptions are how this panel first died on Railway with nothing
    but a platform error page, so the parser degrades to the default and warns.
    """
    from app import config

    os.environ["TITAN_DEFAULT_LOGIN_HOURS"] = "two-days"
    try:
        assert config._hours_env("TITAN_DEFAULT_LOGIN_HOURS", 24.0) == 24.0
    finally:
        del os.environ["TITAN_DEFAULT_LOGIN_HOURS"]
    assert config._hours_env("TITAN_DEFAULT_LOGIN_HOURS", 24.0) == 24.0   # unset
    os.environ["TITAN_DEFAULT_LOGIN_HOURS"] = "6"
    try:
        assert config._hours_env("TITAN_DEFAULT_LOGIN_HOURS", 24.0) == 6.0
    finally:
        del os.environ["TITAN_DEFAULT_LOGIN_HOURS"]
