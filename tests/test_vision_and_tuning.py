"""Vision has to be agreed by both ends, and the tuning has to reach the config.

These tests exist because the panel used to publish `flow=xtls-rprx-vision` in every
Reality link while `generate_xray_config()` never wrote a `flow` into the inbound's
client entry. That combination handshakes and then carries garbage - exactly the
"opens but has no traffic" report an operator gets - and nothing in the suite could
see it, because each side looked fine on its own. So the invariant tested here is
the *pair*: link flow == inbound flow, always.
"""
import pytest

from app import links, tuning, xray

PROFILE_KEYS = ("operator_profile", "vision_enabled", "sockopt_enabled", "xhttp_mode",
                "xhttp_padding", "xhttp_xmux", "tcp_congestion", "tcp_keepalive_idle",
                "tcp_user_timeout", "tcp_mptcp", "sniffing_enabled", "sniffing_route_only",
                "client_fragment_enabled", "fragment_enabled", "fragment_length",
                "fragment_interval", "wg_keepalive", "wg_mtu")


@pytest.fixture()
def settings_guard(db):
    """Settings are global; every test here changes them, so snapshot and restore."""
    snapshot = {k: db.get_settings().get(k) for k in PROFILE_KEYS}
    yield db
    db.set_settings({k: v for k, v in snapshot.items() if v is not None})


@pytest.fixture()
def reality_user(make_user):
    return make_user(name="vision-me", protocol="vless", transport="tcp",
                     security="reality", enabled=1)


def _inbound(cfg, tag):
    for ib in cfg["inbounds"]:
        if ib.get("tag") == tag:
            return ib
    return None


def test_vision_flow_is_written_into_the_reality_inbound(client, db, reality_user,
                                                          settings_guard):
    db.set_meta("reality_priv", "test-private-key")
    db.set_meta("reality_sid", "abcd1234")
    cfg = xray.generate_xray_config()
    ib = _inbound(cfg, "in-vless-reality")
    assert ib, f"no reality inbound: {[i.get('tag') for i in cfg['inbounds']]}"
    client_entry = next(c for c in ib["settings"]["clients"] if c["email"] == reality_user["uid"])
    assert client_entry.get("flow") == tuning.VISION_FLOW


def test_link_and_inbound_never_disagree_about_flow(client, db, reality_user, settings_guard):
    """The invariant: whatever the link says, the inbound says the same."""
    db.set_meta("reality_priv", "test-private-key")
    settings = db.get_settings()
    link = links.build_vless_link("node.example", 443, reality_user, settings)
    cfg = xray.generate_xray_config()
    ib = _inbound(cfg, "in-vless-reality")
    entry = next(c for c in ib["settings"]["clients"] if c["email"] == reality_user["uid"])
    assert ("flow=" + tuning.VISION_FLOW in link) == (entry.get("flow") == tuning.VISION_FLOW)

    # now the other way round
    db.set_setting("vision_enabled", False)
    settings = {**db.get_settings(), "vision_enabled": False}
    link2 = links.build_vless_link("node.example", 443, reality_user, settings)
    assert "flow=" not in link2, link2
    cfg2 = xray.generate_xray_config()
    entry2 = next(c for c in _inbound(cfg2, "in-vless-reality")["settings"]["clients"]
                  if c["email"] == reality_user["uid"])
    assert "flow" not in entry2, entry2


def test_flow_never_appears_on_a_stream_that_cannot_carry_it(client, db, make_user,
                                                             settings_guard):
    """WS / XHTTP / gRPC have no Vision. Emitted there it is a broken config."""
    for transport in ("ws", "xhttp", "grpc", "httpupgrade"):
        u = make_user(name=f"t-{transport}", protocol="vless", transport=transport,
                      security="tls")
        link = links.build_vless_link("node.example", 443, u, db.get_settings())
        assert "flow=" not in link, (transport, link)
    db.set_meta("reality_priv", "test-private-key")
    cfg = xray.generate_xray_config()
    for tag in ("in-vless-ws", "in-vless-xhttp", "in-vmess-xhttp"):
        ib = _inbound(cfg, tag)
        if ib:
            assert all("flow" not in c for c in ib["settings"]["clients"]), tag


def test_xhttp_mode_and_extra_follow_the_mode(client, db, settings_guard, make_user):
    # Inbounds only exist for protocols that have users, so a test that inspects
    # one has to create the user first.
    make_user(name="xhttp-probe", protocol="vless", transport="xhttp", security="tls")
    db.set_setting("xhttp_mode", "packet-up")
    db.set_setting("xhttp_padding", "100-1000")
    ib = _inbound(xray.generate_xray_config(), "in-vless-xhttp")
    xs = ib["streamSettings"]["xhttpSettings"]
    assert xs["mode"] == "packet-up"
    assert xs["extra"]["xPaddingBytes"] == "100-1000"
    assert "scMaxEachPostBytes" in xs["extra"] and "scStreamUpServerSecs" not in xs["extra"]

    db.set_setting("xhttp_mode", "stream-up")
    xs = _inbound(xray.generate_xray_config(), "in-vless-xhttp")["streamSettings"]["xhttpSettings"]
    assert "scStreamUpServerSecs" in xs["extra"] and "scMaxEachPostBytes" not in xs["extra"]


def test_pinned_xhttp_mode_is_published_in_links_too(client, db, settings_guard):
    """`auto` is what an omitted mode already means, so only a pinned mode is added."""
    settings = {**db.get_settings(), "xhttp_mode": "auto"}
    link_auto = links.build_vless_link("n.example", 443,
                                       {"uuid": "u", "name": "n", "protocol": "vless",
                                        "transport": "xhttp", "security": "tls"}, settings)
    assert "mode=" not in link_auto
    settings = {**settings, "xhttp_mode": "stream-up"}
    link_pinned = links.build_vless_link("n.example", 443,
                                         {"uuid": "u", "name": "n", "protocol": "vless",
                                          "transport": "xhttp", "security": "tls"}, settings)
    assert "mode=stream-up" in link_pinned


def test_sockopt_and_sniffing_land_on_tcp_inbounds_only(client, db, settings_guard, make_user):
    make_user(name="sockopt-probe", protocol="vless", transport="ws", security="tls")
    db.set_setting("sockopt_enabled", True)
    cfg = xray.generate_xray_config()
    ws = _inbound(cfg, "in-vless-ws")
    assert ws["streamSettings"]["sockopt"]["tcpcongestion"] == "bbr"
    assert ws["streamSettings"]["sockopt"]["tcpKeepAliveIdle"] == 30
    assert ws["sniffing"]["enabled"] is True
    # never: clamping MSS/recv window throttles long-haul paths
    import json as _json
    blob = _json.dumps(cfg)
    for forbidden in ("tcpMss", "tcpRecvWindow", "tcpSendWindow"):
        assert forbidden not in blob

    db.set_setting("sockopt_enabled", False)
    cfg = xray.generate_xray_config()
    assert "sockopt" not in _inbound(cfg, "in-vless-ws")["streamSettings"]


def test_reality_rotation_keeps_the_old_values_accepted(client, db, settings_guard,
                                                         reality_user):
    """Rotating must not burn the links already in subscribers' phones."""
    from app import reality
    saved = (db.get_meta("reality_sid"), db.get_meta("reality_sids"),
             db.get_settings().get("reality_sid"))
    try:
        db.set_meta("reality_sid", "1111aaaa")
        db.set_meta("reality_sids", "")
        db.set_meta("reality_priv", "test-private-key")
        out = reality.rotate_short_id()
        ids = _inbound(xray.generate_xray_config(), "in-vless-reality")[
            "streamSettings"]["realitySettings"]["shortIds"]
        assert "1111aaaa" in ids, ids          # the old link still works
        assert out["sid"] in ids, ids          # and the new one is served
        assert all(len(i) % 2 == 0 for i in ids), ids
        # a fresh short id is the one published to new links
        assert db.get_settings()["reality_sid"] == out["sid"]
    finally:
        db.set_meta("reality_sid", saved[0] or "")
        db.set_meta("reality_sids", saved[1] or "")
        db.set_setting("reality_sid", saved[2] or "")


def test_rotating_does_not_kill_links_published_with_an_empty_sid(client, db):
    """A panel that never had a short id must not lose its subscribers on rotation."""
    from app import reality
    saved = (db.get_meta("reality_sid"), db.get_meta("reality_sids"))
    try:
        db.set_meta("reality_sid", "")
        db.set_meta("reality_sids", "")
        out = reality.rotate_short_id()
        assert "" in out["accepting"], out["accepting"]
        assert out["sid"] in out["accepting"]
    finally:
        db.set_meta("reality_sid", saved[0] or "")
        db.set_meta("reality_sids", saved[1] or "")
