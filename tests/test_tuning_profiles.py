"""Unit tests for the profile maths in app/tuning.py (no DB, no app).

Everything here is about *what we are allowed to promise*: a profile must produce a
config Xray accepts, must never produce one that throttles long-haul paths, and must
not claim a knob the client cannot read.
"""
import json

import pytest

from app import tuning

BASE = {"operator_profile": "general", "vision_enabled": True, "sockopt_enabled": True,
        "tcp_congestion": "bbr", "tcp_keepalive_idle": 30, "tcp_user_timeout": 10000,
        "tcp_mptcp": True, "sniffing_enabled": True, "sniffing_route_only": True,
        "xhttp_mode": "auto", "xhttp_padding": "", "xhttp_xmux": True,
        "client_fragment_enabled": True, "fragment_enabled": False,
        "default_alpn": "", "wg_keepalive": 0, "wg_mtu": 0, "fragment_length": "",
        "fragment_interval": ""}


def settings(**over):
    """A full settings dict; pytest must not collect this helper as a test."""
    return {**BASE, **over}


def test_unknown_profile_falls_back_to_general():
    assert tuning.profile_name(settings(operator_profile="sky")) == "general"
    assert tuning.profile_name(settings(operator_profile="MCI")) == "mci"
    assert tuning.profile_name(settings()) == "general"


def test_mobile_profiles_force_ipv4_and_general_does_not():
    assert tuning.sockopt(settings(operator_profile="mci"))["domainStrategy"] == "UseIPv4"
    assert tuning.sockopt(settings(operator_profile="irancell"))["domainStrategy"] == "UseIPv4"
    assert "domainStrategy" not in tuning.sockopt(settings())


def test_keepalive_and_usertimeout_are_clamped_not_trusted():
    sock = settings(tcp_keepalive_idle="999999", tcp_user_timeout="nope")
    out = tuning.sockopt(sock)
    assert out["tcpKeepAliveIdle"] == 600          # clamped, never a 10-digit idle
    assert out["tcpUserTimeout"] == 10000          # unparsable -> the default


def test_no_profile_can_emit_a_window_or_mss_clamp():
    for name in tuning.PROFILES:
        blob = json.dumps(tuning.sockopt(settings(operator_profile=name)))
        for forbidden in ("tcpMss", "tcpRecvWindow", "tcpSendWindow"):
            assert forbidden not in blob, (name, blob)


def test_xhttp_extra_only_carries_keys_the_chosen_mode_reads():
    for mode, expect, reject in (
        ("packet-up", "scMaxEachPostBytes", "scStreamUpServerSecs"),
        ("stream-up", "scStreamUpServerSecs", "scMaxEachPostBytes"),
        ("auto", "xPaddingBytes", "scMaxEachPostBytes"),
    ):
        extra = tuning.xhttp_extra(settings(xhttp_mode=mode, xhttp_padding="100-1000"), mode)
        assert expect in extra, (mode, extra)
        assert reject not in extra, (mode, extra)


def test_padding_must_be_a_number_or_a_range():
    assert "xPaddingBytes" in tuning.xhttp_extra(settings(xhttp_padding="100-1000"), "auto")
    for junk in ("; rm -rf /", "100-", "1-2-3", ""):
        assert "xPaddingBytes" not in tuning.xhttp_extra(settings(xhttp_padding=junk), "auto")


def test_xmux_is_all_or_nothing_and_client_side_only():
    xmux = tuning.client_xmux(settings())
    assert set(xmux) == {"maxConcurrency", "maxConnections", "cMaxReuseTimes",
                         "hMaxRequestTimes", "hMaxReusableSecs", "hKeepAlivePeriod"}
    assert tuning.client_xmux(settings(xhttp_xmux=False)) == {}


def test_flow_only_applies_to_raw_tcp_with_tls_or_reality():
    for transport, security, want in (
        ("tcp", "reality", tuning.VISION_FLOW), ("tcp", "tls", tuning.VISION_FLOW),
        ("tcp", "none", ""), ("ws", "reality", ""), ("xhttp", "tls", ""),
        ("grpc", "tls", ""), ("httpupgrade", "tls", ""),
    ):
        got = tuning.flow_for(settings(), transport=transport, security=security)
        assert got == want, (transport, security, got)
    assert tuning.flow_for(settings(vision_enabled=False), transport="tcp",
                           security="reality") == ""


def test_fragment_link_params_follow_the_profile_not_wishful_thinking():
    assert tuning.fragment_in_link(settings()) is False                    # general: quiet
    # a mobile profile implies the link params; "general" never adds them
    assert tuning.fragment_in_link(settings(operator_profile="irancell")) is True
    assert tuning.fragment_in_link(settings(operator_profile="general")) is False
    assert tuning.fragment_in_link(settings(fragment_enabled=True)) is True
    # explicit opt-in works on any profile
    assert tuning.fragment_in_link(settings(operator_profile="general", fragment_enabled=True)) is True
    length, interval = tuning.fragment_values(settings(operator_profile="mci"))
    assert length and interval and "-" in length
    assert tuning.fragment_values(settings(fragment_length="5-10"))[0] == "5-10"


def test_singbox_fragment_escalates_only_for_irancell():
    assert tuning.client_fragment(settings(operator_profile="irancell"))["record_fragment"] is True
    assert tuning.client_fragment(settings(operator_profile="general"))["record_fragment"] is False
    assert tuning.client_fragment(settings(operator_profile="general"))["enabled"] is True
    assert tuning.client_fragment(settings(client_fragment_enabled=False))["enabled"] is False


def test_wg_conf_adds_both_mobile_lines_and_omits_them_when_zero():
    u = {"wg_priv": "PRIV", "wg_ip": "10.66.66.5"}
    conf = tuning.wg_conf(u, "wg.example", 51820, "PUB", settings(wg_mtu=1280, wg_keepalive=20))
    assert "MTU = 1280" in conf and "PersistentKeepalive = 20" in conf
    assert "Endpoint = wg.example:51820" in conf and conf.endswith("\n")
    off = tuning.wg_conf(u, "wg.example", 51820, "PUB", settings(wg_mtu=0, wg_keepalive=0))
    assert "MTU" not in off and "PersistentKeepalive" not in off


def test_apply_to_inbounds_skips_udp_and_leaves_the_api_inbound_alone():
    inbounds = [
        {"tag": "ws", "protocol": "vless", "streamSettings": {"network": "ws"}},
        {"tag": "hy", "protocol": "hysteria", "streamSettings": {"network": "hysteria"}},
        {"tag": "api", "protocol": "dokodemo-door", "streamSettings": {"network": "tcp"}},
    ]
    out = tuning.apply_to_inbounds(inbounds, settings())
    assert out[0]["streamSettings"]["sockopt"]["tcpcongestion"] == "bbr"
    assert "sockopt" not in out[1]["streamSettings"], "QUIC inbound got TCP options"
    assert "sniffing" not in out[2], "dokodemo-door must not sniff"


def test_describe_is_what_the_ui_presents_and_holds_no_secrets():
    d = tuning.describe(settings(operator_profile="mci"))
    assert set(d) >= {"profile", "label", "notes", "vision", "sockopt", "xhttp",
                      "fragment", "wg", "warn"}
    blob = json.dumps(d, ensure_ascii=False)
    assert "privateKey" not in blob and "password" not in blob
    assert "BBR" in d["warn"], "the UI must not present BBR as a guaranteed win"


@pytest.mark.parametrize("name", sorted(tuning.PROFILES))
def test_every_profile_is_fully_shaped(name):
    prof = tuning.PROFILES[name]
    assert set(prof) >= {"label", "notes", "domain_strategy", "fragment", "client_alpn",
                         "xhttp_mode", "wg_mtu", "wg_keepalive", "packet_encoding"}
    assert "fa" in prof["label"] and "en" in prof["label"]
    assert set(prof["fragment"]) == {"packets", "length", "interval"}
