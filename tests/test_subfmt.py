"""app/subfmt.py must translate links into client files without inventing anything.

The important property under test is *agreement*: a config file may only contain
what the published link already says, plus the knobs a URL cannot carry. And the
YAML has to be loadable by a real parser, since we emit it by hand instead of
taking on a dependency.
"""
import base64
import json

import pytest

from app import subfmt, tuning

VMESS_LINK = "vmess://" + base64.b64encode(json.dumps({
    "v": "2", "ps": "TiTaN-V-VMess-WS", "add": "v.example", "port": "443",
    "id": "11112222-3333-4444-555566667777", "aid": "0", "scy": "auto", "net": "ws",
    "type": "none", "host": "v.example", "path": "/vm-ws", "tls": "tls",
    "sni": "v.example", "alpn": "http/1.1", "fp": "chrome",
}).encode()).decode()

REALITY = ("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@r.example:443?encryption=none"
           "&security=reality&pbk=PUBKEY-9z&sid=00112233aabbccdd&sni=www.microsoft.com"
           "&spx=%2F&fp=chrome&type=tcp&headerType=none&flow=xtls-rprx-vision#TiTaN-R-Reality")
XHTTP = ("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@x.example:443?encryption=none"
         "&security=tls&type=xhttp&host=x.example&path=%2Fxhttp&sni=x.example&fp=chrome"
         "&alpn=h2%2Chttp%2F1.1&mode=packet-up#TiTaN-R-XHTTP")
TROJAN = ("trojan://pw123@t.example:443?type=ws&path=%2Ftr-ws&host=t.example&sni=t.example"
          "&alpn=http%2F1.1&fp=chrome#TiTaN-T-Trojan")
SS2022 = "ss://2022-blake3-aes-128-gcm:Zm9vYmFy%3D%3D@s.example:443#TiTaN-S-SS"
HY2 = "hysteria2://uuid-hy@h.example:443?sni=h.example&insecure=1&alpn=h3&obfs=salamander&obfsParam=secretpw#TiTaN-H-HY2"
ALL = [REALITY, XHTTP, TROJAN, SS2022, HY2, VMESS_LINK]


def settings(**over):
    base = {k: v for k, v in tuning.PROFILES["general"].items()}
    base.update({"operator_profile": "general", "vision_enabled": True, "sockopt_enabled": True,
                 "xhttp_padding": "100-1000", "xhttp_xmux": True, "client_fragment_enabled": True,
                 "fragment_enabled": False, "default_alpn": "", "wg_mtu": 1280, "wg_keepalive": 25})
    return {**base, **over}


def test_every_link_kind_parses():
    entries, skipped = subfmt.parse_links(ALL)
    assert [e["kind"] for e in entries] == ["vless", "vless", "trojan", "shadowsocks",
                                             "hysteria2", "vmess"]
    assert not skipped
    reality = entries[0]
    assert reality["flow"] == "xtls-rprx-vision" and reality["pbk"] == "PUBKEY-9z"
    assert reality["sid"] == "00112233aabbccdd" and reality["spx"] == "/"
    # a percent-encoded `==` must arrive decoded, or the PSK is wrong
    assert entries[3]["password"] == "Zm9vYmFy=="
    assert entries[4]["obfs"] == "salamander" and entries[4]["insecure"] is True


def test_the_info_link_never_becomes_an_outbound():
    info = ("vless://00000000-0000-0000-0000-000000000001@127.0.0.1:10001?encryption=none"
            "&security=none&type=tcp&headerType=none#TiTaN%20me%20%7C%200%2F10GB")
    entries, skipped = subfmt.parse_links([info, REALITY])
    assert len(entries) == 1 and len(skipped) == 1
    assert "usage-remark" in skipped[0]["reason"]


def test_wireguard_and_garbage_are_reported_not_invented():
    entries, skipped = subfmt.parse_links(["wireguard://QUJD#TiTaN-W-WG", "not a link",
                                          "vless://no-params@example"])
    assert len(skipped) == 2, skipped          # wg is a .conf, "not a link" is nothing
    assert entries[0]["kind"] == "vless"       # a thin link is still reproduced faithfully
    assert entries[0]["security"] == "none" and not entries[0]["flow"]


def test_xray_file_carries_xmux_and_client_sockopt():
    doc = subfmt.xray_config(subfmt.parse_links(ALL)[0], settings())
    xhttp = next(o for o in doc["outbounds"] if o.get("tag") == "TiTaN-R-XHTTP")
    xs = xhttp["streamSettings"]["xhttpSettings"]
    assert xs["mode"] == "packet-up"
    assert xs["extra"]["xPaddingBytes"] == "100-1000"
    # xmux is all-or-nothing: half a block stops the other keys taking defaults
    assert len(xs["extra"]["xmux"]) == 6
    assert xhttp["streamSettings"]["sockopt"]["tcpFastOpen"] is True
    reality = next(o for o in doc["outbounds"] if o.get("tag") == "TiTaN-R-Reality")
    assert reality["settings"]["vnext"][0]["users"][0]["flow"] == "xtls-rprx-vision"
    assert reality["streamSettings"]["realitySettings"]["publicKey"] == "PUBKEY-9z"


def test_xray_file_does_not_invent_a_hysteria2_outbound():
    """Xray's hy2 client outbound is not documented well enough to guess at."""
    entries, _ = subfmt.parse_links([HY2])
    doc = subfmt.xray_config(entries, settings())
    assert [o for o in doc["outbounds"] if o.get("settings")] == []
    assert [o["tag"] for o in doc["outbounds"]] == ["direct", "block"]


def test_singbox_uses_the_real_sing_box_field_names():
    doc = subfmt.singbox_config(subfmt.parse_links([REALITY, XHTTP])[0], settings())
    reality = doc["outbounds"][1]
    assert reality["type"] == "vless" and reality["packet_encoding"] == "xudp"
    tls = reality["tls"]
    assert tls["fragment"] is True        # sing-box's is a switch, not a length map
    assert not isinstance(tls["fragment"], dict)
    assert tls["reality"] == {"enabled": True, "public_key": "PUBKEY-9z", "short_id": "00112233aabbccdd"}
    assert tls["utls"]["fingerprint"] == "chrome"
    assert doc["outbounds"][0]["actors"][0] == "TiTaN-R-Reality"
    # xhttp is sing-box's `http` transport; `xhttp` is not a type name there
    assert doc["outbounds"][2]["transport"]["type"] == "http"


def test_irancell_profile_escalates_to_record_fragment():
    plain = subfmt.singbox_config(subfmt.parse_links([XHTTP])[0], settings())["outbounds"][1]["tls"]
    ir = subfmt.singbox_config(subfmt.parse_links([XHTTP])[0],
                              settings(operator_profile="irancell"))["outbounds"][1]["tls"]
    assert "record_fragment" not in plain
    assert ir["record_fragment"] is True
    assert ir["fragment_fallback_delay"] == "500ms"


def test_clash_output_parses_as_yaml_and_keeps_xmux_under_its_own_name():
    yaml = pytest.importorskip("yaml")
    doc = subfmt.clash_dict(subfmt.parse_links(ALL)[0], settings())
    text = subfmt.dump_yaml(doc)
    assert yaml.safe_load(text) == json.loads(json.dumps(doc))
    xhttp = next(p for p in doc["proxies"] if p["name"] == "TiTaN-R-XHTTP")
    reuse = xhttp["xhttp-opts"]["reuse-settings"]
    assert reuse["max-concurrency"] == "16-32" and "h-max-reusable-secs" in reuse
    assert xhttp["xhttp-opts"]["x-padding-bytes"] == "100-1000"
    reality = next(p for p in doc["proxies"] if p["name"] == "TiTaN-R-Reality")
    assert reality["flow"] == "xtls-rprx-vision"
    assert reality["packet-encoding"] == "xudp"
    assert reality["reality-opts"] == {"public-key": "PUBKEY-9z", "short-id": "00112233aabbccdd"}
    hy = next(p for p in doc["proxies"] if p["type"] == "hysteria2")
    assert hy["obfs-password"] == "secretpw" and hy["skip-cert-verify"] is True


def test_clash_mobile_profile_turns_ipv6_off():
    doc = subfmt.clash_dict(subfmt.parse_links([REALITY])[0], settings(operator_profile="mci"))
    assert doc["ipv6"] is False and doc["tcp-concurrent"] is True
    general = subfmt.clash_dict(subfmt.parse_links([REALITY])[0], settings())
    assert general["ipv6"] is True


def test_yaml_quoting_survives_hostile_remarks():
    text = subfmt.dump_yaml({"proxies": [{"name": "TiTaN | yes: no", "port": 443,
                                          "flag": True, "empty": "", "n": None}],
                             "rules": ["MATCH,Proxy"]})
    assert "yes" in text
    yaml = pytest.importorskip("yaml")
    back = yaml.safe_load(text)
    assert back["proxies"][0]["name"] == "TiTaN | yes: no"
    assert back["proxies"][0]["empty"] == "" and back["proxies"][0]["n"] is None
    assert back["rules"] == ["MATCH,Proxy"]


def test_tags_stay_unique_and_safe():
    used: set[str] = set()
    a = subfmt._tag("TiTaN a b (x): y", used)
    b = subfmt._tag("TiTaN a b (x): y", used)
    assert a != b and ":" not in a and "(" not in a


def test_render_reports_what_it_did_and_unknown_formats_are_refused():
    out = subfmt.render("singbox", ALL, settings(operator_profile="mci"),
                        {"key": "abc", "title": "grp"})
    assert out["media_type"].startswith("application/json")
    assert out["filename"] == "titan-abc.json"
    assert out["entries"] >= 4
    assert any("MCI" in n or "همراه" in n for n in out["notes"]), out["notes"]
    assert any("TCP خام" in n or "raw TCP" in n for n in out["notes"])
    with pytest.raises(ValueError):
        subfmt.render("clash-config", ALL, settings())


def test_empty_subscription_still_produces_a_loadable_file():
    for fmt in subfmt.FORMATS:
        out = subfmt.render(fmt, [], settings(), {"key": "k", "title": "t"})
        assert out["entries"] == 0
        if fmt == "clash":
            assert "proxies: []" in out["text"]
        else:
            doc = json.loads(out["text"])
            assert doc["outbounds"], "an app refuses a config with no outbounds at all"
