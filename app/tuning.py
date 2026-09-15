"""Operator-aware transport tuning.

Why this module exists
----------------------
Every knob that decides ping and survivability on Iranian mobile networks sits in
one of two places, and only the first one is ours to set:

* **server side** - what we write into the Xray config: ``sockopt``,
  ``xhttpSettings``, ``sniffing`` and the per-user ``flow``.  We can apply these
  ourselves, and we do, in :mod:`app.xray`.
* **client side** - fragmentation, uTLS, xmux, MTU.  A ``vless://…`` URL carries
  almost none of it: mainstream clients read ``fp_len``/``fp_int`` as Mahsa-fork
  extensions and ignore everything else, so these are delivered as *generated
  config files* (``app/subfmt.py``).  The link params stay for the apps that do
  parse them.

Numbers here are widely-used starting points, not measurements - ``notes()`` says
exactly that in the UI.  What is deliberately **absent**: ``tcpMss``,
``tcpRecvWindow`` and ``tcpSendWindow``.  Clamping them looks like tuning and
throttles long-haul links; 3x-ui shipped such a clamp and later removed it.
"""
import re

VISION_FLOW = "xtls-rprx-vision"

#: never emitted, whatever a profile says - see the module docstring
FORBIDDEN_SOCKOPT = frozenset({"tcpMss", "tcpRecvWindow", "tcpSendWindow"})

#: QUIC/UDP inbounds - TCP socket options would be nonsense there
UDP_ONLY_NETWORKS = frozenset({"hysteria", "utp", "kcp", "mkcp"})

#: per-operator starting points.  `label` pairs are shown in the UI.
PROFILES: dict[str, dict] = {
    "general": {
        "label": {"fa": "عمومی", "en": "General"},
        "domain_strategy": "",          # leave the client's default alone
        "fragment": {"packets": "1-3", "length": "100-200", "interval": "10-20"},
        "record_fragment": False,
        "client_alpn": ["h3", "h2", "http/1.1"],
        "xhttp_mode": "auto",
        "wg_mtu": 1280,
        "wg_keepalive": 25,
        "packet_encoding": "xudp",
        "notes": {
            "fa": "مقدارهای میانه برای همهٔ اپراتورها؛ برای MCI/Irancell پروفایل اختصاصی بهتر است.",
            "en": "Middle-of-the-road values. Prefer the MCI/Irancell profile on mobile.",
        },
    },
    "mci": {
        "label": {"fa": "همراه اول (MCI)", "en": "MCI"},
        # MCI has no usable IPv6 for most subscribers, so a dual-stack dial costs an
        # extra happy-eyeballs delay on every fresh connection.
        "domain_strategy": "UseIPv4",
        "fragment": {"packets": "1-3", "length": "100-200", "interval": "10-20"},
        "record_fragment": False,
        "client_alpn": ["h2", "http/1.1"],   # QUIC is policed harder than TCP here
        "xhttp_mode": "stream-up",          # better upload throughput on loss-free paths
        "wg_mtu": 1280,
        "wg_keepalive": 20,
        "packet_encoding": "xudp",
        "notes": {
            "fa": "اجبار به IPv4 (روی MCI عملاً جواب نمی‌دهد)، ALPN بدون h3، و keepalive زیر زمان NAT.",
            "en": "Forces IPv4, drops h3 from ALPN, keeps the tunnel under the NAT timeout.",
        },
    },
    "irancell": {
        "label": {"fa": "ایرانسل", "en": "Irancell"},
        "domain_strategy": "UseIPv4",
        # Irancell-style middleboxes rewrite the ClientHello; a small first burst is
        # the usual workaround, and record_fragment is the escalation if it fails.
        "fragment": {"packets": "1-5", "length": "80-160", "interval": "5-15"},
        "record_fragment": True,
        "client_alpn": ["h3", "h2", "http/1.1"],
        "xhttp_mode": "packet-up",          # most compatible upload shape
        "wg_mtu": 1280,
        "wg_keepalive": 15,
        "packet_encoding": "xudp",
        "notes": {
            "fa": "Fragment تهاجمی‌تر + record_fragment، MTU کوچک و keepalive ۱۵s برای NAT سریع‌تر.",
            "en": "Aggressive fragment + record_fragment, small MTU, 15s keepalive for a fast NAT.",
        },
    },
}

DEFAULT_PROFILE = "general"
XHTTP_MODES = ("auto", "packet-up", "stream-up", "stream-one")
#: `auto` on the server accepts every client mode, so links stay quiet unless the
#: admin deliberately pins one (which changes the bytes of every published link).
CLIENT_ONLY_MODES = ("packet-up", "stream-up", "stream-one")


def profile_name(settings: dict) -> str:
    p = str(settings.get("operator_profile") or DEFAULT_PROFILE).strip().lower()
    return p if p in PROFILES else DEFAULT_PROFILE


def profile(settings: dict) -> dict:
    return PROFILES[profile_name(settings)]


def vision_on(settings: dict) -> bool:
    """Vision (the `xtls-rprx-vision` flow) is a raw-TCP thing.

    It is only ever emitted next to an inbound that can carry it - see
    `app.xray.generate_xray_config` and `app.links` - because server and client
    must agree: a `flow` on one side and none on the other leaves a session that
    completes TLS and then carries garbage.
    """
    return bool(settings.get("vision_enabled", True))


def flow_for(settings: dict, *, transport: str, security: str) -> str:
    """The `flow` value for one link/inbound, or "" when Vision does not apply."""
    if not vision_on(settings):
        return ""
    if (transport or "").lower() != "tcp":
        return ""
    if (security or "").lower() not in ("reality", "tls"):
        return ""
    return VISION_FLOW


def _int(settings: dict, key: str, fallback: int, lo: int, hi: int) -> int:
    try:
        v = int(settings.get(key, fallback))
    except (TypeError, ValueError):
        v = int(fallback)
    return max(lo, min(hi, v))


def sockopt(settings: dict) -> dict:
    """`streamSettings.sockopt` for TCP inbounds. {} disables the whole feature."""
    if not settings.get("sockopt_enabled", True):
        return {}
    prof = profile(settings)
    out: dict = {
        "tcpNoDelay": True,
        "tcpFastOpen": True,
        "tcpcongestion": str(settings.get("tcp_congestion") or "bbr"),
        # The keepalive has to be shorter than the operator's NAT timeout
        # (60-120s on 4G) or the tunnel silently dies while it still looks up.
        "tcpKeepAliveIdle": _int(settings, "tcp_keepalive_idle", 30, 5, 600),
        "tcpUserTimeout": _int(settings, "tcp_user_timeout", 10000, 2000, 130000),
    }
    if settings.get("tcp_mptcp", True):
        # MPTCP is what keeps a session alive across a wifi->cellular handover.
        out["tcpMptcp"] = True
    if prof["domain_strategy"]:
        out["domainStrategy"] = prof["domain_strategy"]
    bad = FORBIDDEN_SOCKOPT & set(out)
    if bad:  # pragma: no cover - a profile must never grow these
        raise ValueError(f"forbidden sockopt keys: {sorted(bad)}")
    return out


def sniffing(settings: dict) -> dict:
    """Destination sniffing so routing (and the block lists) see real hostnames."""
    if not settings.get("sniffing_enabled", True):
        return {}
    return {
        "enabled": True,
        "destOverride": ["http", "tls", "quic"],
        "metadataOnly": False,
        # `routeOnly` keeps sniffing as a routing hint only: the real target is
        # still resolved by the remote, which is what you want when the client's
        # DNS is a leak or a lie.
        "routeOnly": bool(settings.get("sniffing_route_only", True)),
    }


TCP_CONGESTION = frozenset({"bbr", "cubic", "reno", ""})


def range_ok(value: str) -> bool:
    """Public form of the `100-1000` / `500` shape check."""
    return _range_ok(value)


def _range_ok(value: str) -> bool:
    """Accept `500`, `100-1000` or `0`; reject anything else."""
    return bool(re.fullmatch(r"\d+(-\d+)?", str(value or "").strip()))


def xhttp_extra(settings: dict, mode: str) -> dict:
    """Server-side `xhttpSettings.extra`, filtered to what `mode` can use.

    Field names follow the Xray transport docs: `noSSEHeader`/`scMaxBufferedPosts`
    are server-only, `scMaxEachPostBytes` applies to packet-up, `scStreamUpServerSecs`
    to stream-up. Emitting the others here would be a knob nobody reads.
    """
    extra: dict = {}
    padding = str(settings.get("xhttp_padding") or "").strip()
    if padding and _range_ok(padding):
        extra["xPaddingBytes"] = padding
    if mode == "packet-up":
        extra["scMaxEachPostBytes"] = _int(settings, "xhttp_max_each_post", 1000000, 5000, 100000000)
        extra["scMaxBufferedPosts"] = _int(settings, "xhttp_max_buffered_posts", 30, 1, 1000)
    if mode == "stream-up":
        extra["scStreamUpServerSecs"] = str(settings.get("xhttp_stream_up_secs") or "20-80")
    if settings.get("xhttp_no_sse_header"):
        # Only when a proxy in front mangles the SSE response header.
        extra["noSSEHeader"] = True
    return extra


def xhttp_mode(settings: dict) -> str:
    mode = str(settings.get("xhttp_mode") or "").strip().lower()
    if mode in XHTTP_MODES:
        return mode
    return profile(settings)["xhttp_mode"]


def xhttp_server_settings(settings: dict, path: str) -> dict:
    """The whole `xhttpSettings` object for an inbound."""
    mode = xhttp_mode(settings)
    out: dict = {"path": path, "mode": mode}
    extra = xhttp_extra(settings, mode)
    if extra:
        out["extra"] = extra
    return out


def client_xmux(settings: dict) -> dict:
    """Client-side xmux (`extra.xmux`), for generated config files only.

    Xray documents xmux as *client only*; putting it in a server inbound is a no-op.
    And as soon as one field is set the others stop taking their defaults, so the
    whole block is emitted or nothing.
    """
    if not settings.get("xhttp_xmux", True):
        return {}
    return {
        "maxConcurrency": "16-32",
        "maxConnections": 0,
        "cMaxReuseTimes": 0,
        "hMaxRequestTimes": "600-900",
        "hMaxReusableSecs": "1800-3000",
        "hKeepAlivePeriod": 0,
    }


def client_fragment(settings: dict) -> dict:
    """sing-box-shaped TLS fragmentation for generated client configs.

    sing-box exposes `fragment`/`record_fragment` as booleans with an optional
    length/interval pair - there is no per-link way to say this, which is the
    whole reason `app/subfmt.py` exists.
    """
    prof = profile(settings)
    frag = dict(prof["fragment"])
    if settings.get("fragment_enabled"):
        # The admin's own numbers win over the profile's starting point.
        frag["length"] = str(settings.get("fragment_length") or frag["length"])
        frag["interval"] = str(settings.get("fragment_interval") or frag["interval"])
    frag["enabled"] = bool(settings.get("client_fragment_enabled", True))
    frag["record_fragment"] = bool(prof["record_fragment"])
    frag["fallback_delay"] = "500ms"
    return frag


def wg_tuning(settings: dict) -> tuple[int, int]:
    """(PersistentKeepalive seconds, MTU) for a generated wg-quick client."""
    prof = profile(settings)
    keep = _int(settings, "wg_keepalive", prof["wg_keepalive"], 0, 300)
    mtu = _int(settings, "wg_mtu", prof["wg_mtu"], 0, 1420)
    return keep, mtu


#: profiles whose whole point is a middlebox that rewrites the ClientHello
FRAGMENT_PROFILES = frozenset({"mci", "irancell"})


def fragment_in_link(settings: dict) -> bool:
    """Should `fp_len`/`fp_int` ride along in the link?

    Only Mahsa-family apps read those (MahsaNG/NikaNG); mainstream clients ignore
    them, which is what `app/subfmt.py` is for. They cost nothing for everyone
    else and are the one fragment lever a plain link has, so a mobile profile
    implies them and "general" never adds them - published links keep their exact
    bytes until an operator deliberately picks a profile.
    """
    if settings.get("fragment_enabled"):
        return True
    return profile_name(settings) in FRAGMENT_PROFILES


def fragment_values(settings: dict) -> tuple[str, str]:
    """(length, interval) as they go into a link, profile defaults included."""
    prof = profile(settings)
    default = prof["fragment"]
    return (str(settings.get("fragment_length") or default["length"]),
            str(settings.get("fragment_interval") or default["interval"]))


def wg_conf(u: dict, host: str, port: int, server_pub: str,
            settings: dict, dns: str = "1.1.1.1") -> str:
    """A wg-quick `[Interface]/[Peer]` block, tuned for mobile NAT.

    Both lines matter on Iranian 4G: `PersistentKeepalive` must be shorter than the
    operator's UDP NAT mapping (60-120s) or the tunnel goes quiet while wg0 still
    reads "up", and an MTU below the real path MTU is what keeps big packets out of
    a PMTU blackhole on PPPoE and 4G.
    """
    keepalive, mtu = wg_tuning(settings)
    lines = [
        "[Interface]",
        f"PrivateKey = {u.get('wg_priv') or ''}",
        f"Address = {u.get('wg_ip') or ''}/32",
        f"DNS = {dns}",
    ]
    if mtu:
        lines.append(f"MTU = {mtu}")
    lines += ["", "[Peer]", f"PublicKey = {server_pub or ''}",
              "AllowedIPs = 0.0.0.0/0, ::/0", f"Endpoint = {host}:{port}"]
    if keepalive:
        lines.append(f"PersistentKeepalive = {keepalive}")
    return "\n".join(lines) + "\n"


def packet_encoding(settings: dict) -> str:
    return str(profile(settings).get("packet_encoding") or "")


def client_alpn(settings: dict) -> list[str]:
    alpn = str(settings.get("default_alpn") or "").strip()
    if alpn:
        return [a for a in alpn.split(",") if a]
    return list(profile(settings)["client_alpn"])


def apply_to_inbounds(inbounds: list[dict], settings: dict) -> list[dict]:
    """Attach `sockopt` (+ sniffing where it helps) to every TCP inbound."""
    sock = sockopt(settings)
    sniff = sniffing(settings)
    for ib in inbounds:
        ss = ib.get("streamSettings")
        if not isinstance(ss, dict):
            continue
        if str(ss.get("network") or "").lower() in UDP_ONLY_NETWORKS:
            continue
        if sock:
            ss["sockopt"] = dict(sock)
        if sniff and ib.get("protocol") in ("vless", "vmess", "trojan", "shadowsocks"):
            ib.setdefault("sniffing", dict(sniff))
    return inbounds


def describe(settings: dict) -> dict:
    """Everything the UI needs to explain what is about to be applied."""
    prof_key = profile_name(settings)
    prof = PROFILES[prof_key]
    lang = "fa"
    return {
        "profile": prof_key,
        "label": prof["label"].get(lang, prof["label"]["en"]),
        "labels": {k: v["label"] for k, v in PROFILES.items()},
        "notes": prof["notes"].get(lang, prof["notes"]["en"]),
        "vision": vision_on(settings),
        "flow": VISION_FLOW if vision_on(settings) else "",
        "sockopt": sockopt(settings),
        "sniffing": sniffing(settings),
        "xhttp": {"mode": xhttp_mode(settings), "extra": xhttp_extra(settings, xhttp_mode(settings))},
        "xmux": bool(settings.get("xhttp_xmux", True)),
        "fragment": client_fragment(settings),
        "wg": dict(zip(("keepalive", "mtu"), wg_tuning(settings), strict=True)),
        "warn": ("BBR needs the host kernel module; inside a shared container it can be "
                 "ignored. Measure before believing." if sockopt(settings).get("tcpcongestion") == "bbr" else ""),
    }
