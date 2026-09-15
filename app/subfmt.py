"""Client config files: Xray JSON, sing-box JSON, mihomo/Clash YAML.

Why these parse the links we already publish
-------------------------------------------
`app/links.py` is the single source of truth for what a subscriber receives. If a
second code path re-derived the parameters for a config file, the two would drift
the first time a per-user override (fingerprint, short id, transport, node host)
landed on one side only - and a config file that disagrees with the link is worse
than no config file, because it imports cleanly and then fails silently.

What a URL cannot carry
-----------------------
Nothing. Well: almost nothing that matters. `fragment`, TLS record sizing, xmux
stream reuse, MTU, routing and DNS policy are all client-side settings, and the
only link-level fragments we can emit (`fp_len`/`fp_int`) are read by Mahsa-family
apps and ignored by the mainstream ones. That is the entire reason this module
exists: the profile in :mod:`app.tuning` is only real once it reaches the device,
and the way to reach the device is an importable file.

Deliberately absent
-------------------
* hysteria2 in the Xray JSON - the client-side outbound shape is not documented
  well enough to guess, so it is reported in `skipped` instead of being invented.
* `packet-encoding`/`xudp` for links whose server transport is not raw TCP.
* any key a target app does not actually read: see `notes` for what the user must
  still toggle in the app itself.
"""
import base64
import binascii
import json
import re
from urllib.parse import quote, unquote

from . import tuning

FORMATS = ("xray", "singbox", "clash")
_MEDIA = {"xray": "application/json", "singbox": "application/json", "clash": "text/yaml"}
_EXT = {"xray": "json", "singbox": "json", "clash": "yaml"}
#: transports a real client can dial; anything else is a remark-only entry
_SUPPORTED = {"vless", "vmess", "trojan", "shadowsocks", "hysteria2"}


# ------------------------------------------------------------------ parsing
def _params(query: str) -> dict:
    out: dict[str, str] = {}
    for chunk in (query or "").split("&"):
        if not chunk:
            continue
        key, _, value = chunk.partition("=")
        out[key] = unquote(value)
    return out


def _b64_json(blob: str) -> dict:
    pad = "=" * (-len(blob) % 4)
    for variant in (blob, blob.replace("-", "+").replace("_", "/")):
        try:
            data = base64.b64decode(variant + pad)
        except (binascii.Error, ValueError):
            continue
        try:
            parsed = json.loads(data.decode("utf-8", "ignore"))
        except ValueError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return {}


def _b64_text(blob: str) -> str:
    pad = "=" * (-len(blob) % 4)
    try:
        return base64.urlsafe_b64decode(blob + pad).decode("utf-8", "ignore")
    except (binascii.Error, ValueError):
        return ""


def parse_link(link: str) -> dict | None:
    """One link -> a normalised description. None when we cannot build a client config."""
    link = (link or "").strip()
    scheme = link.split("://", 1)[0].lower() if "://" in link else ""
    if scheme == "ss":
        scheme = "shadowsocks"          # the wire format is `ss://`, the kind is not
    if scheme not in _SUPPORTED and scheme != "wireguard":
        return None
    rest = link.split("://", 1)[1] if "://" in link else link
    frag = ""
    if "#" in rest:
        rest, _, frag = rest.partition("#")
    name = unquote(frag) or "TiTaN"
    q = ""
    if "?" in rest:
        rest, _, q = rest.partition("?")
    p = _params(q)

    if scheme == "vmess":
        obj = _b64_json(rest)
        if not obj:
            return None
        net = str(obj.get("net") or "tcp")
        return {
            "kind": "vmess", "name": str(obj.get("ps") or name),
            "server": str(obj.get("add") or ""), "port": _port(obj.get("port")),
            "user": str(obj.get("id") or ""), "cipher": str(obj.get("scy") or "auto"),
            "transport": net if net in ("ws", "grpc", "httpupgrade", "xhttp", "tcp") else "tcp",
            "security": "tls" if str(obj.get("tls") or "") == "tls" else "none",
            "path": str(obj.get("path") or ""), "host": str(obj.get("host") or ""),
            "sni": str(obj.get("sni") or ""), "fp": str(obj.get("fp") or ""),
            "alpn": [a for a in str(obj.get("alpn") or "").split(",") if a],
            "service": str(obj.get("serviceName") or ""),
        }

    if scheme == "wireguard":
        return None  # delivered as a .conf / wireguard:// link, not as an app config

    if scheme == "shadowsocks":
        head, _, loc = rest.partition("@")
        if ":" in head:
            method, _, password = head.partition(":")     # SIP008: method:b64url-psk
            password = unquote(password)                  # `==` arrives percent-encoded
        else:
            raw = _b64_text(head)                          # legacy: b64("method:password")
            method, _, password = raw.partition(":")
        if not method or not password:
            return None
        return {
            "kind": "shadowsocks", "name": name, "server": _host(loc), "port": _port(loc),
            "user": "", "cipher": method, "password": password,
            "transport": "tcp", "security": "none",
        }

    # vless / trojan / hysteria2: <scheme>://<credential>@<host>:<port>
    cred, _, loc = rest.partition("@")
    entry = {
        "kind": scheme, "name": name, "user": unquote(cred), "password": unquote(cred),
        "server": _host(loc), "port": _port(loc),
        "transport": {"hysteria2": "hysteria"}.get(scheme, p.get("type") or "tcp"),
        "security": p.get("security") or ("tls" if scheme == "trojan" else "none"),
        "path": p.get("path") or "", "host": p.get("host") or "",
        "sni": p.get("sni") or "", "fp": p.get("fp") or "",
        "alpn": [a for a in (p.get("alpn") or "").split(",") if a],
        "flow": p.get("flow") or "", "mode": p.get("mode") or "",
        "service": p.get("serviceName") or "",
        "pbk": p.get("pbk") or p.get("publicKey") or "",
        "sid": p.get("sid") or p.get("shortId") or "",
        "spx": p.get("spx") or p.get("spiderX") or "",
        "insecure": str(p.get("allowInsecure") or p.get("insecure") or "0") in ("1", "true"),
        "cipher": p.get("encryption") or "",
        "obfs": p.get("obfs") or "", "obfs_param": p.get("obfsParam") or "",
    }
    if not entry["server"]:
        return None
    return entry


def _host(loc: str) -> str:
    return (loc.rsplit(":", 1)[0] if loc.count(":") == 1 else loc.split(":")[0]) or ""


def _port(value) -> int:
    if isinstance(value, str):
        value = value.rsplit(":", 1)[-1]
    try:
        return int(value)
    except (TypeError, ValueError):
        return 443


#: the uuid of the panel's own "status" link (see links.build_links): it carries a
#: remark only and must never become an outbound in a generated config file
INFO_LINK_UUID = "00000000-0000-0000-0000-000000000001"
LOOPBACK = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}


def parse_links(links: list[str]) -> tuple[list[dict], list[dict]]:
    entries, skipped = [], []
    for link in links or []:
        entry = parse_link(link)
        if entry and entry["user"] == INFO_LINK_UUID and entry["server"] in LOOPBACK:
            skipped.append({"name": entry["name"], "reason": "it is the usage-remark link, not a config"})
            continue
        if entry and entry["server"] and entry["port"]:
            entries.append(entry)
        elif link:
            skipped.append({"name": unquote(link.rsplit("#", 1)[-1]) or "—",
                             "reason": "no client-config form for this link type"})
    return entries, skipped


# ------------------------------------------------------------------ shared bits
def _tag(name: str, used: set[str]) -> str:
    clean = re.sub(r"[\[\](){}\"':,|*&%$#@!<>?/\\]", "", str(name or "")).strip() or "TiTaN"
    clean = clean.replace(" ", "-")[:48]
    tag, n = clean, 2
    while tag in used:
        tag = f"{clean}-{n}"
        n += 1
    used.add(tag)
    return tag


def _extra_client(settings: dict, mode: str) -> dict:
    """Client-side xhttp `extra`: padding + xmux stream reuse (both client-only)."""
    extra: dict = {}
    padding = str(settings.get("xhttp_padding") or "").strip()
    if padding and re.fullmatch(r"\d+(-\d+)?", padding):
        extra["xPaddingBytes"] = padding
    if mode != "stream-one":
        xmux = tuning.client_xmux(settings)
        if xmux:
            extra["xmux"] = xmux
    return extra


# ------------------------------------------------------------------ xray json
def xray_config(entries: list[dict], settings: dict) -> dict:
    """A v2rayN/Xray-core client config: outbounds + the profile's client socket."""
    sock = tuning.sockopt(settings)
    alpn = tuning.client_alpn(settings)
    used: set[str] = set()
    outbounds: list[dict] = []
    tags: list[str] = []
    for e in entries:
        tag = _tag(e["name"], used)
        tags.append(tag)
        stream: dict = {"network": e.get("transport") or "tcp", "security": e.get("security") or "none"}
        sec = (e.get("security") or "none").lower()
        if sec == "reality":
            stream["realitySettings"] = {
                "fingerprint": e.get("fp") or "chrome",
                "serverName": e.get("sni") or "",
                "publicKey": e.get("pbk") or "",
                "shortId": e.get("sid") or "",
                "spiderX": e.get("spx") or "",
                "alpn": alpn,
            }
        elif sec == "tls":
            tls: dict = {"serverName": e.get("sni") or "", "alpn": e.get("alpn") or alpn,
                         "allowInsecure": bool(e.get("insecure"))}
            if e.get("fp"):
                tls["fingerprint"] = e["fp"]
            stream["tlsSettings"] = tls
        net = (e.get("transport") or "tcp").lower()
        if net == "ws":
            ws: dict = {"path": e.get("path") or "/"}
            if e.get("host"):
                ws["headers"] = {"Host": e["host"]}
            stream["wsSettings"] = ws
        elif net in ("xhttp", "httpupgrade"):
            xs: dict = {"path": e.get("path") or "/xhttp"}
            if e.get("host"):
                xs["host"] = e["host"]
            if e.get("mode"):
                xs["mode"] = e["mode"]
            extra = _extra_client(settings, e.get("mode") or "auto")
            if extra:
                xs["extra"] = extra
            stream["xhttpSettings" if net == "xhttp" else "httpUpgradeSettings"] = xs
        elif net == "grpc":
            gs: dict = {"serviceName": e.get("service") or "titan", "multiMode": True}
            if e.get("host"):
                gs["authority"] = e["host"]
            stream["grpcSettings"] = gs
        if sock:
            stream["sockopt"] = dict(sock)

        ob: dict = {"tag": tag, "streamSettings": stream}
        kind = e["kind"]
        if kind == "vless":
            user = {"id": e["user"], "encryption": e.get("cipher") or "none"}
            if e.get("flow"):
                user["flow"] = e["flow"]
            ob.update(protocol="vless",
                      settings={"vnext": [{"address": e["server"], "port": e["port"],
                                           "users": [user]}]})
        elif kind == "vmess":
            ob.update(protocol="vmess",
                      settings={"vnext": [{"address": e["server"], "port": e["port"],
                                          "users": [{"id": e["user"], "alterId": 0,
                                                     "security": e.get("cipher") or "auto"}]}]})
        elif kind == "trojan":
            ob.update(protocol="trojan",
                      settings={"servers": [{"address": e["server"], "port": e["port"],
                                             "password": e.get("password") or e["user"],
                                             "email": tag}]})
        elif kind == "shadowsocks":
            ob.update(protocol="shadowsocks",
                      settings={"servers": [{"address": e["server"], "port": e["port"],
                                             "method": e.get("cipher") or "",
                                             "password": e.get("password") or "",
                                             "level": 0, "email": tag}]})
        else:  # pragma: no cover - parse_link filters these out
            continue
        outbounds.append(ob)

    direct = {"type": "field", "outboundTag": "direct"}
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"listen": "127.0.0.1", "port": 10808, "protocol": "http", "tag": "http"},
            {"listen": "127.0.0.1", "port": 1080, "protocol": "socks", "tag": "socks",
             "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"}},
        ],
        "outbounds": outbounds + [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"},
        ],
        "routing": {"domainStrategy": "AsOrigin", "rules": [
            {"type": "field", "network": "udp", "port": "53", "outboundTag": "direct"},
            {**direct, "ip": ["geoip:private"]},
            {**direct, "domain": ["subdomain:ir"]},
            {"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"},
        ]},
    }


# ------------------------------------------------------------------ sing-box
def singbox_config(entries: list[dict], settings: dict) -> dict:
    """A sing-box/Hiddify config: real fragmentation, uTLS, xudp, and routing."""
    frag = tuning.client_fragment(settings)
    alpn = tuning.client_alpn(settings)
    pe = tuning.packet_encoding(settings)
    used: set[str] = set()
    outbounds, tags = [], []
    for e in entries:
        tag = _tag(e["name"], used)
        tags.append(tag)
        kind = e["kind"]
        ob: dict = {"tag": tag, "server": e["server"], "port": e["port"]}
        if kind == "vless":
            ob["type"] = "vless"
            ob["uuid"] = e["user"]
            ob["packet_encoding"] = pe or "xudp"
            if e.get("flow"):
                ob["flow"] = e["flow"]
        elif kind == "vmess":
            ob["type"] = "vmess"
            ob["uuid"] = e["user"]
            ob["security"] = e.get("cipher") or "auto"
        elif kind == "trojan":
            ob["type"] = "trojan"
            ob["password"] = e.get("password") or e["user"]
        elif kind == "shadowsocks":
            ob["type"] = "shadowsocks"
            ob["method"] = e.get("cipher") or ""
            ob["password"] = e.get("password") or ""
        elif kind == "hysteria2":
            ob["type"] = "hysteria2"
            ob["password"] = e["user"]
            if e.get("obfs") == "salamander" and e.get("obfs_param"):
                ob["obfs"] = {"mode": "salamander", "password": e["obfs_param"]}
        else:  # pragma: no cover
            continue

        sec = (e.get("security") or "none").lower()
        tls: dict = {"enabled": sec != "none", "server_name": e.get("sni") or ""}
        if sec != "none":
            tls["insecure"] = bool(e.get("insecure"))
            tls["alpn"] = e.get("alpn") or alpn
            if e.get("fp"):
                tls["utls"] = {"enabled": True, "fingerprint": e["fp"]}
            if sec == "reality":
                tls["reality"] = {"enabled": True, "public_key": e.get("pbk") or "",
                                  "short_id": e.get("sid") or ""}
            if frag["enabled"]:
                # sing-box fragments on its own (it does not take length/interval in
                # a config), and `record_fragment` is the escalation for a middlebox
                # that still rewrites the ClientHello. `fragment_fallback_delay`
                # keeps it from costing time where it is not needed.
                tls["fragment"] = True
                tls["fragment_fallback_delay"] = frag["fallback_delay"]
                if frag["record_fragment"]:
                    tls["record_fragment"] = True
        if tls["enabled"]:
            ob["tls"] = tls

        net = (e.get("transport") or "tcp").lower()
        if kind != "hysteria2":
            if net == "ws":
                tr: dict = {"type": "ws", "path": e.get("path") or "/"}
                if e.get("host"):
                    tr["headers"] = {"Host": e["host"]}
                ob["transport"] = tr
            elif net in ("xhttp", "httpupgrade"):
                tr = {"type": "http", "path": e.get("path") or "/xhttp", "method": "POST"}
                if e.get("host"):
                    tr["host"] = [e["host"]]
                ob["transport"] = tr
            elif net == "grpc":
                tr = {"type": "grpc", "service_name": e.get("service") or "titan",
                      "idle_timeout": "60s"}
                if e.get("host"):
                    tr["authority"] = e["host"]
                ob["transport"] = tr
        outbounds.append(ob)

    selector = {"type": "selector", "tag": "proxy", "actors": tags + ["direct"]}
    return {
        "log": {"level": "warning", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "local", "address": "local", "detour": "direct"},
                {"tag": "remote", "address": "https://one.one.one.one/dns-query",
                 "detour": "proxy"},
            ],
            "rules": [{"action": "route", "outbound": "local", "domain_suffix": ["ir"]}],
            "final": "remote",
            # MCI/Irancell: an IPv6 DNS answer the path cannot use costs a timeout
            # before the v4 fallback, so pin v4 when the operator profile says so.
            **({"strategy": "prefer_ipv4"} if tuning.profile(settings)["domain_strategy"] else {}),
        },
        "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1",
                      "listen_port": 2080}],
        "outbounds": [selector] + outbounds + [
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
        ],
        "route": {
            "rules": [
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"domain_suffix": ["ir"], "outbound": "direct"},
                {"protocol": "quic", "action": "reject"},
            ],
            "final": "proxy",
            "auto_detect_interface": True,
            "override_android_package": False,
        },
    }


# ------------------------------------------------------------------ mihomo / clash
def clash_dict(entries: list[dict], settings: dict) -> dict:
    prof = tuning.profile(settings)
    alpn = tuning.client_alpn(settings)
    used: set[str] = set()
    proxies, names = [], []
    for e in entries:
        tag = _tag(e["name"], used)
        names.append(tag)
        sec = (e.get("security") or "none").lower()
        proxy: dict = {
            "name": tag, "type": e["kind"], "server": e["server"], "port": e["port"],
            "udp": True,
        }
        if e["kind"] in ("vless", "vmess", "trojan"):
            proxy["uuid"] = e["user"] if e["kind"] != "trojan" else ""
            if e["kind"] == "trojan":
                proxy["password"] = e.get("password") or e["user"]
                proxy.pop("uuid")
            if e["kind"] == "vmess":
                proxy["cipher"] = e.get("cipher") or "auto"
        elif e["kind"] == "shadowsocks":
            proxy["cipher"] = e.get("cipher") or ""
            proxy["password"] = e.get("password") or ""
        elif e["kind"] == "hysteria2":
            proxy["password"] = e["user"]
            if e.get("obfs") == "salamander" and e.get("obfs_param"):
                proxy["obfs"] = "salamander"
                proxy["obfs-password"] = e["obfs_param"]

        if e["kind"] in ("vless", "trojan", "vmess", "shadowsocks"):
            proxy["network"] = {"xhttp": "xhttp", "httpupgrade": "httpupgrade"}.get(
                (e.get("transport") or "tcp").lower(), (e.get("transport") or "tcp").lower())
        if e.get("flow"):
            proxy["flow"] = e["flow"]
        if e.get("transport") in ("tcp", "xhttp", "httpupgrade", "grpc", "ws") and pe_ok(e):
            proxy["packet-encoding"] = prof["packet_encoding"]
        if e["kind"] == "hysteria2":
            # A hy2 link carries sni/insecure but no `security=`; it is always TLS.
            if e.get("sni"):
                proxy["sni"] = e["sni"]
            proxy["skip-cert-verify"] = bool(e.get("insecure"))
        elif sec != "none":
            proxy["tls"] = True
            if e.get("sni"):
                proxy["servername"] = e["sni"]
            proxy["client-fingerprint"] = e.get("fp") or "chrome"
            proxy["alpn"] = e.get("alpn") or alpn
            proxy["skip-cert-verify"] = bool(e.get("insecure"))
            if sec == "reality":
                proxy["reality-opts"] = {"public-key": e.get("pbk") or "",
                                         "short-id": e.get("sid") or ""}
        net = (e.get("transport") or "tcp").lower()
        if net in ("ws", "httpupgrade") and e.get("path"):
            opts = {"path": e["path"]}
            if e.get("host"):
                opts["host"] = e["host"]
            proxy[f"{net}-opts"] = opts
        elif net == "xhttp":
            opts = {"path": e.get("path") or "/xhttp"}
            if e.get("host"):
                opts["host"] = e["host"]
            if e.get("mode"):
                opts["mode"] = e["mode"]
            padding = str(settings.get("xhttp_padding") or "").strip()
            if padding and re.fullmatch(r"\d+(-\d+)?", padding):
                opts["x-padding-bytes"] = padding
            xmux = tuning.client_xmux(settings)
            if xmux and e.get("mode") != "stream-one":
                # mihomo spells xmux `reuse-settings`, with dashes
                opts["reuse-settings"] = {
                    "max-concurrency": xmux["maxConcurrency"],
                    "max-connections": str(xmux["maxConnections"]),
                    "c-max-reuse-times": str(xmux["cMaxReuseTimes"]),
                    "h-max-request-times": xmux["hMaxRequestTimes"],
                    "h-max-reusable-secs": xmux["hMaxReusableSecs"],
                    "h-keep-alive-period": xmux["hKeepAlivePeriod"],
                }
            proxy["xhttp-opts"] = opts
        elif net == "grpc":
            proxy["grpc-opts"] = {"grpc-service-name": e.get("service") or "titan"}
        proxies.append(proxy)

    groups = [{"name": "TiTaN", "type": "select", "proxies": names + ["DIRECT", "REJECT"]}]
    if len(names) > 1:
        groups.append({"name": "TiTaN-Auto", "type": "url-test", "url": "http://www.gstatic.com/generate_204",
                       "interval": 300, "tolerance": 40, "proxies": names})
    return {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "warning",
        # happy-eyeballs for real: mihomo races the A/AAAA instead of waiting out a
        # dead IPv6 attempt, which is exactly what MCI makes you pay for.
        "tcp-concurrent": True,
        "unified-delay": True,
        "ipv6": not bool(prof["domain_strategy"]),
        "global-client-fingerprint": "chrome",
        "proxies": proxies,
        "proxy-groups": groups,
        "dns": {
            "enable": True, "listen": "127.0.0.1:1053", "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16", "fake-ip-filter": ["*.lan", "+.local"],
            "default-nameserver": ["223.5.5.5", "1.1.1.1"],
            "nameserver": ["https://dns.cloudflare.com/dns-query", "223.5.5.5"],
            "proxy-server-nameserver": ["223.5.5.5"],
            "direct-nameserver": ["223.5.5.5"],
        },
        "sniffer": {"enable": True, "force-dns-mapping": True, "parse-pure-ip": True,
                    "override-destination": False,
                    "sniff": {"HTTP": {"ports": [80, 8080]}, "TLS": {"ports": [443]},
                              "QUIC": {"ports": [443, 8443]}}},
        "rules": [
            "GEOIP,LAN,DIRECT,no-resolve",
            "DOMAIN-SUFFIX,local,DIRECT",
            "DOMAIN-SUFFIX,ir,DIRECT",
            "GEOIP,IR,DIRECT,no-resolve",
            f"MATCH,{'TiTaN-Auto' if len(names) > 1 else 'TiTaN'}",
        ],
        "profile": {"store-selections": True, "store-fake-ip": True},
    }


def pe_ok(e: dict) -> bool:
    """xudp-style packet encoding only means something on raw TCP/WS-ish dials."""
    return (e.get("transport") or "tcp").lower() in ("tcp", "ws", "xhttp", "httpupgrade", "grpc")


# ------------------------------------------------------------------ yaml (no dependency)
def _scalar(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    special = ("", "~", "null", "true", "false", "yes", "no", "on", "off")
    needs_quote = (text in special or text != text.strip() or
                   text[0] in "-?:,[]{}#&*!|>%@`\"'" or
                   ": " in text or " #" in text or
                   bool(re.fullmatch(r"[-+]?\d+(\.\d+)?", text)) or
                   any(ch in text for ch in "\n\t"))
    if needs_quote:
        return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return text


def dump_yaml(data, indent: int = 0) -> str:
    """A YAML block-style dump small enough to audit, with no third-party import.

    Only the subset this module emits: mappings, lists, scalars. `yaml.safe_load`
    round-trips it (see tests/test_subfmt.py), which is the only guarantee needed.
    """
    pad = "  " * indent
    out: list[str] = []
    if isinstance(data, dict):
        for key, value in data.items():
            k = _scalar(key)
            if isinstance(value, (dict, list)) and value:
                out.append(f"{pad}{k}:")
                out.append(dump_yaml(value, indent + 1))
            elif isinstance(value, dict):
                out.append(f"{pad}{k}: " + "{}")
            elif isinstance(value, list):
                out.append(f"{pad}{k}: " + "[]")
            else:
                out.append(f"{pad}{k}: {_scalar(value)}")
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and item:
                body = dump_yaml(item, indent + 1)
                first, _, rest = body.partition("\n")
                out.append(f"{pad}- {first.lstrip()}")
                if rest:
                    out.append(rest)
            elif isinstance(item, list):
                out.append(f"{pad}-")
                out.append(dump_yaml(item, indent + 1))
            else:
                out.append(f"{pad}- {_scalar(item)}")
    else:
        out.append(f"{pad}{_scalar(data)}")
    return "\n".join(out)


# ------------------------------------------------------------------ entry point
def render(fmt: str, links: list[str], settings: dict, meta: dict | None = None) -> dict:
    """Build one client config. Returns {text, media_type, filename, notes, skipped}."""
    fmt = (fmt or "").strip().lower()
    if fmt not in FORMATS:
        raise ValueError(f"unknown format: {fmt}")
    entries, skipped = parse_links(links)
    if fmt == "xray":
        doc: object = xray_config(entries, settings)
    elif fmt == "singbox":
        doc = singbox_config(entries, settings)
    else:
        doc = clash_dict(entries, settings)
    text = (json.dumps(doc, ensure_ascii=False, indent=2) if fmt != "clash"
            else "# generated by titan-panel — " + str((meta or {}).get("title") or "subscription") + "\n"
                 + dump_yaml(doc) + "\n")

    prof = tuning.profile(settings)
    notes = [
        f"پروفایل: {prof['label']['fa']} — {prof['notes']['fa']}",
        "اگر اپت fragment را از لینک نمی‌خواند (v2rayNG/Hiddify)، همین فایل را import کن.",
    ]
    if any(e.get("flow") for e in entries):
        notes.append("flow=xtls-rprx-vision فقط روی TCP خام کار می‌کند؛ روی WS/xhttp آن را روشن نکن.")
    if fmt == "xray":
        notes.append("sockopt روی Windows/Android بی‌اثر است (BBR در کرنل نیست); روی دسکتاپ لینوکسی اثر دارد.")
    if fmt == "clash":
        notes.append("mihomo fragment را از این فایل نمی‌خواند؛ گزینهٔ TLS Fragment را در خود اپ روشن کن.")
    if skipped:
        notes.append(f"{len(skipped)} لینک به فایل نرفت: " + "; ".join(s["reason"] for s in skipped[:3]))
    key = quote(str((meta or {}).get("key") or "titan"), safe="")
    return {
        "format": fmt,
        "text": text,
        "media_type": _MEDIA[fmt] + "; charset=utf-8",
        "filename": f"titan-{key}.{_EXT[fmt]}",
        "entries": len(entries),
        "skipped": skipped,
        "notes": notes,
    }
