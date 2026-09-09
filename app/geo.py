"""Geolocation for node addresses — hostname/IP → country, city, flag.

Why this file exists
--------------------
The admin adds a node by pasting *only* its domain. The panel must then say
where that server actually is, and the naive way (resolve the domain, ask a
GeoIP API) is exactly what produced the complaint "it shows the same USA / the
main server". Three real problems with that naive answer:

* a Railway/Render platform domain resolves to the *platform's* anycast range,
  not to the node's datacenter — the answer is "US" no matter where the VPS is;
* a domain behind a CDN (Cloudflare) reports the CDN's announced location;
* one provider (ip-api, plain HTTP) fails or times out and the field stays
  empty forever.

So detection has three layers, best first, and always says which one answered:

1. **ask the node itself** (`GET /api/geo-self`, node-role panel + its token):
   the node resolves *its own* egress IP, which is the ground truth;
2. **public GeoIP providers** with fallback (ipwho.is → ip-api → ipinfo if a
   token is configured), on the resolved IP;
3. **notes** that tell the admin when the answer cannot be trusted (platform
   domain, CDN ASN, same location as this panel), so "دقیق" never turns into a
   confident lie.

Nothing here is fatal: every path returns ``{}`` (plus ``error``) so a node can
always be created, and results are cached per host in the DB.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import socket
import time

log = logging.getLogger("titan.geo")

#: how long a cached lookup stays fresh (6 h)
CACHE_TTL = 6 * 3600
_TIMEOUT = 4.0

_HOST_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9.\-_]{0,251}[a-zA-Z0-9])?$")

#: domains whose DNS answer belongs to the platform, not to the server
PLATFORM_SUFFIXES = (
    ".up.railway.app", ".railway.app", ".workers.dev", ".vercel.app",
    ".netlify.app", ".onrender.com", ".fly.dev", ".azurewebsites.net",
    ".herokuapp.com", ".web.app", ".pages.dev",
)

_CDN_HINTS = ("cloudflare", "fastly", "akamai", "amazon.com, inc", "google llc",
              "microsoft corporation", "cdn77", "incapsula", "imperva")

#: provider fetchers take an ip and return a dict of geo keys (or {})
_PROVIDERS = (
    ("ipwho.is", "https://ipwho.is/{ip}"),
    ("ip-api", "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,connection"),
    ("ipinfo", "https://ipinfo.io/{ip}/json"),
)

# ------------------------------------------------------------------ primitives
def http_json(url: str, timeout: float = _TIMEOUT, headers: dict | None = None) -> dict:
    """One GET returning JSON. Isolated so tests can stub the whole network."""
    import httpx

    with httpx.Client(timeout=timeout, headers=headers or {}, follow_redirects=True) as c:
        return c.get(url).json()


def resolve_ip(host: str, timeout: float = 2.5) -> str:
    """First IPv4 (then IPv6) answer for `host`, or ""."""
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                infos = socket.getaddrinfo(host, None, family, socket.SOCK_STREAM)
            except (OSError, UnicodeError):
                continue
            if infos:
                return str(infos[0][4][0])
    except Exception as exc:  # noqa: BLE001
        log.debug("resolve %s failed: %s", host, exc)
    finally:
        socket.setdefaulttimeout(old)
    return ""


def clean_host(value) -> str:
    """`https://user@Host:8443/path` -> `host` (lower-cased, no brackets)."""
    host = str(value or "").strip()
    host = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", host)
    host = host.split("/", 1)[0].rsplit("@", 1)[-1]
    host = re.sub(r":\d+$", "", host)
    return host.strip().strip("[]").lower()


def flag_from_code(code: str) -> str:
    code = (code or "").upper().strip()
    if len(code) == 2 and code.isalpha():
        return "".join(chr(0x1F1E6 + (ord(c) - ord("A"))) for c in code)
    return "🏳️"


def _is_usable_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_unspecified)


def _clean_geo(city, country, cc) -> dict:
    cc = (str(cc or "")).strip().upper()[:2]
    if not re.fullmatch(r"[A-Z]{2}", cc or ""):
        return {}
    country = (str(country or "")).strip()[:64]
    return {
        "city": (str(city or "")).strip()[:64],
        # some providers (ipinfo) only return the ISO code; showing the code is
        # better than showing nothing
        "country": country or cc,
        "country_code": cc,
        "flag": flag_from_code(cc),
    }


def _from_provider_json(name: str, d: dict) -> tuple[dict, str]:
    """Normalise one provider's payload into (geo, isp)."""
    if not isinstance(d, dict):
        return {}, ""
    if name == "ipwho.is":
        if d.get("success") is False:
            return {}, ""
        conn = d.get("connection") or {}
        return (_clean_geo(d.get("city"), d.get("country"), d.get("country_code")),
                str(conn.get("isp") or ""))
    if name == "ip-api":
        if d.get("status") != "success":
            return {}, ""
        conn = d.get("connection") or {}
        return (_clean_geo(d.get("city"), d.get("country"), d.get("countryCode")),
                str(conn.get("isp") or ""))
    # ipinfo: {city, country:"US", org:"AS13335 Cloudflare, Inc."} - `country` is
    # already the ISO code there, and `org` carries the ASN owner we check for CDNs.
    return _clean_geo(d.get("city"), "", d.get("country")), str(d.get("org") or "")


# ------------------------------------------------------------------- the cache
def _cache_get(host: str) -> dict:
    try:
        from . import db
        raw = db.get_meta(f"geo:{host}")
    except Exception:  # noqa: BLE001 - cache is an optimisation, never a requirement
        return {}
    if not raw:
        return {}
    try:
        row = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    if time.time() - float(row.get("ts") or 0) > CACHE_TTL:
        return {}
    return row.get("geo") or {}


def _cache_put(host: str, geo: dict) -> None:
    if not geo or not geo.get("country_code"):
        return
    try:
        from . import db
        db.set_meta(f"geo:{host}", json.dumps({"ts": time.time(), "geo": geo}, ensure_ascii=False))
    except Exception:  # noqa: BLE001
        pass


# --------------------------------------------------------------- the providers
def lookup_ip(ip: str) -> tuple[dict, str]:
    """Try each provider in order. Returns (geo, provider_name)."""
    from . import config

    for name, template in _PROVIDERS:
        if name == "ipinfo" and not config.IPINFO_TOKEN:
            continue
        url = template.format(ip=ip)
        if name == "ipinfo":
            url += f"?token={config.IPINFO_TOKEN}"
        try:
            data = http_json(url)
        except Exception as exc:  # noqa: BLE001 - provider down/timeout is normal
            log.debug("geo provider %s failed: %s", name, exc)
            continue
        geo, isp = _from_provider_json(name, data)
        if geo:
            geo["isp"] = isp[:64]
            return geo, name
    return {}, ""


def egress_ip() -> str:
    """The IP this process leaves with — the accurate answer for a node."""
    for probe in ("https://api.ipify.org?format=json", "https://ifconfig.co/json",
                  "https://ipinfo.io/json"):
        try:
            data = http_json(probe, timeout=3.0)
        except Exception:  # noqa: BLE001
            continue
        ip = str((data or {}).get("ip") or "").strip()
        if _is_usable_ip(ip):
            return ip
    return ""


# ------------------------------------------------------------------- node side
def detect_self() -> dict:
    """What a node reports about itself (its own egress IP → geo)."""
    ip = egress_ip()
    if not ip:
        return {"error": "no-egress-ip", "ip": ""}
    geo, provider = lookup_ip(ip)
    if not geo:
        return {"error": "provider-failed", "ip": ip}
    geo.update({"ip": ip, "source": f"node:{provider}", "notes": []})
    return geo


# ---------------------------------------------------------------- main side
def _platform_domain(host: str) -> bool:
    return any(host.endswith(suf) or host == suf.lstrip(".") for suf in PLATFORM_SUFFIXES)


def _ask_the_node(host: str, token: str) -> dict:
    """Best answer: the node tells us where it is. Empty dict if unreachable."""
    if not token:
        return {}
    for scheme in ("https", "http"):
        try:
            data = http_json(f"{scheme}://{host}/api/geo-self", timeout=4.0,
                             headers={"X-Node-Token": token})
        except Exception:  # noqa: BLE001 - old node versions 404 here
            continue
        if isinstance(data, dict) and data.get("country_code"):
            out = _clean_geo(data.get("city"), data.get("country"), data.get("country_code"))
            if out:
                out["ip"] = str(data.get("ip") or "")[:64]
                out["source"] = "node"
                return out
    return {}


def detect(address: str, *, token: str = "", force: bool = False) -> dict:
    """Locate a node address. Always returns a dict; `country_code` may be absent.

    Keys when successful: city, country, country_code, flag, ip, source, notes[].
    """
    from . import config

    host = clean_host(address)
    if not host or not _HOST_RE.match(host):
        return {"error": "invalid-address", "notes": []}

    cached = {} if force else _cache_get(host)
    notes: list[str] = []
    if cached:
        out = dict(cached)
        out["source"] = f"{out.get('source', 'ip')} (cached)"
        out["notes"] = _notes_for(host, out)
        return out

    geo = _ask_the_node(host, token)
    ip = geo.get("ip") or ""
    if not geo:
        try:
            ipaddress.ip_address(host)
            ip = host
        except ValueError:
            ip = resolve_ip(host)
        if not _is_usable_ip(ip):
            return {"error": "unresolved" if not ip else "non-public-ip",
                    "ip": ip, "host": host, "notes": []}
        geo, provider = lookup_ip(ip)
        if not geo:
            return {"error": "provider-failed", "ip": ip, "host": host, "notes": []}
        geo["source"] = f"ip:{provider}"
    geo["ip"] = ip

    notes = _notes_for(host, geo)
    geo["notes"] = notes
    _cache_put(host, {k: v for k, v in geo.items() if k != "notes"})
    if config.IS_RAILWAY and _platform_domain(host):
        log.info("geo: %s is a platform domain; country comes from the platform's "
                 "anycast IP, not the node's datacenter", host)
    return geo


def _notes_for(host: str, geo: dict) -> list[str]:
    """Explain every case where the answer is technically right but misleading."""
    notes: list[str] = []
    isp = (geo.get("isp") or "").lower()
    code = geo.get("country_code") or ""
    if _platform_domain(host):
        notes.append(
            f"«{host}» دامنهٔ پلتفرم است: DNS آن به IP مشترک {code or 'پلتفرم'} می‌رسد، نه "
            "دیتاسنتر واقعی سرور. برای country/city دقیق، IP یا دامنهٔ مستقیم نود را بزن.")
    if any(h in isp for h in _CDN_HINTS):
        notes.append(
            f"IP در بازهٔ «{geo.get('isp')}» است (CDN/ابر): کشور نشان‌داده‌شده محلِ "
            "هر-جایِ آن سرویس است، نه محل فیزیکی نود.")
    try:
        from . import db
        own = db.get_settings().get("public_domain") or ""
    except Exception:  # noqa: BLE001
        own = ""
    if own and clean_host(own) == host:
        notes.append("این نشانی همان دامنهٔ پنل اصلی است؛ اگر نود جداست، آدرس نود را وارد کن.")
    return notes
