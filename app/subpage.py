"""The public subscription page - what a *human* sees when they open `/sub/<key>`.

A VPN client and a browser want two different things from the same URL. Clients
must keep getting base64 (that is all v2rayNG / Happ / Streisand / Hiddify
parse), so this module is only reached when the visitor actually asks for HTML.

Rules this page follows, and why:

* Same payload, nothing more. It renders exactly the links the base64 body
  carries - no member roster, no user ids, no admin notes, no settings. A group
  link is shared by everyone in it, so one member must not learn who else is in
  the group or read their usage separately (that is why `/sub/<key>/json`
  aggregates instead of listing members).
* No session, no cookies, no third-party requests. Every asset is inline, so
  the page still works on a phone with no DNS for the panel's CDN of choice and
  leaks nothing to flagcdn.com or a font host.
* Read-only by design. Nothing here mutates state; rotating a link stays an
  admin action inside the panel.
"""
from __future__ import annotations

import base64
import io
import json
import time
from urllib.parse import unquote, urlsplit

try:  # qrcode + Pillow are in requirements.txt, but a slim install must not 500
    import qrcode as _qrcode
except Exception:  # pragma: no cover - exercised by the "no qrcode" test
    _qrcode = None

#: QR bitmaps cost a PIL image each; a 200-member group must not build 200 of them.
MAX_QR = 24

#: schemes a phone can hand to a VPN app. Anything else is shown but never made
#: into a clickable href, so a name/remark that was crafted as `javascript:...`
#: cannot turn the "open in app" button into an XSS payload.
OPENABLE = {"vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "wireguard"}

_PROTOCOL_LABEL = {
    "vless": "VLESS",
    "vmess": "VMess",
    "trojan": "Trojan",
    "ss": "Shadowsocks",
    "shadowsocks": "Shadowsocks",
    "hysteria2": "Hysteria2",
    "hy2": "Hysteria2",
    "wireguard": "WireGuard",
}

_UNITS = [(1024 ** 4, "TB"), (1024 ** 3, "GB"), (1024 ** 2, "MB"), (1024, "KB")]


def humansize(n: int | float | None) -> str:
    """Bytes in the unit a human expects, no trailing ".0"."""
    try:
        n = float(n or 0)
    except (TypeError, ValueError):
        return "0"
    if n <= 0:
        return "0"
    for step, unit in _UNITS:
        if n >= step:
            val = n / step
            return f"{val:.0f} {unit}" if val >= 100 else f"{val:.2f} {unit}"
    return f"{int(n)} B"


def qr_data_uri(text: str, box: int = 5) -> str:
    """A PNG QR code as a data URI ("" when the QR library is unavailable).

    Inline data URIs rather than a route: the page then needs no extra request,
    works from `file://` if someone saves it, and the codes cannot be fetched by
    guessing a URL.
    """
    if not text or _qrcode is None:
        return ""
    try:
        img = _qrcode.make(
            text, box_size=box, border=2,
            error_correction=_qrcode.constants.ERROR_CORRECT_M,
        )
        buf = io.BytesIO()
        img.save(buf, format="PNG", optimize=True)
    except Exception:  # a too-long link must not take the page down
        return ""
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def _vmess_body(parts) -> dict:
    """Decoded json of a `vmess://<base64 json>#remark` link ({} if unparseable).

    Needed because a VMess link has no host in its URL: everything is inside the
    base64 blob, so a table of endpoints would otherwise print base64 garbage.
    """
    if parts is None:
        return {}
    body = (parts.netloc or "").strip("/")
    if not body:
        return {}
    try:
        blob = json.loads(base64.b64decode(body + "=" * (-len(body) % 4)).decode("utf-8"))
    except (ValueError, TypeError, UnicodeDecodeError):
        return {}
    return blob if isinstance(blob, dict) else {}


def link_meta(link: str, index: int = 0, with_qr: bool = True) -> dict:
    """Describe one config link for display (protocol, host, transport, label).

    Everything shown is already visible in the link itself - this only parses it,
    so the page can render a table instead of a wall of `vless://...`. A link it
    cannot understand is still shown, just unlabelled: rendering never fails.
    """
    try:
        parts = urlsplit(link)
    except ValueError:
        parts = None
    scheme = (parts.scheme if parts else "").lower()
    host = (parts.hostname or "") if parts else ""
    try:
        port = parts.port if parts else None
    except ValueError:
        port = None
    frag = unquote(parts.fragment or "") if parts else ""
    params = {}
    for chunk in ((parts.query if parts else "") or "").split("&"):
        if "=" in chunk:
            k, v = chunk.split("=", 1)
            params[k] = unquote(v)
    transport = (params.get("type") or params.get("mode") or "").lower()
    security = (params.get("security") or "").lower()
    sni = params.get("sni") or params.get("peer") or ""
    if not security and sni:
        security = "tls"
    if scheme == "vmess":
        blob = _vmess_body(parts)
        if blob:
            host = str(blob.get("add") or host)
            port = blob.get("port") or port
            transport = str(blob.get("net") or transport or "").lower()
            security = str(blob.get("tls") or "").lower() or security
            sni = str(blob.get("sni") or sni or "")
            frag = frag or str(blob.get("ps") or "")
    if not transport:
        # hysteria2 and wireguard links carry no `type=` at all
        if scheme in ("hysteria2", "hy2"):
            transport = "brutal"
        elif scheme == "wireguard":
            transport = "client"
    security = {"reality": "REALITY", "tls": "TLS"}.get(security, security) or "none"
    return {
        "idx": index,
        "link": link,
        "protocol": scheme,
        "protocol_label": _PROTOCOL_LABEL.get(scheme, (scheme or "link").upper()),
        "label": frag or f"{scheme or 'link'}://{host or '?'}",
        "host": host,
        "port": port or "",
        "endpoint": f"{host}:{port}" if host and port else host,
        "transport": transport,
        "security": security,
        "sni": sni,
        "fp": params.get("fp") or "",
        "path": params.get("path") or "",
        "remark": frag,
        "openable": scheme in OPENABLE,
        "qr": qr_data_uri(link, box=4) if with_qr else "",
    }


def stamp(ts: int | float | None) -> str:
    """A plain Gregorian date for the no-JavaScript case (JS replaces it with a
    Jalali one via Intl, which needs no library)."""
    if not ts:
        return ""
    try:
        return time.strftime("%Y-%m-%d", time.gmtime(float(ts)))
    except (OverflowError, OSError, ValueError):
        return ""


#: Which app gets which file. `fmt` is the subfmt key; the routes live in main.py.
_DOWNLOADS = (
    ("singbox", "sing-box / Hiddify", "singbox.json"),
    ("clash", "Clash Meta / mihomo", "clash.yaml"),
    ("xray", "v2rayN / v2rayNG", "xray.json"),
)
_PROFILE_LABELS = {"general": "عمومی", "mci": "همراه اول", "irancell": "ایرانسل"}


def _downloads(model: dict) -> list[dict]:
    """Per-app files, with the page's `?profile=` kept on the URL."""
    base = (model.get("sub_url") or "").rstrip("/")
    query = model.get("sub_query") or ""
    return [{"fmt": fmt, "label": label, "url": f"{base}/{suffix}{query}",
             "file": f"titan-{fmt}.{suffix.rsplit('.', 1)[-1]}"}
            for fmt, label, suffix in _DOWNLOADS]


def _profiles(model: dict) -> list[dict]:
    """One URL per operator profile - what the admin hands out as a one-click.

    `?profile=` only changes the *generated file*; nothing stored is touched, so a
    subscriber can try MCI today and Irancell tomorrow without the admin flipping
    a global switch.
    """
    base = (model.get("sub_url") or "").rstrip("/")
    active = model.get("profile") or "general"
    out = []
    for key, label in _PROFILE_LABELS.items():
        url = base if key == "general" else f"{base}?profile={key}"
        out.append({"key": key, "label": label, "url": url, "active": key == active})
    return out


def _notes(model: dict) -> list[str]:
    notes = list(model.get("config_notes") or [])
    if not notes:
        notes = [
            "اگر اپت گزینهٔ Fragment در تنظیماتش دارد و لینک برایش کاری نکرد، این فایل را import کن.",
            "فایل‌ها فقط کانفیگِ دستگاه تو را می‌سازند؛ روی سرور چیزی تغییر نمی‌دهند.",
        ]
    return notes


def decorate(model: dict) -> dict:
    """Fill in the derived view fields (configs, QR, progress, copy text)."""
    links = model.get("links") or []
    want_qr = len(links) <= MAX_QR
    model["configs"] = [link_meta(l, i, with_qr=want_qr) for i, l in enumerate(links)]
    model.setdefault("share_url", model.get("sub_url") or "")
    # The QR must encode the same URL the copy button hands over, otherwise a
    # profile-picked page prints a QR that quietly drops the profile.
    model["qr"] = qr_data_uri(model.get("share_url") or "")
    model["has_qr"] = bool(model["qr"])
    used = int(model.get("used") or 0)
    total = int(model.get("total") or 0)
    model["pct"] = min(100, round(used * 100 / total)) if total > 0 else 0
    model["expire_date"] = stamp(int(model.get("expire_at") or 0))
    model.setdefault("configs_count", len(model["configs"]))
    model["downloads"] = _downloads(model)
    model["profiles"] = _profiles(model)
    model["notes"] = _notes(model)
    model["used_text"] = humansize(used)
    model["total_text"] = humansize(total) if total else "∞"
    model["left_text"] = humansize(total - used) if total > used else "۰"
    model["no_qr_reason"] = (
        _qrcode is None
        or ("این صفحه بیش از حد کانفیگ دارد تا QR هر کدام را بسازد" if links and not want_qr else "")
    )
    return model
