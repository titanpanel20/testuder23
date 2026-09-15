"""REALITY (VLESS) key management.

REALITY needs a stable x25519 keypair per panel. We generate it once with the
Xray binary (``xray x25519``) and persist it in the database so connection links
stay valid across restarts. The private key lives in `meta` (never exposed to the
frontend); the public key + short id are stored as settings so the link builder
can read them.

Keeping those keys valid across a *redeploy* therefore depends on the database
surviving it - i.e. on a persistent Volume (`/app/data` on Railway). Without one,
every deploy generates a new keypair and previously published `pbk` values die.
Rotation
--------
`shortIds` and `serverNames` are lists, so a rotation does not have to break the
links already in the wild: the new value becomes the one handed out to new links,
while the previous ones stay accepted for a grace period (see `accepted_*`).
Changing `dest` is different - the target site is what Reality hides behind, so it
must be measured, not guessed. `probe_dest()` measures from *this* host, which is
exactly what an unreachable-by-DPI destination looks like from the server side; it
is not a reading of the subscriber's network.
"""
import asyncio
import json
import logging
import secrets
import socket
import ssl
import subprocess
import time

from . import config, db

log = logging.getLogger("titan.reality")

#: Destinations that are widely reported to behave well as a Reality target:
#: TLS 1.3, X25519, a huge anycast footprint, and a path that is expensive for a
#: censor to block. Nothing here is a promise - `suggest()` re-measures.
CANDIDATE_DESTS: tuple[tuple[str, int, str], ...] = (
    ("www.microsoft.com", 443, "TLS1.3 + X25519, anycast, low collateral damage"),
    ("speed.cloudflare.com", 443, "big pipes, but popular: rate limits and DPI attention"),
    ("www.apple.com", 443, "stable, strict TLS stack, no 0-RTT weirdness"),
    ("aurora-program.name", 443, "obscure, low-traffic, cheap to imitate"),
    ("developer.ibm.com", 443, "IBMB, boring enough to survive"),
)


def _meta_list(key: str, keep_empty: bool = False) -> list[str]:
    """A JSON list in `meta`. `keep_empty` matters for shortIds: "" is a real value
    there (it is the short id every pre-rotation link carries), not a missing one."""
    raw = db.get_meta(key) or ""
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except ValueError:
        parts = str(raw).split(",")
        return parts if keep_empty else [p for p in parts if p]
    if not isinstance(data, list):
        return []
    return [str(p) for p in data if keep_empty or str(p)]


def _set_meta_list(key: str, values: list[str]) -> None:
    db.set_meta(key, json.dumps(values[-12:]))


def accepted_short_ids(primary: str = "") -> list[str]:
    """Every short id this panel still honours, newest last, plus "" if allowed."""
    sid = primary or db.get_meta("reality_sid") or ""
    ids = _meta_list("reality_sids", keep_empty=True)
    out: list[str] = []
    for value in ids + [sid]:
        if value not in out:
            out.append(value)
    # A panel that never rotated has no short id, and its links say `sid=`: the
    # inbound must accept "" or every existing subscriber is locked out.
    return out or [""]


def accepted_server_names() -> list[str]:
    """`serverNames` for the inbound: current + the ones older links still send."""
    current = sorted({s for s in (config.REALITY_SNI,
                                  db.get_settings().get("reality_sni") or "") if s})
    out: list[str] = []
    for value in _meta_list("reality_snis") + current:
        if value and value not in out:
            out.append(value)
    return out or list(current or [config.REALITY_SNI])


def rotate_short_id(count: int = 1, keep_grace: bool = True) -> dict:
    """Mint fresh short ids; old ones keep working until the grace list is cleared.

    Short ids are hex, even length, at most 16 chars. They are not secrets (they
    ship inside every link); they only let the server tell clients apart.
    """
    n = max(1, min(int(count or 1), 8))
    new = [secrets.token_hex(4) for _ in range(n)]
    # `accepted_short_ids()` already contains "" for a panel that never set a short
    # id, which is exactly the sid every pre-rotation link carries - so rotating
    # cannot lock those subscribers out.
    old = accepted_short_ids() if keep_grace else []
    sid = new[0]
    db.set_meta("reality_sid", sid)
    _set_meta_list("reality_sids", [s for s in old if s != sid] + new)
    db.set_setting("reality_sid", sid)
    log.info("Reality short ids rotated (new=%s, accepting %d)", sid, len(old) + n)
    return {"sid": sid, "minted": new, "accepting": accepted_short_ids()}


def rotate_sni(sni: str = "", dest: str = "", keep_grace: bool = True) -> dict:
    """Point the panel at a new masquerade target, optionally keeping the old SNI."""
    sni = (sni or "").strip()
    dest = (dest or "").strip()
    if sni:
        old = accepted_server_names() if keep_grace else []
        db.set_setting("reality_sni", sni)
        _set_meta_list("reality_snis", [s for s in old if s != sni] + [sni])
    if dest:
        db.set_setting("reality_dest", dest)
    log.info("Reality masquerade updated (sni=%s dest=%s)", sni or "-", dest or "-")
    return {"sni": sni or db.get_settings().get("reality_sni", ""),
            "dest": dest or db.get_settings().get("reality_dest", ""),
            "accepting": accepted_server_names()}


def _raw_probe(dest: str, port: int, timeout: float) -> dict:
    """One blocking TCP+TLS handshake. Runs in a thread; facts only, no verdict.

    `ok` means "this target can carry Reality from here": TLS 1.3 and, if the
    server picked a curve, X25519. Nothing here says the target is a *good*
    disguise or that a subscriber can reach it - only that the handshake we need
    succeeds from this host.
    """
    out = {"ok": False, "handshake_ms": None, "tls13": False, "alpn": "", "group": "",
           "reason": ""}
    started = time.monotonic()
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        with (socket.create_connection((dest, port), timeout=timeout) as sock,
              ctx.wrap_socket(sock, server_hostname=dest) as tls):
            out["handshake_ms"] = round((time.monotonic() - started) * 1000, 1)
            out["tls13"] = tls.version() == "TLSv1.3"
            out["alpn"] = tls.selected_alpn_protocol() or ""
            try:
                out["group"] = str(tls.selected_group.get("name") or "")
            except (AttributeError, ValueError):
                out["group"] = ""
            out["ok"] = bool(out["tls13"] and (not out["group"] or out["group"] == "x25519"))
    except ssl.SSLError as e:
        out["reason"] = f"tls-error: {str(e)[:120]}"
        out["handshake_ms"] = round((time.monotonic() - started) * 1000, 1)
    except (socket.timeout, TimeoutError):
        out["reason"] = "timeout"
    except OSError as e:
        out["reason"] = f"{type(e).__name__}: {str(e)[:120]}"
    if out["tls13"] and out["group"] and out["group"] != "x25519":
        out["reason"] = f"key share is {out['group']}, Reality wants x25519"
    return out


async def probe_dest(dest: str, port: int = 443, timeout: float = 4.0) -> dict:
    dest = (dest or "").strip()
    if not dest:
        return {"dest": "", "ok": False, "reason": "no-dest"}
    loop = asyncio.get_running_loop()
    res = await loop.run_in_executor(None, _raw_probe, dest, int(port), float(timeout))
    res["dest"] = f"{dest}:{port}"
    return res


async def suggest(limit: int = 5, timeout: float = 4.0) -> list[dict]:
    """Measure every candidate from here and rank: reachable, fast, sane TLS."""
    probes = await asyncio.gather(*[
        probe_dest(host, port, timeout) for host, port, _why in CANDIDATE_DESTS
    ])
    for probe, (_host, _port, why) in zip(probes, CANDIDATE_DESTS, strict=True):
        probe["note"] = why
    good = [p for p in probes if p.get("ok")]
    good.sort(key=lambda p: p.get("handshake_ms") or 9e9)
    return (good + [p for p in probes if not p.get("ok")])[:max(1, int(limit or 5))]


def _xray_x25519() -> tuple[str, str] | None:
    """Return (private_key, public_key) from `xray x25519`, or None."""
    try:
        out = subprocess.run(
            [config.XRAY_BIN, "x25519"],
            capture_output=True, text=True, timeout=20,
        )
    except Exception as e:  # noqa: BLE001
        log.warning("xray x25519 failed: %s", e)
        return None
    priv = pub = ""
    for line in (out.stdout or "").splitlines():
        if line.startswith("Private key:"):
            priv = line.split(":", 1)[1].strip()
        elif line.startswith("Public key:"):
            pub = line.split(":", 1)[1].strip()
    if priv and pub:
        return priv, pub
    return None


def ensure_reality_keys() -> dict | None:
    """Return {priv, pub, sid, sni, dest} for the panel, generating once.

    Returns None when no Xray binary is available (dev/mock mode) and no keys
    have been generated yet — Reality inbounds are then skipped.
    """
    priv = db.get_meta("reality_priv")
    if priv:
        return {
            "priv": priv,
            "pub": db.get_meta("reality_pub") or "",
            "sid": db.get_meta("reality_sid") or "",
            "sni": config.REALITY_SNI,
            "dest": config.REALITY_DEST,
        }
    keys = _xray_x25519()
    if not keys:
        return None
    priv, pub = keys
    sid = secrets.token_hex(4)
    db.set_meta("reality_priv", priv)
    db.set_meta("reality_pub", pub)
    db.set_meta("reality_sid", sid)
    # public values → settings, so get_settings() carries them to link builder
    db.set_setting("reality_pub", pub)
    db.set_setting("reality_sid", sid)
    db.set_setting("reality_sni", config.REALITY_SNI)
    db.set_setting("reality_dest", config.REALITY_DEST)
    log.info("Reality keypair generated (sni=%s dest=%s)", config.REALITY_SNI, config.REALITY_DEST)
    return {"priv": priv, "pub": pub, "sid": sid, "sni": config.REALITY_SNI, "dest": config.REALITY_DEST}


def apply_reality_config(data: dict) -> None:
    """Node side: accept the main panel's reality keypair + short id."""
    if not data or not data.get("priv"):
        return
    db.set_meta("reality_priv", data["priv"])
    db.set_meta("reality_pub", data.get("pub", ""))
    db.set_meta("reality_sid", data.get("sid", ""))
    db.set_setting("reality_pub", data.get("pub", ""))
    db.set_setting("reality_sid", data.get("sid", ""))
    db.set_setting("reality_sni", config.REALITY_SNI)
    db.set_setting("reality_dest", config.REALITY_DEST)
