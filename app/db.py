"""SQLite persistence layer for TiTaN.

Thread/async safe via a process-wide lock. Uses WAL mode for concurrent reads
while writes are serialized.
"""
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
from typing import Any

from . import config

_lock = threading.RLock()
_conn: sqlite3.Connection | None = None


def coerce_node_id(v) -> int:
    """Coerce a node_id, preserving 0 (auto / nearest node)."""
    try:
        return int(v) if v not in (None, "") else 1
    except (TypeError, ValueError):
        return 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS admin (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    username      TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    salt          TEXT NOT NULL,
    created_at    REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    uid             TEXT UNIQUE NOT NULL,
    uuid            TEXT UNIQUE NOT NULL,
    name            TEXT NOT NULL DEFAULT 'User',
    note            TEXT NOT NULL DEFAULT '',
    enabled         INTEGER NOT NULL DEFAULT 1,
    protocol        TEXT NOT NULL DEFAULT 'vless',
    transport       TEXT NOT NULL DEFAULT 'ws',
    security        TEXT NOT NULL DEFAULT 'tls',
    fingerprint     TEXT NOT NULL DEFAULT 'chrome',
    alpn            TEXT NOT NULL DEFAULT 'http/1.1',
    public_key      TEXT NOT NULL DEFAULT '',
    short_id        TEXT NOT NULL DEFAULT '',
    spider_x        TEXT NOT NULL DEFAULT '',
    max_devices     INTEGER NOT NULL DEFAULT 0,
    first_device_uid TEXT NOT NULL DEFAULT '',
    allowed_ips     TEXT NOT NULL DEFAULT '',
    quota_bytes     INTEGER NOT NULL DEFAULT 0,
    expire_at       REAL,
    created_at      REAL NOT NULL,
    used_up         INTEGER NOT NULL DEFAULT 0,
    used_down       INTEGER NOT NULL DEFAULT 0,
    request_count   INTEGER NOT NULL DEFAULT 0,
    max_requests    INTEGER NOT NULL DEFAULT 0,
    avatar          TEXT NOT NULL DEFAULT '',
    ss_method       TEXT NOT NULL DEFAULT '2022-blake3-aes-128-gcm',
    wg_ip           TEXT NOT NULL DEFAULT '',
    wg_priv         TEXT NOT NULL DEFAULT '',
    wg_pub          TEXT NOT NULL DEFAULT '',
    last_seen       REAL
);
CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL NOT NULL,
    level      TEXT NOT NULL DEFAULT 'info',
    action     TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT '',
    ip         TEXT NOT NULL DEFAULT '',
    user_id    INTEGER
);
CREATE TABLE IF NOT EXISTS traffic_hourly (
    bucket INTEGER PRIMARY KEY,
    up     INTEGER NOT NULL DEFAULT 0,
    down   INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS nodes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    address      TEXT NOT NULL DEFAULT '',
    city         TEXT NOT NULL DEFAULT '',
    country      TEXT NOT NULL DEFAULT '',
    country_code TEXT NOT NULL DEFAULT '',
    flag         TEXT NOT NULL DEFAULT '🏳️',
    token        TEXT NOT NULL DEFAULT '',
    wg_pub       TEXT NOT NULL DEFAULT '',
    is_local     INTEGER NOT NULL DEFAULT 0,
    enabled      INTEGER NOT NULL DEFAULT 1,
    created_at   REAL NOT NULL,
    last_seen    REAL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_users_uid ON users(uid);
-- Subscription GROUPS: one public link that carries several users' configs.
-- (3x-ui has no equivalent; this is the "add a subscription" the panel lacked -
-- before it, one link could only ever mean one user.)
CREATE TABLE IF NOT EXISTS subscriptions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    skey         TEXT NOT NULL UNIQUE,
    name         TEXT NOT NULL,
    remark       TEXT NOT NULL DEFAULT '',
    member_uids  TEXT NOT NULL DEFAULT '[]',
    enabled      INTEGER NOT NULL DEFAULT 1,
    include_info INTEGER NOT NULL DEFAULT 1,
    created_at   REAL NOT NULL,
    updated_at   REAL NOT NULL
);
"""


def _connect() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        os.makedirs(config.DATA_DIR, exist_ok=True)
        _conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA foreign_keys=ON")
        _conn.executescript(SCHEMA)
        _conn.commit()
        _ensure_bootstrap()
    return _conn


def _ensure_bootstrap():
    """Generate secret key / default settings / migrations on first run."""
    c = _conn
    if not get_meta("secret_key"):
        set_meta("secret_key", secrets.token_hex(32))
    if not get_meta("created_at"):
        set_meta("created_at", str(time.time()))
    if not get_meta("backup_last_at"):
        set_meta("backup_last_at", "0")

    # migration: users.node_id (config -> node association)
    cols = [r["name"] for r in c.execute("PRAGMA table_info(users)").fetchall()]
    if "node_id" not in cols:
        c.execute("ALTER TABLE users ADD COLUMN node_id INTEGER NOT NULL DEFAULT 1")
        c.commit()
    if "avatar" not in cols:
        c.execute("ALTER TABLE users ADD COLUMN avatar TEXT NOT NULL DEFAULT ''")
        c.commit()
    if "ss_method" not in cols:
        c.execute("ALTER TABLE users ADD COLUMN ss_method TEXT NOT NULL DEFAULT '2022-blake3-aes-128-gcm'")
        c.commit()
    if "wg_ip" not in cols:
        c.execute("ALTER TABLE users ADD COLUMN wg_ip TEXT NOT NULL DEFAULT ''")
        c.commit()
    if "wg_priv" not in cols:
        c.execute("ALTER TABLE users ADD COLUMN wg_priv TEXT NOT NULL DEFAULT ''")
        c.commit()
    if "wg_pub" not in cols:
        c.execute("ALTER TABLE users ADD COLUMN wg_pub TEXT NOT NULL DEFAULT ''")
        c.commit()

    # migration: nodes.token (per-node credential issued by the main panel)
    ncols = [r["name"] for r in c.execute("PRAGMA table_info(nodes)").fetchall()]
    if "token" not in ncols:
        c.execute("ALTER TABLE nodes ADD COLUMN token TEXT NOT NULL DEFAULT ''")
        c.commit()
    if "wg_pub" not in ncols:
        c.execute("ALTER TABLE nodes ADD COLUMN wg_pub TEXT NOT NULL DEFAULT ''")
        c.commit()

    # seed the local node (this server) once
    row = c.execute("SELECT id FROM nodes WHERE is_local=1").fetchone()
    if not row:
        c.execute(
            "INSERT INTO nodes(name, address, city, country, country_code, flag, "
            "is_local, enabled, created_at, last_seen) VALUES(?,?,?,?,?,?,?,?,?,?)",
            ("سرور اصلی", "", "—", "—", "", "🌐", 1, 1, time.time(), time.time()),
        )
        c.commit()

    # --- default admin — no registration required. ---------------------------
    # Username: "TiTaN". Password intentionally unset until the admin sets one
    # from Settings → Security. While auth_is_default is "1", login accepts the
    # default username without any password.
    if not get_admin():
        from . import security as _sec
        hp = _sec.hash_password("")
        set_admin("TiTaN", hp["hash"], hp["salt"])
        set_meta("auth_is_default", "1")
        # start of the no-password window (app.main._first_run_state)
        set_meta("auth_default_since", str(time.time()))


def apply_env_admin_password() -> bool:
    """Seed or recover the admin credential from TITAN_ADMIN_PASSWORD.

    Two jobs. On a fresh deploy it closes the no-password window before the
    platform routes traffic to the container. And it stays honoured on every boot,
    which is the documented way back in for someone who let the window expire or
    lost the password - set the variable, redeploy, log in. Nothing is wiped.

    A short value is ignored rather than applied: a 4-character password reached
    through the same public URL is worse than the window it closes.
    """
    from . import config, security as _sec
    pw = config.ADMIN_PASSWORD or ""
    if not pw:
        return False
    log = logging.getLogger("titan.db")
    if len(pw) < 8:
        log.error("TITAN_ADMIN_PASSWORD is shorter than 8 characters - ignored; "
                  "the first-run login stays bounded by TITAN_DEFAULT_LOGIN_HOURS")
        return False
    was_default = get_meta("auth_is_default") == "1"
    admin = get_admin()
    hp = _sec.hash_password(pw)
    set_admin(admin["username"] if admin else "TiTaN", hp["hash"], hp["salt"])
    set_meta("auth_is_default", "0")
    # a platform deploy shows WARNING by default, and "I closed the open door"
    # is the line an operator needs to see in the Railway log
    log.log(logging.WARNING if was_default else logging.INFO,
            "admin password applied from TITAN_ADMIN_PASSWORD%s",
            "; the no-password first-run login is now closed" if was_default else "")
    return True


def get_meta(key: str) -> str | None:
    with _lock:
        c = _connect()
        row = c.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None


def set_meta(key: str, value: str):
    with _lock:
        c = _connect()
        c.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        c.commit()


def get_secret_key() -> str:
    key = get_meta("secret_key")
    if not key:
        key = secrets.token_hex(32)
        set_meta("secret_key", key)
    return key


def get_admin() -> dict | None:
    with _lock:
        c = _connect()
        row = c.execute("SELECT * FROM admin WHERE id=1").fetchone()
        return dict(row) if row else None


def set_admin(username: str, password_hash: str, salt: str) -> None:
    with _lock:
        c = _connect()
        c.execute("DELETE FROM admin")
        c.execute(
            "INSERT INTO admin(id, username, password_hash, salt, created_at) "
            "VALUES(1, ?, ?, ?, ?)",
            (username, password_hash, salt, time.time()),
        )
        c.commit()


def get_settings() -> dict:
    with _lock:
        c = _connect()
        rows = c.execute("SELECT key, value FROM settings").fetchall()
    settings = dict(config.DEFAULT_SETTINGS)
    for row in rows:
        try:
            settings[row["key"]] = json.loads(row["value"])
        except (json.JSONDecodeError, TypeError):
            settings[row["key"]] = row["value"]
    return settings


def set_setting(key: str, value: Any) -> None:
    with _lock:
        c = _connect()
        c.execute(
            "INSERT INTO settings(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, json.dumps(value)),
        )
        c.commit()


def set_settings(mapping: dict) -> None:
    for k, v in mapping.items():
        set_setting(k, v)


def list_users() -> list[dict]:
    with _lock:
        c = _connect()
        rows = c.execute("SELECT * FROM users ORDER BY created_at ASC").fetchall()
    return [dict(r) for r in rows]


def get_user(uid: str) -> dict | None:
    with _lock:
        c = _connect()
        row = c.execute("SELECT * FROM users WHERE uid=?", (uid,)).fetchone()
        return dict(row) if row else None


def get_user_by_uuid(uuid: str) -> dict | None:
    with _lock:
        c = _connect()
        row = c.execute("SELECT * FROM users WHERE uuid=?", (uuid,)).fetchone()
        return dict(row) if row else None


def create_user(data: dict) -> dict:
    with _lock:
        c = _connect()
        cols = [
            "uid", "uuid", "name", "note", "enabled", "protocol", "transport",
            "security", "fingerprint", "alpn", "public_key", "short_id",
            "spider_x", "max_devices", "first_device_uid", "allowed_ips",
            "quota_bytes", "expire_at", "created_at", "max_requests", "node_id",
            "avatar", "ss_method", "wg_ip", "wg_priv", "wg_pub",
        ]
        now = time.time()
        values = {
            "uid": data["uid"],
            "uuid": data["uuid"],
            "name": data.get("name", "User")[:64],
            "note": data.get("note", "")[:200],
            "enabled": 1 if data.get("enabled", True) else 0,
            "protocol": data.get("protocol", "vless"),
            "transport": data.get("transport", "ws"),
            "security": data.get("security", "tls"),
            "fingerprint": data.get("fingerprint", "chrome"),
            "alpn": data.get("alpn", "http/1.1"),
            "public_key": data.get("public_key", ""),
            "short_id": data.get("short_id", ""),
            "spider_x": data.get("spider_x", ""),
            "max_devices": int(data.get("max_devices", 0) or 0),
            "first_device_uid": data.get("first_device_uid", ""),
            "allowed_ips": json.dumps(data.get("allowed_ips", []), ensure_ascii=False),
            "quota_bytes": int(data.get("quota_bytes", 0) or 0),
            "expire_at": data.get("expire_at"),
            "created_at": now,
            "max_requests": int(data.get("max_requests", 0) or 0),
            "node_id": coerce_node_id(data.get("node_id")),
            "avatar": data.get("avatar", "") or "",
            "ss_method": data.get("ss_method", "2022-blake3-aes-128-gcm"),
            "wg_ip": data.get("wg_ip", "") or "",
            "wg_priv": data.get("wg_priv", "") or "",
            "wg_pub": data.get("wg_pub", "") or "",
        }
        placeholders = ", ".join("?" for _ in cols)
        c.execute(
            f"INSERT INTO users({', '.join(cols)}) VALUES({placeholders})",
            [values[col] for col in cols],
        )
        c.commit()
    return get_user(data["uid"])


def update_user(uid: str, fields: dict) -> dict | None:
    allowed = {
        "name", "note", "enabled", "protocol", "transport", "security",
        "fingerprint", "alpn", "public_key", "short_id", "spider_x",
        "max_devices", "first_device_uid", "quota_bytes", "expire_at",
        "max_requests", "node_id", "avatar", "uuid",
        "ss_method", "wg_ip", "wg_priv", "wg_pub",
        # allowed_ips was missing from this allowlist, so PATCH silently
        # dropped it (the handler validated it, the UPDATE never wrote it).
        "allowed_ips",
    }
    with _lock:
        c = _connect()
        sets, vals = [], []
        for k, v in fields.items():
            if k not in allowed:
                continue
            if k == "enabled":
                v = 1 if v else 0
            if k == "allowed_ips":
                v = json.dumps(v, ensure_ascii=False)
            sets.append(f"{k}=?")
            vals.append(v)
        if sets:
            vals.append(uid)
            c.execute(f"UPDATE users SET {', '.join(sets)} WHERE uid=?", vals)
            c.commit()
    return get_user(uid)


def set_user_usage(uid: str, up: int, down: int) -> None:
    with _lock:
        c = _connect()
        c.execute(
            "UPDATE users SET used_up=?, used_down=? WHERE uid=?", (up, down, uid)
        )
        c.commit()


def add_user_usage(uid: str, up_delta: int, down_delta: int) -> None:
    with _lock:
        c = _connect()
        c.execute(
            "UPDATE users SET used_up=used_up+?, used_down=used_down+? WHERE uid=?",
            (up_delta, down_delta, uid),
        )
        c.commit()


def reset_user_usage(uid: str) -> None:
    with _lock:
        c = _connect()
        c.execute(
            "UPDATE users SET used_up=0, used_down=0, request_count=0 WHERE uid=?",
            (uid,),
        )
        c.commit()


def delete_user(uid: str) -> bool:
    with _lock:
        c = _connect()
        cur = c.execute("DELETE FROM users WHERE uid=?", (uid,))
        c.commit()
        return cur.rowcount > 0


def touch_last_seen(uid: str, ts: float | None = None) -> None:
    with _lock:
        c = _connect()
        c.execute("UPDATE users SET last_seen=? WHERE uid=?", (ts or time.time(), uid))
        c.commit()


def count_recently_seen(seconds: int) -> int:
    with _lock:
        c = _connect()
        row = c.execute(
            "SELECT COUNT(*) AS n FROM users WHERE last_seen IS NOT NULL AND last_seen > ?",
            (time.time() - seconds,),
        ).fetchone()
        return row["n"]


def get_totals() -> dict:
    with _lock:
        c = _connect()
        row = c.execute(
            "SELECT COALESCE(SUM(used_up),0) AS up, COALESCE(SUM(used_down),0) AS down, "
            "COUNT(*) AS n FROM users"
        ).fetchone()
        return {"up": row["up"], "down": row["down"], "count": row["n"]}


def add_event(level: str, action: str, detail: str = "", ip: str = "", user_id: int | None = None) -> None:
    with _lock:
        c = _connect()
        c.execute(
            "INSERT INTO events(ts, level, action, detail, ip, user_id) VALUES(?,?,?,?,?,?)",
            (time.time(), level, action, detail[:400], ip, user_id),
        )
        c.commit()
        # keep only the last 2000 rows
        c.execute(
            "DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 2000)"
        )
        c.commit()


def list_events(limit: int = 200, level: str | None = None) -> list[dict]:
    with _lock:
        c = _connect()
        if level:
            rows = c.execute(
                "SELECT * FROM events WHERE level=? ORDER BY id DESC LIMIT ?",
                (level, limit),
            ).fetchall()
        else:
            rows = c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


def clear_events() -> None:
    with _lock:
        c = _connect()
        c.execute("DELETE FROM events")
        c.commit()


# ------------------------------------------------------------------ nodes
def list_nodes() -> list[dict]:
    with _lock:
        c = _connect()
        rows = c.execute("SELECT * FROM nodes ORDER BY is_local DESC, id ASC").fetchall()
    return [dict(r) for r in rows]


def get_node(node_id: int) -> dict | None:
    with _lock:
        c = _connect()
        row = c.execute("SELECT * FROM nodes WHERE id=?", (node_id,)).fetchone()
        return dict(row) if row else None


def create_node(data: dict) -> dict:
    with _lock:
        c = _connect()
        cur = c.execute(
            "INSERT INTO nodes(name, address, city, country, country_code, flag, token, "
            "is_local, enabled, created_at, last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                data.get("name", "Node")[:64],
                data.get("address", "")[:200],
                data.get("city", "")[:64],
                data.get("country", "")[:64],
                data.get("country_code", "")[:2],
                data.get("flag", "🏳️"),
                data.get("token", ""),
                0,
                1 if data.get("enabled", True) else 0,
                time.time(),
                time.time(),
            ),
        )
        c.commit()
        return get_node(cur.lastrowid)


def get_node_by_token(token: str) -> dict | None:
    """Find a (remote) node by its per-node credential."""
    token = (token or "").strip()
    if not token:
        return None
    with _lock:
        c = _connect()
        row = c.execute("SELECT * FROM nodes WHERE token=? AND is_local=0", (token,)).fetchone()
        return dict(row) if row else None


def update_node(node_id: int, fields: dict) -> dict | None:
    allowed = {"name", "address", "city", "country", "country_code", "flag", "enabled", "wg_pub"}
    with _lock:
        c = _connect()
        sets, vals = [], []
        for k, v in fields.items():
            if k not in allowed:
                continue
            if k == "enabled":
                v = 1 if v else 0
            sets.append(f"{k}=?")
            vals.append(v)
        if sets:
            vals.append(node_id)
            c.execute(f"UPDATE nodes SET {', '.join(sets)} WHERE id=?", vals)
            c.commit()
    return get_node(node_id)


# ------------------------------------------------------- subscription groups
#: a group's public token: `sg` + 12 hex, so it can never collide with a 16-hex
#: user uid (both are accepted by /sub/<key>).
def new_subscription_key() -> str:
    return "sg" + secrets.token_hex(6)


def _decode_members(row: dict) -> dict:
    raw = row.get("member_uids")
    if isinstance(raw, str):
        try:
            data = json.loads(raw or "[]")
        except ValueError:
            data = []
        row["member_uids"] = [str(u) for u in data if u]
    elif raw is None:
        row["member_uids"] = []
    return row


def create_subscription(data: dict) -> dict:
    now = time.time()
    with _lock:
        c = _connect()
        cur = c.execute(
            "INSERT INTO subscriptions(skey, name, remark, member_uids, enabled, include_info, "
            "created_at, updated_at) VALUES(?,?,?,?,?,?,?,?)",
            (
                data["skey"],
                (data.get("name") or "Subscription")[:64],
                (data.get("remark") or "")[:200],
                json.dumps(list(data.get("member_uids") or [])),
                1 if data.get("enabled", True) else 0,
                1 if data.get("include_info", True) else 0,
                now, now,
            ),
        )
        c.commit()
        return get_subscription(cur.lastrowid)


def get_subscription(sub_id: int) -> dict | None:
    with _lock:
        c = _connect()
        row = c.execute("SELECT * FROM subscriptions WHERE id=?", (sub_id,)).fetchone()
    return _decode_members(dict(row)) if row else None


def get_subscription_by_key(skey: str) -> dict | None:
    skey = (skey or "").strip()
    if not skey:
        return None
    with _lock:
        c = _connect()
        row = c.execute("SELECT * FROM subscriptions WHERE skey=?", (skey,)).fetchone()
    return _decode_members(dict(row)) if row else None


def list_subscriptions() -> list[dict]:
    with _lock:
        c = _connect()
        rows = c.execute("SELECT * FROM subscriptions ORDER BY id DESC").fetchall()
    return [_decode_members(dict(r)) for r in rows]


def update_subscription(sub_id: int, fields: dict) -> dict | None:
    allowed = {"name", "remark", "member_uids", "enabled", "include_info", "skey"}
    with _lock:
        c = _connect()
        sets, vals = [], []
        for k, v in fields.items():
            if k not in allowed:
                continue
            if k == "member_uids":
                v = json.dumps([str(u) for u in (v or [])])
            elif k in ("enabled", "include_info"):
                v = 1 if v else 0
            sets.append(f"{k}=?")
            vals.append(v)
        if sets:
            vals.append(time.time())
            sets.append("updated_at=?")
            vals.append(sub_id)
            c.execute(f"UPDATE subscriptions SET {', '.join(sets)} WHERE id=?", vals)
            c.commit()
    return get_subscription(sub_id)


def delete_subscription(sub_id: int) -> bool:
    with _lock:
        c = _connect()
        cur = c.execute("DELETE FROM subscriptions WHERE id=?", (sub_id,))
        c.commit()
    return cur.rowcount > 0


def delete_node(node_id: int) -> bool:
    with _lock:
        c = _connect()
        cur = c.execute("DELETE FROM nodes WHERE id=? AND is_local=0", (node_id,))
        c.commit()
        return cur.rowcount > 0


def touch_node(node_id: int) -> None:
    with _lock:
        c = _connect()
        c.execute("UPDATE nodes SET last_seen=? WHERE id=?", (time.time(), node_id))
        c.commit()


def set_local_node_location(city: str, country: str, country_code: str, flag: str) -> None:
    with _lock:
        c = _connect()
        c.execute(
            "UPDATE nodes SET city=?, country=?, country_code=?, flag=? WHERE is_local=1",
            (city, country, country_code, flag),
        )
        c.commit()


def backup_bytes() -> bytes:
    """Return a consistent snapshot of the DB file."""
    with _lock:
        c = _connect()
        c.execute("PRAGMA wal_checkpoint(FULL)")
        c.commit()
    with open(config.DB_PATH, "rb") as f:
        return f.read()


def add_traffic(bucket: int, up: int, down: int) -> None:
    with _lock:
        c = _connect()
        c.execute(
            "INSERT INTO traffic_hourly(bucket, up, down) VALUES(?,?,?) "
            "ON CONFLICT(bucket) DO UPDATE SET up=up+excluded.up, down=down+excluded.down",
            (bucket, up, down),
        )
        c.execute("DELETE FROM traffic_hourly WHERE bucket < ?", (bucket - 168 * 3600,))
        c.commit()


def get_traffic(bucket_from: int) -> list[dict]:
    with _lock:
        c = _connect()
        rows = c.execute(
            "SELECT bucket, up, down FROM traffic_hourly WHERE bucket >= ? ORDER BY bucket ASC",
            (bucket_from,),
        ).fetchall()
    return [dict(r) for r in rows]


def replace_db(data: bytes) -> bool:
    """Replace the live DB with the given bytes (used by restore)."""
    global _conn
    with _lock:
        if _conn is not None:
            try:
                _conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                _conn.close()
            except sqlite3.Error:
                pass
            _conn = None
        os.makedirs(config.DATA_DIR, exist_ok=True)
        tmp = config.DB_PATH + ".restore"
        with open(tmp, "wb") as f:
            f.write(data)
        for suffix in ("-wal", "-shm"):
            try:
                os.remove(config.DB_PATH + suffix)
            except OSError:
                pass
        os.replace(tmp, config.DB_PATH)
        _connect()
        return True
