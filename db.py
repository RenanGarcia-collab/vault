import sqlite3
from pathlib import Path
from datetime import datetime
from config import DB_PATH, INSTANCE_DIR

SCHEMA = """
CREATE TABLE IF NOT EXISTS vendors (
  key TEXT PRIMARY KEY,
  name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS folders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  parent_id INTEGER,
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  login_username TEXT,
  password_hash TEXT NOT NULL,
  device_password_enc TEXT,
  role TEXT NOT NULL,
  device_id INTEGER,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  vendor TEXT NOT NULL,
  user_id INTEGER,
  script_id INTEGER,
  folder_id INTEGER,
  ipaddr TEXT NOT NULL,
  port INTEGER NOT NULL DEFAULT 22,
  dev_username TEXT NOT NULL,
  dev_password_enc TEXT NOT NULL,
  command_override TEXT,
  interval_minutes INTEGER,
  last_run_at TEXT,
  next_run_at TEXT,
  running INTEGER,
  run_started_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS backups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id INTEGER NOT NULL,
  path TEXT NOT NULL,
  created_at TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  status TEXT NOT NULL,
  message TEXT,
  debug_log TEXT,
  duration_seconds INTEGER,
  line_count INTEGER,
  content_hash TEXT,
  firmware TEXT,
  diff_summary TEXT
);

CREATE TABLE IF NOT EXISTS vendor_scripts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vendor TEXT NOT NULL UNIQUE,
  pre_text TEXT,
  cmd TEXT,
  prompt TEXT,
  read_mode TEXT,
  sleep INTEGER,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scripts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  vendor TEXT NOT NULL,
  pre_text TEXT,
  cmd TEXT,
  prompt TEXT,
  read_mode TEXT,
  sleep INTEGER,
  timeout_seconds INTEGER,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS app_settings (
  key TEXT PRIMARY KEY,
  value TEXT,
  updated_at TEXT NOT NULL
);
"""

DEFAULT_SCRIPTS = [
    ("Huawei OLT", "huawei", "enable", "display current-configuration", ">", "shell", 0, 900),
    ("Huawei Switch", "huawei", "screen-length 0 temporary", "display current-configuration", ">", "shell", 0, 180),
    ("Juniper", "juniper", "", "show configuration | display set | no-more", "", "exec", 0, 180),
    ("Mikrotik", "mikrotik", "", "/export", "", "exec", 0, 120),
    ("Datacom", "datacom", "", "show running-config | nomore", "#", "shell", 6, 180),
]

DEFAULT_VENDORS = [
    ("huawei", "Huawei"),
    ("juniper", "Juniper"),
    ("mikrotik", "Mikrotik"),
    ("datacom", "Datacom"),
]


def connect():
    Path(INSTANCE_DIR).mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = connect()
    try:
        conn.executescript(SCHEMA)
        _ensure_columns(conn)
        _ensure_vendors(conn)
        _ensure_scripts(conn)
        _ensure_default_folder(conn)
        _ensure_settings(conn)
        conn.commit()
    finally:
        conn.close()


def _has_column(conn, table, column):
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(r[1] == column for r in rows)


def _ensure_columns(conn):
    # users table migrations
    if not _has_column(conn, "users", "login_username"):
        conn.execute("ALTER TABLE users ADD COLUMN login_username TEXT")
    if not _has_column(conn, "users", "device_password_enc"):
        conn.execute("ALTER TABLE users ADD COLUMN device_password_enc TEXT")
    conn.execute("UPDATE users SET login_username = username WHERE login_username IS NULL OR login_username = ''")
    # devices table migrations
    if not _has_column(conn, "devices", "interval_minutes"):
        conn.execute("ALTER TABLE devices ADD COLUMN interval_minutes INTEGER")
    if not _has_column(conn, "devices", "last_run_at"):
        conn.execute("ALTER TABLE devices ADD COLUMN last_run_at TEXT")
    if not _has_column(conn, "devices", "next_run_at"):
        conn.execute("ALTER TABLE devices ADD COLUMN next_run_at TEXT")
    if not _has_column(conn, "devices", "folder_id"):
        conn.execute("ALTER TABLE devices ADD COLUMN folder_id INTEGER")
    if not _has_column(conn, "devices", "user_id"):
        conn.execute("ALTER TABLE devices ADD COLUMN user_id INTEGER")
    if not _has_column(conn, "devices", "script_id"):
        conn.execute("ALTER TABLE devices ADD COLUMN script_id INTEGER")
    if not _has_column(conn, "devices", "running"):
        conn.execute("ALTER TABLE devices ADD COLUMN running INTEGER")
    if not _has_column(conn, "devices", "run_started_at"):
        conn.execute("ALTER TABLE devices ADD COLUMN run_started_at TEXT")
    if not _has_column(conn, "devices", "last_debug"):
        conn.execute("ALTER TABLE devices ADD COLUMN last_debug TEXT")
    if not _has_column(conn, "devices", "last_debug_at"):
        conn.execute("ALTER TABLE devices ADD COLUMN last_debug_at TEXT")
    if not _has_column(conn, "folders", "parent_id"):
        conn.execute("ALTER TABLE folders ADD COLUMN parent_id INTEGER")
    if not _has_column(conn, "folders", "sort_order"):
        conn.execute("ALTER TABLE folders ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0")
    _ensure_folder_constraints(conn)
    # backups table migrations
    if not _has_column(conn, "backups", "duration_seconds"):
        conn.execute("ALTER TABLE backups ADD COLUMN duration_seconds INTEGER")
    if not _has_column(conn, "backups", "line_count"):
        conn.execute("ALTER TABLE backups ADD COLUMN line_count INTEGER")
    if not _has_column(conn, "backups", "content_hash"):
        conn.execute("ALTER TABLE backups ADD COLUMN content_hash TEXT")
    if not _has_column(conn, "backups", "firmware"):
        conn.execute("ALTER TABLE backups ADD COLUMN firmware TEXT")
    if not _has_column(conn, "backups", "diff_summary"):
        conn.execute("ALTER TABLE backups ADD COLUMN diff_summary TEXT")
    # migrate legacy one-to-one user binding to devices.user_id
    if _has_column(conn, "users", "device_id") and _has_column(conn, "devices", "user_id"):
        rows = conn.execute(
            "SELECT id, device_id FROM users WHERE role = 'device' AND device_id IS NOT NULL"
        ).fetchall()
        for row in rows:
            conn.execute(
                "UPDATE devices SET user_id = COALESCE(user_id, ?) WHERE id = ?",
                (row["id"], row["device_id"]),
            )
    _normalize_next_run_at(conn)


def _ensure_folder_constraints(conn):
    create_sql = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'folders'"
    ).fetchone()
    folder_sql = (create_sql["sql"] or "") if create_sql else ""
    if "name TEXT NOT NULL UNIQUE" in folder_sql:
        conn.execute("ALTER TABLE folders RENAME TO folders_old")
        conn.execute(
            """
            CREATE TABLE folders (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL,
              parent_id INTEGER,
              sort_order INTEGER NOT NULL DEFAULT 0,
              created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            INSERT INTO folders (id, name, parent_id, sort_order, created_at)
            SELECT id, name, parent_id, sort_order, created_at
            FROM folders_old
            """
        )
        conn.execute("DROP TABLE folders_old")
    conn.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_folders_parent_name_unique
        ON folders (IFNULL(parent_id, -1), lower(trim(name)))
        """
    )


def _normalize_next_run_at(conn):
    local_tz = datetime.now().astimezone().tzinfo
    rows = conn.execute(
        "SELECT id, next_run_at FROM devices WHERE next_run_at IS NOT NULL AND next_run_at LIKE '%Z'"
    ).fetchall()
    for row in rows:
        raw = (row["next_run_at"] or "").strip()
        try:
            dt_utc = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            dt_local = dt_utc.astimezone(local_tz)
            normalized = dt_local.strftime("%Y-%m-%dT%H:%M:%S")
            conn.execute("UPDATE devices SET next_run_at = ? WHERE id = ?", (normalized, row["id"]))
        except Exception:
            continue


def _ensure_vendors(conn):
    conn.execute("CREATE TABLE IF NOT EXISTS vendors (key TEXT PRIMARY KEY, name TEXT NOT NULL)")
    rows = conn.execute("SELECT key FROM vendors").fetchall()
    existing = {r["key"] for r in rows}
    for key, name in DEFAULT_VENDORS:
        if key not in existing:
            conn.execute("INSERT INTO vendors (key, name) VALUES (?, ?)", (key, name))
    # cleanup vendor no longer used in this deployment
    cisco_devices = conn.execute("SELECT COUNT(1) AS c FROM devices WHERE vendor = 'cisco'").fetchone()["c"]
    if cisco_devices == 0:
        conn.execute("DELETE FROM vendors WHERE key = 'cisco'")



def _ensure_default_folder(conn):
    conn.execute("CREATE TABLE IF NOT EXISTS folders (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, parent_id INTEGER, sort_order INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)")
    row = conn.execute("SELECT id FROM folders ORDER BY id LIMIT 1").fetchone()
    if not row:
        conn.execute("INSERT INTO folders (name, parent_id, sort_order, created_at) VALUES (?, NULL, 0, datetime('now'))", ("Geral",))
        row = conn.execute("SELECT id FROM folders ORDER BY id LIMIT 1").fetchone()
    folder_id = row["id"]
    conn.execute("UPDATE devices SET folder_id = ? WHERE folder_id IS NULL", (folder_id,))


def _ensure_scripts(conn):
    conn.execute(
        "CREATE TABLE IF NOT EXISTS scripts (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, vendor TEXT NOT NULL, pre_text TEXT, cmd TEXT, prompt TEXT, read_mode TEXT, sleep INTEGER, timeout_seconds INTEGER, created_at TEXT NOT NULL)"
    )
    rows = conn.execute("SELECT name FROM scripts").fetchall()
    existing = {r["name"] for r in rows}
    for name, vendor, pre_text, cmd, prompt, read_mode, sleep, timeout_seconds in DEFAULT_SCRIPTS:
        if name not in existing:
            conn.execute(
                "INSERT INTO scripts (name, vendor, pre_text, cmd, prompt, read_mode, sleep, timeout_seconds, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
                (name, vendor, pre_text, cmd, prompt, read_mode, sleep, timeout_seconds),
            )
    cisco_devices = conn.execute("SELECT COUNT(1) AS c FROM devices WHERE vendor = 'cisco'").fetchone()["c"]
    if cisco_devices == 0:
        conn.execute("DELETE FROM scripts WHERE vendor = 'cisco'")
    rows = conn.execute("SELECT id, vendor, script_id FROM devices").fetchall()
    for r in rows:
        if r["script_id"] is None:
            s = conn.execute(
                "SELECT id FROM scripts WHERE vendor = ? ORDER BY id LIMIT 1",
                (r["vendor"],),
            ).fetchone()
            if s:
                conn.execute("UPDATE devices SET script_id = ? WHERE id = ?", (s["id"], r["id"]))


def _ensure_settings(conn):
    conn.execute("CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT, updated_at TEXT NOT NULL)")
    row = conn.execute("SELECT value FROM app_settings WHERE key = 'storage_total_gb'").fetchone()
    if not row:
        conn.execute(
            "INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, datetime('now'))",
            ("storage_total_gb", "10"),
        )
    row = conn.execute("SELECT value FROM app_settings WHERE key = 'global_interval_minutes'").fetchone()
    if not row:
        conn.execute(
            "INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, datetime('now'))",
            ("global_interval_minutes", "60"),
        )
