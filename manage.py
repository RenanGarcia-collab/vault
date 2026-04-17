import argparse
import os
import signal
import time
import hashlib
import difflib
from datetime import datetime, timedelta
from pathlib import Path
from db import init_db, connect
from security import hash_password, decrypt_secret
from backup import run_backup, save_backup, MIN_BACKUP_BYTES, prune_backups, min_backup_bytes
from config import BACKUP_KEEP_LAST, BACKUP_ROOT
from utils import now_iso


LOCK_PATH = os.environ.get("SCHEDULER_LOCK_PATH", "/tmp/backup-dashboard-scheduler.lock")
STALE_RUNNING_GRACE_SECONDS = int(os.environ.get("STALE_RUNNING_GRACE_SECONDS", "120"))


def _device_timeout_seconds():
    try:
        return int(os.environ.get("SCHEDULER_DEVICE_TIMEOUT_SECONDS", "900"))
    except Exception:
        return 900


def _parse_iso_datetime(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


def _mark_device_debug(conn, device_id: int, log_lines):
    conn.execute(
        "UPDATE devices SET last_debug = ?, last_debug_at = ? WHERE id = ?",
        ("\n".join(log_lines), now_iso(), device_id),
    )
    conn.commit()


def _expire_stale_running(conn):
    rows = conn.execute(
        """
        SELECT d.id, d.name, d.run_started_at, s.timeout_seconds
        FROM devices d
        LEFT JOIN scripts s ON s.id = d.script_id
        WHERE d.running = 1
        """
    ).fetchall()
    now = datetime.now()
    released = []
    for row in rows:
        started_at = _parse_iso_datetime(row["run_started_at"])
        timeout_seconds = row["timeout_seconds"] or _device_timeout_seconds()
        if started_at is None:
            conn.execute(
                "UPDATE devices SET running = 0, run_started_at = NULL WHERE id = ?",
                (row["id"],),
            )
            released.append((row["id"], row["name"], "sem run_started_at"))
            continue
        age_seconds = (now - started_at).total_seconds()
        if age_seconds <= timeout_seconds + STALE_RUNNING_GRACE_SECONDS:
            continue
        conn.execute(
            """
            UPDATE devices
            SET running = 0,
                run_started_at = NULL,
                last_debug = CASE
                    WHEN last_debug IS NULL OR last_debug = '' THEN ?
                    ELSE last_debug || char(10) || ?
                END,
                last_debug_at = ?
            WHERE id = ?
            """,
            (
                f"[{now.strftime('%H:%M:%S')}] stale running flag reset by scheduler",
                f"[{now.strftime('%H:%M:%S')}] stale running flag reset by scheduler",
                now_iso(),
                row["id"],
            ),
        )
        released.append((row["id"], row["name"], f"{int(age_seconds)}s"))
    if released:
        conn.commit()
    return released


def _alarm_handler(signum, frame):
    raise TimeoutError("Timeout por dispositivo excedido")


def _run_with_timeout(seconds, func, *args, **kwargs):
    if not seconds or seconds <= 0 or os.name == "nt":
        return func(*args, **kwargs)
    previous = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, _alarm_handler)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        return func(*args, **kwargs)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _acquire_lock():
    try:
        fd = os.open(LOCK_PATH, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except FileExistsError:
        try:
            with open(LOCK_PATH, "r", encoding="utf-8") as f:
                content = f.read().strip().split()
            pid = int(content[0]) if content else None
            if pid:
                try:
                    os.kill(pid, 0)
                    return None
                except ProcessLookupError:
                    os.unlink(LOCK_PATH)
                    return _acquire_lock()
        except Exception:
            return None
        return None
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(f"{os.getpid()} {int(time.time())}\n")
    return fd


def _release_lock(fd):
    try:
        os.close(fd)
    except Exception:
        pass
    try:
        os.unlink(LOCK_PATH)
    except Exception:
        pass


def init_admin(args):
    init_db()
    conn = connect()
    try:
        existing = conn.execute("SELECT * FROM users WHERE username = ?", (args.username,)).fetchone()
        if existing:
            conn.execute(
                "UPDATE users SET password_hash = ?, role = 'admin' WHERE id = ?",
                (hash_password(args.password), existing["id"]),
            )
        else:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, device_id, created_at) VALUES (?, ?, 'admin', NULL, ?)",
                (args.username, hash_password(args.password), now_iso()),
            )
        conn.commit()
        print("Admin criado/atualizado")
    finally:
        conn.close()


def _next_run_iso(interval_minutes):
    if not interval_minutes:
        return None
    now = datetime.now()
    base = now.replace(second=0, microsecond=0)
    remainder = base.minute % interval_minutes
    minutes_to_add = (interval_minutes - remainder) % interval_minutes
    if minutes_to_add == 0:
        minutes_to_add = interval_minutes
    return (base + timedelta(minutes=minutes_to_add)).strftime("%Y-%m-%dT%H:%M:%S")


def _global_interval_minutes(conn):
    row = conn.execute("SELECT value FROM app_settings WHERE key = 'global_interval_minutes'").fetchone()
    try:
        value = int((row["value"] if row else "60") or "60")
        return value if value > 0 else 60
    except Exception:
        return 60

def _get_vendor_script_override(conn, vendor):
    row = conn.execute("SELECT * FROM vendor_scripts WHERE vendor = ?", (vendor,)).fetchone()
    if not row:
        return None
    pre_text = row["pre_text"] or ""
    pre_list = [line.strip() for line in pre_text.splitlines() if line.strip()]
    def _row_get(r, key, default=None):
        try:
            return r[key]
        except Exception:
            return default
    return {
        "pre": pre_list,
        "cmd": row["cmd"],
        "prompt": row["prompt"],
        "read_mode": row["read_mode"],
        "sleep": row["sleep"],
        "timeout": _row_get(row, "timeout_seconds"),
    }


def _get_script_override(conn, script_id):
    if not script_id:
        return None, None
    row = conn.execute("SELECT * FROM scripts WHERE id = ?", (int(script_id),)).fetchone()
    if not row:
        return None, None
    pre_text = row["pre_text"] or ""
    pre_list = [line.strip() for line in pre_text.splitlines() if line.strip()]
    profile = "olt" if "olt" in (row["name"] or "").lower() else "switch"
    override = {
        "pre": pre_list,
        "cmd": row["cmd"],
        "prompt": row["prompt"],
        "read_mode": row["read_mode"],
        "sleep": row["sleep"],
        "timeout": row["timeout_seconds"],
        "profile": profile,
    }
    return override, row["vendor"]


def _latest_backup_path(device):
    base = Path(BACKUP_ROOT) / device["vendor"].lower() / device["slug"]
    latest_link = base / "latest.txt"
    if latest_link.exists():
        try:
            return latest_link.resolve()
        except Exception:
            return None
    return None


def _diff_summary(old_text: str, new_text: str):
    if old_text is None or new_text is None:
        return None
    added = 0
    removed = 0
    for line in difflib.ndiff(old_text.splitlines(), new_text.splitlines()):
        if line.startswith("+ "):
            added += 1
        elif line.startswith("- "):
            removed += 1
    return f"added={added} removed={removed}"


def run_device(device_id):
    conn = connect()
    try:
        device = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        if not device:
            raise SystemExit("Dispositivo não encontrado")
        interval = _global_interval_minutes(conn)
        timeout_seconds = _device_timeout_seconds()
        dev_password = decrypt_secret(device["dev_password_enc"])
        script_override, _ = _get_script_override(conn, device["script_id"])
        override = script_override or _get_vendor_script_override(conn, device["vendor"].lower())
        conn.execute(
            "UPDATE devices SET running = 1, run_started_at = ?, last_debug = ?, last_debug_at = ? WHERE id = ?",
            (now_iso(), "", now_iso(), device_id),
        )
        conn.commit()
        log_lines = []
        def log_cb(msg):
            ts = datetime.now().strftime("%H:%M:%S")
            log_lines.append(f"[{ts}] {msg}")
            if len(log_lines) > 200:
                log_lines[:] = log_lines[-200:]
            _mark_device_debug(conn, device_id, log_lines)
        content, meta = _run_with_timeout(
            timeout_seconds,
            run_backup,
            device,
            device["dev_username"],
            dev_password,
            device["command_override"],
            override,
            log_cb=log_cb,
        )
        latest_path = _latest_backup_path(device)
        old_content = None
        old_hash = None
        if latest_path and latest_path.exists():
            try:
                old_content = latest_path.read_text(encoding="utf-8", errors="ignore")
                old_hash = hashlib.md5(old_content.encode("utf-8", errors="ignore")).hexdigest()
            except Exception:
                old_content = None
                old_hash = None
        same = old_hash and meta.get("content_hash") and old_hash == meta.get("content_hash")
        diff_summary = _diff_summary(old_content, content) if old_content is not None else None
        removed = []
        if same and latest_path:
            path = str(latest_path)
            size = latest_path.stat().st_size
        else:
            path, size = save_backup(device, content)
            removed = prune_backups(device, BACKUP_KEEP_LAST)
        status = "ok"
        message = None
        if meta.get("validation_error"):
            status = "invalid"
            message = meta["validation_error"]
        elif same:
            status = "same"
            message = "Backup idêntico (não salvo)"
        elif size < min_backup_bytes(device["vendor"]):
            status = "short"
            message = f"Backup muito curto ({size} bytes)"
        conn.execute(
            "INSERT INTO backups (device_id, path, created_at, size_bytes, status, message, debug_log, duration_seconds, line_count, content_hash, firmware, diff_summary) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                device_id,
                path,
                now_iso(),
                size,
                status,
                message,
                "\n".join(log_lines),
                meta.get("duration_seconds"),
                meta.get("line_count"),
                meta.get("content_hash"),
                meta.get("firmware"),
                diff_summary,
            ),
        )
        if removed:
            placeholders = ",".join(["?"] * len(removed))
            conn.execute(
                f"DELETE FROM backups WHERE device_id = ? AND path IN ({placeholders})",
                [device_id, *removed],
            )
        conn.execute(
            "UPDATE devices SET last_run_at = ?, next_run_at = ? WHERE id = ?",
            (now_iso(), _next_run_iso(interval), device_id),
        )
        conn.commit()
        print(f"Backup ok: {path}")
    except Exception as exc:
        conn.execute(
            "INSERT INTO backups (device_id, path, created_at, size_bytes, status, message, debug_log, duration_seconds, line_count, content_hash, firmware, diff_summary) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (device_id, "", now_iso(), 0, "error", str(exc), "\n".join(log_lines), None, None, None, None, None),
        )
        conn.execute(
            "UPDATE devices SET last_run_at = ?, next_run_at = ? WHERE id = ?",
            (now_iso(), _next_run_iso(interval), device_id),
        )
        conn.commit()
        raise
    finally:
        try:
            conn.execute(
                "UPDATE devices SET running = 0, run_started_at = NULL WHERE id = ?",
                (device_id,),
            )
            conn.commit()
        except Exception:
            pass
        conn.close()


def run_all(args):
    init_db()
    conn = connect()
    try:
        devices = conn.execute("SELECT * FROM devices").fetchall()
        if not devices:
            print("Nenhum dispositivo cadastrado")
            return
        for d in devices:
            print(f"Coletando {d['name']} ({d['vendor']})...")
            run_device(d["id"])
    finally:
        conn.close()


def run_due(args):
    init_db()
    now = datetime.now()
    lock_fd = _acquire_lock()
    if lock_fd is None:
        print("Scheduler já em execução. Ignorando este ciclo.")
        return
    conn = connect()
    try:
        released = _expire_stale_running(conn)
        for device_id, name, age in released:
            print(f"Liberando running preso: {name} (id={device_id}, idade={age})")
        rows = conn.execute(
            """
            SELECT * FROM devices
            WHERE (next_run_at IS NULL OR next_run_at <= ?)
              AND (running IS NULL OR running = 0)
            """,
            (now.strftime("%Y-%m-%dT%H:%M:%S"),),
        ).fetchall()
        if not rows:
            print("Nenhum dispositivo agendado agora")
            return
        for d in rows:
            print(f"Coletando {d['name']} ({d['vendor']})...")
            run_device(d["id"])
    finally:
        conn.close()
        _release_lock(lock_fd)


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_admin = sub.add_parser("init-admin")
    p_admin.add_argument("--username", required=True)
    p_admin.add_argument("--password", required=True)
    p_admin.set_defaults(func=init_admin)

    p_run = sub.add_parser("run-device")
    p_run.add_argument("--id", required=True, type=int)
    p_run.set_defaults(func=lambda args: run_device(args.id))

    p_all = sub.add_parser("run-all")
    p_all.set_defaults(func=run_all)

    p_due = sub.add_parser("run-due")
    p_due.set_defaults(func=run_due)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
