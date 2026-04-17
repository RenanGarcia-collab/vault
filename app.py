from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, abort
from datetime import datetime, timedelta
from pathlib import Path
import os
import shutil
import sqlite3
import threading
import hashlib
import math
from config import FLASK_HOST, FLASK_PORT, BACKUP_ROOT, BACKUP_KEEP_LAST
from db import init_db, connect
from security import load_session_secret, hash_password, verify_password, encrypt_secret, decrypt_secret
from utils import slugify, now_iso
from backup import run_backup, save_backup, list_backups, ensure_device_dir, VENDOR_COMMANDS, MIN_BACKUP_BYTES, prune_backups, min_backup_bytes, normalize_huawei_output
import difflib

app = Flask(__name__)
app.secret_key = load_session_secret()
STALE_RUNNING_GRACE_SECONDS = int(os.environ.get("STALE_RUNNING_GRACE_SECONDS", "120"))


@app.before_request
def init():
    init_db()


@app.after_request
def disable_dynamic_cache(response):
    if request.endpoint != "static":
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    conn = connect()
    try:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        return user
    finally:
        conn.close()


def login_required(fn):
    def wrapper(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper


def admin_required(fn):
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user or user["role"] != "admin":
            abort(403)
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper


def get_device_or_404(device_id):
    conn = connect()
    try:
        device = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        if not device:
            abort(404)
        return device
    finally:
        conn.close()


def check_device_access(user, device):
    if user["role"] == "admin":
        return True
    if device["user_id"] == user["id"]:
        return True
    if user["device_id"] == device["id"]:
        return True
    return False


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = connect()
        try:
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        finally:
            conn.close()
        if not user or not verify_password(password, user["password_hash"]):
            flash("Login inválido", "error")
            return render_template("login.html")
        session["user_id"] = user["id"]
        return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    user = current_user()
    conn = connect()
    try:
        folders = conn.execute("SELECT * FROM folders ORDER BY sort_order, name").fetchall()
        vendors = conn.execute("SELECT * FROM vendors ORDER BY name").fetchall()
        if user["role"] == "admin":
            devices = conn.execute(
                """
                SELECT d.*, v.name AS vendor_label
                FROM devices d
                LEFT JOIN vendors v ON v.key = d.vendor
                ORDER BY d.vendor, d.name
                """
            ).fetchall()
        else:
            devices = conn.execute(
                """
                SELECT d.*, v.name AS vendor_label
                FROM devices d
                LEFT JOIN vendors v ON v.key = d.vendor
                WHERE d.user_id = ? OR d.id = ?
                """,
                (user["id"], user["device_id"]),
            ).fetchall()
    finally:
        conn.close()

    vendor_map = {v["key"]: v["name"] for v in vendors}
    by_parent, _ = _build_folder_tree(folders)
    root_folders = by_parent.get(None, [])
    device_counts = {}
    for d in devices:
        device_counts[d["folder_id"]] = device_counts.get(d["folder_id"], 0) + 1

    # vendor summary (last backup time per vendor)
    summaries = {}
    conn = connect()
    try:
        rows = conn.execute(
            """
            SELECT d.folder_id AS folder_id, MAX(b.created_at) AS last_backup
            FROM devices d
            LEFT JOIN backups b ON b.device_id = d.id
            GROUP BY d.folder_id
            """
        ).fetchall()
        for r in rows:
            summaries[r["folder_id"]] = r["last_backup"]
        storage_total_gb = float(_get_setting(conn, "storage_total_gb", "10") or "10")
    finally:
        conn.close()

    def _max_ts(a, b):
        if not a:
            return b
        if not b:
            return a
        return a if a >= b else b

    def _folder_total_count(folder_id):
        total = device_counts.get(folder_id, 0)
        for child in by_parent.get(folder_id, []):
            total += _folder_total_count(child["id"])
        return total

    def _folder_last_backup(folder_id):
        latest = summaries.get(folder_id)
        for child in by_parent.get(folder_id, []):
            child_latest = _folder_last_backup(child["id"])
            if not latest:
                latest = child_latest
            elif child_latest and child_latest > latest:
                latest = child_latest
        return latest

    storage_used_bytes = _dir_size_bytes(BACKUP_ROOT)
    storage_total_bytes = int(storage_total_gb * 1024 * 1024 * 1024)
    storage_pct = min(100, round((storage_used_bytes / storage_total_bytes) * 100, 1)) if storage_total_bytes else 0
    storage_angle = max(0, min(360, round((storage_pct / 100) * 360, 1)))
    storage_remaining_bytes = max(0, storage_total_bytes - storage_used_bytes)
    storage_state_label, storage_state_class = _storage_state(storage_pct)
    disk_total_bytes, disk_used_bytes, disk_free_bytes = _disk_usage_bytes(BACKUP_ROOT)
    disk_pct = min(100, round((disk_used_bytes / disk_total_bytes) * 100, 1)) if disk_total_bytes else 0
    disk_state_label, disk_state_class = _storage_state(disk_pct)

    return render_template(
        "index.html",
        user=user,
        devices=devices,
        folder_counts={f["id"]: _folder_total_count(f["id"]) for f in folders},
        folder_summaries={f["id"]: _folder_last_backup(f["id"]) for f in folders},
        folders=root_folders,
        current_folder_id=None,
        active_path=[],
        vendor_map=vendor_map,
        humanize=_humanize_since,
        backup_root=BACKUP_ROOT,
        storage_total_gb=storage_total_gb,
        storage_used_bytes=storage_used_bytes,
        storage_total_bytes=storage_total_bytes,
        storage_remaining_bytes=storage_remaining_bytes,
        storage_pct=storage_pct,
        storage_angle=storage_angle,
        storage_state_label=storage_state_label,
        storage_state_class=storage_state_class,
        disk_total_bytes=disk_total_bytes,
        disk_used_bytes=disk_used_bytes,
        disk_free_bytes=disk_free_bytes,
        disk_pct=disk_pct,
        disk_state_label=disk_state_label,
        disk_state_class=disk_state_class,
        format_bytes=_format_bytes,
        format_gb=_format_gb,
    )


@app.route("/events")
@login_required
def events():
    user = current_user()
    status = (request.args.get("status") or "all").strip().lower()
    start_date_raw = (request.args.get("start") or "").strip()
    end_date_raw = (request.args.get("end") or "").strip()
    page = request.args.get("page", "1")
    try:
        page = int(page)
    except Exception:
        page = 1
    if page < 1:
        page = 1
    per_page = 10
    offset = (page - 1) * per_page

    def _normalize_date(value: str):
        if not value:
            return "", ""
        raw = value.strip()
        if "/" in raw and len(raw) >= 8:
            try:
                d, m, y = raw.split("/")[:3]
                normalized = f"{y.zfill(4)}-{m.zfill(2)}-{d.zfill(2)}"
                return normalized, raw
            except Exception:
                return "", ""
        return raw, raw

    start_date, start_display = _normalize_date(start_date_raw)
    end_date, end_display = _normalize_date(end_date_raw)

    where_clause = ""
    params = []
    if status == "error":
        where_clause = "WHERE b.status = 'error'"
    elif status == "success":
        where_clause = "WHERE b.status != 'error'"
    else:
        status = "all"
    if start_date:
        where_clause += (" AND " if where_clause else "WHERE ") + "date(b.created_at) >= date(?)"
        params.append(start_date)
    if end_date:
        where_clause += (" AND " if where_clause else "WHERE ") + "date(b.created_at) <= date(?)"
        params.append(end_date)

    conn = connect()
    try:
        total = conn.execute(
            f"SELECT COUNT(1) AS c FROM backups b {where_clause}",
            params,
        ).fetchone()["c"]
        rows = conn.execute(
            f"""
            SELECT b.created_at, b.status, b.message, d.name AS device_name, d.vendor AS vendor
            FROM backups b
            LEFT JOIN devices d ON d.id = b.device_id
            {where_clause}
            ORDER BY datetime(b.created_at) DESC, b.id DESC
            LIMIT ? OFFSET ?
            """,
            (*params, per_page, offset),
        ).fetchall()
        recent_total = conn.execute(
            """
            SELECT COUNT(1) AS c
            FROM backups
            WHERE datetime(created_at) >= datetime('now', '-7 days')
            """
        ).fetchone()["c"]
        recent_errors = conn.execute(
            """
            SELECT COUNT(1) AS c
            FROM backups
            WHERE status = 'error' AND datetime(created_at) >= datetime('now', '-7 days')
            """
        ).fetchone()["c"]
        recent_success = recent_total - recent_errors
    finally:
        conn.close()

    total_pages = max(1, math.ceil(total / per_page)) if total else 1
    page = min(page, total_pages)
    status_labels = {
        "ok": "Ok",
        "short": "Curto",
        "same": "Igual",
        "invalid": "Inválido",
        "error": "Erro",
    }
    return render_template(
        "events.html",
        user=user,
        rows=rows,
        page=page,
        total_pages=total_pages,
        total=total,
        status=status,
        status_labels=status_labels,
        recent_success=recent_success,
        recent_errors=recent_errors,
        start_date=start_date,
        end_date=end_date,
        start_display=start_display,
        end_display=end_display,
    )


@app.route("/settings", methods=["GET", "POST"])
@admin_required
def settings():
    conn = connect()
    try:
        current = _global_interval_minutes(conn)
        if request.method == "POST":
            interval = _parse_global_interval(request.form.get("global_interval_minutes"))
            if interval is None:
                flash("Intervalo inválido.", "error")
                return render_template("settings.html", user=current_user(), global_interval_minutes=current)
            _set_setting(conn, "global_interval_minutes", interval)
            if request.form.get("apply_all") == "1":
                next_run = _next_run_iso(interval)
                conn.execute("UPDATE devices SET next_run_at = ?", (next_run,))
            conn.commit()
            flash("Configurações atualizadas.", "success")
            return redirect(url_for("settings"))
    finally:
        conn.close()
    return render_template("settings.html", user=current_user(), global_interval_minutes=current)


def _parse_interval(value):
    try:
        v = int(value)
        if v <= 0:
            return None
        return v
    except Exception:
        return None


def _parse_port(value):
    try:
        v = int((value or "").strip() or "22")
        if v <= 0 or v > 65535:
            return None
        return v
    except Exception:
        return None


def _parse_iso_datetime(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


def _device_timeout_for_row(conn, row):
    timeout_seconds = None
    if row and row["script_id"]:
        script = conn.execute("SELECT timeout_seconds FROM scripts WHERE id = ?", (row["script_id"],)).fetchone()
        timeout_seconds = script["timeout_seconds"] if script else None
    try:
        timeout_seconds = int(timeout_seconds or 0)
    except Exception:
        timeout_seconds = 0
    return timeout_seconds or 900


def _reset_stale_running_for_device(conn, row):
    if not row or not row["running"]:
        return False
    started_at = _parse_iso_datetime(row["run_started_at"])
    timeout_seconds = _device_timeout_for_row(conn, row)
    now = datetime.now()
    if started_at is not None:
        age_seconds = (now - started_at).total_seconds()
        if age_seconds <= timeout_seconds + STALE_RUNNING_GRACE_SECONDS:
            return False
    note = f"[{now.strftime('%H:%M:%S')}] stale running flag reset by web"
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
        (note, note, now_iso(), row["id"]),
    )
    conn.commit()
    return True


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


def _get_setting(conn, key, default=None):
    row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row and row["value"] is not None else default


def _set_setting(conn, key, value):
    conn.execute(
        """
        INSERT INTO app_settings (key, value, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
        """,
        (key, str(value), now_iso()),
    )


def _parse_storage_gb(value):
    raw = (value or "").strip().lower().replace(" ", "")
    if raw.endswith("gb"):
        raw = raw[:-2]
    size = float(raw)
    if size <= 0:
        raise ValueError
    return size


def _global_interval_minutes(conn):
    raw = _get_setting(conn, "global_interval_minutes", "60")
    return _parse_global_interval(raw) or 60


def _build_folder_tree(rows):
    by_parent = {}
    by_id = {}
    for r in rows:
        by_id[r["id"]] = r
        by_parent.setdefault(r["parent_id"], []).append(r)
    for children in by_parent.values():
        children.sort(key=lambda x: ((x["sort_order"] if "sort_order" in x.keys() else 0), (x["name"] or "").lower()))
    return by_parent, by_id


def _folder_descendants(by_parent, folder_id):
    descendants = set()
    stack = [folder_id]
    while stack:
        current = stack.pop()
        for child in by_parent.get(current, []):
            cid = child["id"]
            if cid not in descendants:
                descendants.add(cid)
                stack.append(cid)
    return descendants


def _folder_options(rows, exclude_ids=None):
    by_parent, _ = _build_folder_tree(rows)
    options = []

    def walk(parent_id, prefix):
        for r in by_parent.get(parent_id, []):
            if exclude_ids and r["id"] in exclude_ids:
                continue
            label = f"{prefix}{r['name']}"
            options.append({"id": r["id"], "name": label})
            walk(r["id"], f"{prefix}{r['name']} / ")

    walk(None, "")
    return options


def _folder_path(by_id, folder_id):
    path = []
    current = by_id.get(folder_id)
    while current:
        path.append(current)
        current = by_id.get(current["parent_id"])
    return list(reversed(path))


def _folder_tree_nodes(by_parent, parent_id):
    nodes = []
    for child in by_parent.get(parent_id, []):
        nodes.append(
            {
                "id": child["id"],
                "name": child["name"],
                "children": _folder_tree_nodes(by_parent, child["id"]),
            }
        )
    return nodes


def _folder_depth(by_id, folder_id):
    depth = 0
    current = by_id.get(folder_id)
    while current and current["parent_id"]:
        depth += 1
        current = by_id.get(current["parent_id"])
    return depth


def _max_depth_for_parent(by_id, parent_id):
    if parent_id is None:
        return 0
    if parent_id not in by_id:
        return None
    return _folder_depth(by_id, parent_id) + 1


def _folder_label_map(rows):
    return {item["id"]: item["name"] for item in _folder_options(rows)}


def _find_same_parent_folder(conn, name, parent_id, exclude_folder_id=None):
    params = [name.strip().lower(), parent_id]
    query = "SELECT id, name, parent_id FROM folders WHERE lower(trim(name)) = ? AND parent_id IS ?"
    if exclude_folder_id is not None:
        query += " AND id != ?"
        params.append(exclude_folder_id)
    return conn.execute(query, params).fetchone()


def _find_other_parent_folder(conn, name, parent_id, exclude_folder_id=None):
    params = [name.strip().lower(), parent_id]
    query = "SELECT id, name, parent_id FROM folders WHERE lower(trim(name)) = ? AND parent_id IS NOT ?"
    if exclude_folder_id is not None:
        query += " AND id != ?"
        params.append(exclude_folder_id)
    query += " ORDER BY id LIMIT 1"
    return conn.execute(query, params).fetchone()


def _device_name_matches_clause():
    return "lower(trim(name)) = ?"


def _find_same_folder_device(conn, name, folder_id, exclude_device_id=None):
    params = [name.strip().lower(), folder_id]
    query = f"SELECT id, name, slug, folder_id FROM devices WHERE {_device_name_matches_clause()} AND folder_id = ?"
    if exclude_device_id is not None:
        query += " AND id != ?"
        params.append(exclude_device_id)
    return conn.execute(query, params).fetchone()


def _find_other_folder_device(conn, name, folder_id, exclude_device_id=None):
    params = [name.strip().lower(), folder_id]
    query = f"SELECT id, name, slug, folder_id FROM devices WHERE {_device_name_matches_clause()} AND folder_id != ?"
    if exclude_device_id is not None:
        query += " AND id != ?"
        params.append(exclude_device_id)
    query += " ORDER BY id LIMIT 1"
    return conn.execute(query, params).fetchone()


def _build_unique_device_slug(conn, name, exclude_device_id=None, preferred_slug=None):
    base_slug = slugify(name)
    candidates = []
    if preferred_slug:
        candidates.append(preferred_slug)
    candidates.append(base_slug)
    suffix = 2
    while True:
        candidate = candidates.pop(0) if candidates else f"{base_slug}-{suffix}"
        suffix += 1
        if exclude_device_id is None:
            row = conn.execute("SELECT id FROM devices WHERE slug = ?", (candidate,)).fetchone()
        else:
            row = conn.execute(
                "SELECT id FROM devices WHERE slug = ? AND id != ?",
                (candidate, exclude_device_id),
            ).fetchone()
        if not row:
            return candidate


def _render_devices_new_form(vendors, scripts, folder_options, device_users, vendor_prefill, folder_prefill, form_data=None, duplicate_name_warning=None):
    return render_template(
        "devices_new.html",
        user=current_user(),
        vendors=vendors,
        scripts=scripts,
        folder_options=folder_options,
        device_users=device_users,
        vendor_prefill=vendor_prefill,
        folder_prefill=folder_prefill,
        form_data=form_data or {},
        duplicate_name_warning=duplicate_name_warning,
    )


def _render_devices_edit_form(device, vendors, scripts, folder_options, device_users, assigned_user, form_data=None, duplicate_name_warning=None):
    return render_template(
        "devices_edit.html",
        user=current_user(),
        device=device,
        vendors=vendors,
        scripts=scripts,
        folder_options=folder_options,
        device_users=device_users,
        assigned_user=assigned_user,
        form_data=form_data or {},
        duplicate_name_warning=duplicate_name_warning,
    )


def _render_folders_new_form(folder_options, parent_prefill, form_data=None, duplicate_name_warning=None):
    return render_template(
        "folders_new.html",
        user=current_user(),
        folder_options=folder_options,
        parent_prefill=parent_prefill,
        form_data=form_data or {},
        duplicate_name_warning=duplicate_name_warning,
    )


def _render_folders_edit_form(folder, folder_options, form_data=None, duplicate_name_warning=None):
    return render_template(
        "folders_edit.html",
        user=current_user(),
        folder=folder,
        folder_options=folder_options,
        form_data=form_data or {},
        duplicate_name_warning=duplicate_name_warning,
    )


def _parse_global_interval(value):
    try:
        v = int((value or "").strip())
        if v <= 0:
            return None
        return v
    except Exception:
        return None


def _dir_size_bytes(path):
    base = Path(path)
    if not base.exists():
        return 0
    total = 0
    for item in base.rglob("*"):
        try:
            if item.is_file():
                total += item.stat().st_size
        except OSError:
            continue
    return total


def _disk_usage_bytes(path):
    target = path if os.path.exists(path) else "/"
    usage = shutil.disk_usage(target)
    used = max(0, usage.total - usage.free)
    return usage.total, used, usage.free


def _format_bytes(num):
    if num is None:
        return "0 B"
    size = float(num)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _format_gb(num):
    if num is None:
        return "0 GB"
    return f"{float(num):.2f} GB"


def _storage_state(storage_pct):
    if storage_pct >= 90:
        return "Capacidade crítica", "critical"
    if storage_pct >= 75:
        return "Capacidade em alerta", "warning"
    return "Capacidade saudável", "healthy"


def _format_datetime_display(value):
    if not value:
        return "—"
    raw = str(value).strip()
    try:
        normalized = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        return dt.strftime("%d/%m/%Y %H:%M")
    except Exception:
        return raw


def _format_date_display(value):
    if not value:
        return "—"
    raw = str(value).strip()
    try:
        normalized = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        return dt.strftime("%d/%m/%Y")
    except Exception:
        return raw[:10] if len(raw) >= 10 else raw


def _format_time_display(value):
    if not value:
        return "—"
    raw = str(value).strip()
    try:
        normalized = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        return dt.strftime("%H:%M")
    except Exception:
        return raw[11:16] if len(raw) >= 16 else raw


def _is_under_root(file_path: Path, root: Path) -> bool:
    try:
        return file_path.resolve().is_relative_to(root.resolve())
    except AttributeError:
        return os.path.commonpath([str(file_path.resolve()), str(root.resolve())]) == str(root.resolve())


@app.context_processor
def inject_template_helpers():
    return {
        "format_datetime": _format_datetime_display,
        "format_date": _format_date_display,
        "format_time": _format_time_display,
    }


@app.context_processor
def inject_sidebar_tree():
    if not session.get("user_id"):
        return {}
    conn = connect()
    try:
        folders = conn.execute("SELECT * FROM folders ORDER BY sort_order, name").fetchall()
        by_parent, _ = _build_folder_tree(folders)
        device_counts = {}
        rows = conn.execute("SELECT folder_id, COUNT(1) AS c FROM devices GROUP BY folder_id").fetchall()
        for r in rows:
            device_counts[r["folder_id"]] = r["c"]

        def _count_recursive(fid):
            total = device_counts.get(fid, 0)
            for child in by_parent.get(fid, []):
                total += _count_recursive(child["id"])
            return total

        def _tree(parent_id):
            nodes = []
            for f in by_parent.get(parent_id, []):
                nodes.append(
                    {
                        "id": f["id"],
                        "name": f["name"],
                        "count": _count_recursive(f["id"]),
                        "children": _tree(f["id"]),
                    }
                )
            return nodes

        return {"sidebar_tree": _tree(None)}
    finally:
        conn.close()


def _device_users(conn, selected_device_id=None):
    return conn.execute(
        """
        SELECT *
        FROM users
        WHERE role = 'device'
        ORDER BY username
        """
    ).fetchall()


def _resolve_device_credentials(conn, user_id):
    if not user_id:
        raise ValueError("Selecione um usuário de perfil Equipamento para o dispositivo.")
    selected_user = conn.execute(
        "SELECT * FROM users WHERE id = ? AND role = 'device'",
        (int(user_id),),
    ).fetchone()
    if not selected_user:
        raise ValueError("Usuário vinculado inválido.")
    if not selected_user["device_password_enc"]:
        raise ValueError("O usuário vinculado não possui senha reutilizável para o equipamento. Recrie esse usuário no menu de usuários.")
    return (selected_user["login_username"] or selected_user["username"]), decrypt_secret(selected_user["device_password_enc"])


def _get_vendor_script_override(vendor):
    conn = connect()
    try:
        row = conn.execute("SELECT * FROM vendor_scripts WHERE vendor = ?", (vendor,)).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    def _row_get(r, key, default=None):
        try:
            return r[key]
        except Exception:
            return default
    pre_text = row["pre_text"] or ""
    pre_list = [line.strip() for line in pre_text.splitlines() if line.strip()]
    return {
        "pre": pre_list,
        "cmd": row["cmd"],
        "prompt": row["prompt"],
        "read_mode": row["read_mode"],
        "sleep": row["sleep"],
        "timeout": _row_get(row, "timeout_seconds"),
    }


def _get_script_override(script_id):
    if not script_id:
        return None, None
    try:
        script_id = int(script_id)
    except (TypeError, ValueError):
        return None, None
    conn = connect()
    try:
        row = conn.execute("SELECT * FROM scripts WHERE id = ?", (script_id,)).fetchone()
    finally:
        conn.close()
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


def _recent_backup_rows(conn, device_id, limit=3):
    rows = conn.execute(
        """
        SELECT *
        FROM backups
        WHERE device_id = ?
        ORDER BY datetime(created_at) DESC, id DESC
        LIMIT ?
        """,
        (device_id, limit),
    ).fetchall()
    normalized = []
    for row in rows:
        item = dict(row)
        path = (item.get("path") or "").strip()
        item["file_exists"] = bool(path and os.path.exists(path))
        normalized.append(item)
    return normalized


def _parse_diff_summary(summary):
    if not summary:
        return 0, 0
    added = 0
    removed = 0
    for chunk in str(summary).split():
        if "=" not in chunk:
            continue
        key, value = chunk.split("=", 1)
        try:
            amount = int(value)
        except Exception:
            continue
        if key == "added":
            added = amount
        elif key == "removed":
            removed = amount
    return added, removed


def _backup_change_label(row):
    if not row:
        return "Sem execucoes recentes."
    status = (row.get("status") or "ok").lower()
    if status == "same":
        return "Nenhuma alteracao detectada neste backup."
    if status == "ok":
        added, removed = _parse_diff_summary(row.get("diff_summary"))
        if added or removed:
            return f"Alteracoes detectadas: {added} linhas adicionadas e {removed} removidas."
        return "Backup salvo com alteracoes, mas sem resumo detalhado das diferencas."
    if status == "short":
        return "O backup foi salvo, mas o conteudo ficou curto demais para confiar na comparacao."
    if status == "invalid":
        return "O backup foi coletado, mas o conteudo nao passou na validacao."
    if status == "error":
        return f"Falha na coleta: {row.get('message') or 'erro nao informado'}"
    return "Status de backup nao reconhecido."


def _select_compare_pair(rows):
    if not rows:
        return None, None
    current_row = None
    for row in rows:
        if row.get("path") and row.get("file_exists"):
            current_row = row
            break
    if not current_row:
        return None, None

    current_path = current_row.get("path")
    current_hash = current_row.get("content_hash")
    baseline_row = None
    seen_current = False
    for row in rows:
        if not row.get("path") or not row.get("file_exists"):
            continue
        if not seen_current:
            if row is current_row:
                seen_current = True
            continue
        same_snapshot = False
        if current_hash and row.get("content_hash"):
            same_snapshot = row.get("content_hash") == current_hash
        elif current_path and row.get("path"):
            same_snapshot = row.get("path") == current_path
        if same_snapshot:
            continue
        baseline_row = row
        break
    return current_row, baseline_row


def _latest_compare_url(current_row, previous_row):
    if not current_row or not previous_row:
        return None
    if not current_row.get("path") or not previous_row.get("path"):
        return None
    if not current_row.get("file_exists") or not previous_row.get("file_exists"):
        return None
    return url_for("compare_backup", current=current_row["path"], previous=previous_row["path"])


def _display_change_label(latest_row, current_row, previous_row, vendor=""):
    if not latest_row:
        return None
    latest_status = (latest_row.get("status") or "").lower()
    if latest_status == "same" and current_row and previous_row:
        added, removed = _parse_diff_summary(_diff_summary(
            _load_backup_content(Path(previous_row["path"]), vendor),
            _load_backup_content(Path(current_row["path"]), vendor),
        ))
        if added or removed:
            return (
                "Sem novas alteracoes nesta coleta. "
                f"A configuracao atual ainda difere do snapshot anterior: {added} linhas adicionadas e {removed} removidas."
            )
    return _backup_change_label(latest_row)


def _load_backup_content(file_path: Path, vendor: str):
    content = file_path.read_text(encoding="utf-8", errors="ignore")
    if (vendor or "").lower() == "huawei":
        content = normalize_huawei_output(content)
    return content


def _resolve_device_for_backup_access(conn, user, file_path: Path):
    if user["role"] == "device":
        devices = conn.execute(
            "SELECT * FROM devices WHERE user_id = ? OR id = ?",
            (user["id"], user["device_id"]),
        ).fetchall()
        if not devices:
            abort(403)
        device = next(
            (
                d for d in devices
                if _is_under_root(file_path, Path(BACKUP_ROOT) / d["vendor"].lower() / d["slug"])
            ),
            None,
        )
        if not device:
            abort(403)
        return device

    parts = file_path.parts
    if len(parts) >= 5:
        vendor = parts[-5]
        slug = parts[-4]
        return conn.execute(
            "SELECT * FROM devices WHERE vendor = ? AND slug = ?",
            (vendor, slug),
        ).fetchone()
    return None


def _humanize_since(iso_ts):
    if not iso_ts:
        return "—"
    try:
        raw = str(iso_ts).strip()
        if raw.endswith("Z"):
            raw = raw[:-1]
        dt = datetime.fromisoformat(raw)
    except Exception:
        return iso_ts
    if dt.tzinfo:
        now = datetime.now(dt.tzinfo)
    else:
        now = datetime.now()
    delta = now - dt
    seconds = int(delta.total_seconds())
    if seconds < 0:
        return "agora"
    if seconds < 60:
        return "agora"
    minutes = seconds // 60
    if minutes < 60:
        return f"há {minutes} minuto" if minutes == 1 else f"há {minutes} minutos"
    hours = minutes // 60
    if hours < 24:
        return f"há {hours} hora" if hours == 1 else f"há {hours} horas"
    days = hours // 24
    return f"há {days} dia" if days == 1 else f"há {days} dias"


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


def _build_unified_diff(previous_text: str, current_text: str, previous_label: str, current_label: str):
    diff_lines = list(
        difflib.unified_diff(
            previous_text.splitlines(),
            current_text.splitlines(),
            fromfile=previous_label,
            tofile=current_label,
            lineterm="",
            n=3,
        )
    )
    return "\n".join(diff_lines) if diff_lines else "Nenhuma diferenca encontrada."


def _build_diff_snippets(previous_text: str, current_text: str, context_lines: int = 2, max_blocks: int = 8):
    raw_lines = list(
        difflib.unified_diff(
            previous_text.splitlines(),
            current_text.splitlines(),
            fromfile="anterior",
            tofile="atual",
            lineterm="",
            n=context_lines,
        )
    )
    blocks = []
    current_block = None
    for line in raw_lines:
        if line.startswith(("---", "+++")):
            continue
        if line.startswith("@@"):
            if current_block and current_block["lines"]:
                blocks.append(current_block)
            current_block = {"header": line, "lines": []}
            continue
        if current_block is None:
            continue
        if line.startswith(("+", "-")) and not line.startswith(("+++", "---")):
            line_kind = "added" if line.startswith("+") else "removed"
            current_block["lines"].append({"kind": line_kind, "text": line})
        elif line.startswith(" "):
            current_block["lines"].append({"kind": "context", "text": line})
    if current_block and current_block["lines"]:
        blocks.append(current_block)
    return blocks[:max_blocks]



@app.route("/folders/new", methods=["GET", "POST"])
@admin_required
def folders_new():
    conn = connect()
    try:
        all_folders = conn.execute("SELECT * FROM folders ORDER BY sort_order, name").fetchall()
        by_parent, by_id = _build_folder_tree(all_folders)
        folder_options = _folder_options(all_folders)
        folder_labels = _folder_label_map(all_folders)
        parent_prefill = request.args.get("parent_id")
        if request.method == "POST":
            try:
                form_data = {
                    "name": request.form.get("name", "").strip(),
                    "parent_id": (request.form.get("parent_id") or "").strip(),
                    "confirm_duplicate_name": (request.form.get("confirm_duplicate_name") or "").strip(),
                }
                name = request.form.get("name", "").strip()
                parent_id_raw = request.form.get("parent_id") or None
                if not name:
                    flash("Preencha o nome da pasta.", "error")
                    return _render_folders_new_form(folder_options, parent_prefill, form_data=form_data)
                if parent_id_raw:
                    try:
                        parent_id = int(parent_id_raw)
                    except ValueError:
                        flash("Pasta pai inválida.", "error")
                        return _render_folders_new_form(folder_options, parent_prefill, form_data=form_data)
                    parent = by_id.get(parent_id)
                    if not parent:
                        flash("Pasta pai inválida.", "error")
                        return _render_folders_new_form(folder_options, parent_prefill, form_data=form_data)
                    if _max_depth_for_parent(by_id, parent_id) > 2:
                        flash("Profundidade máxima atingida (pasta > subpasta > device).", "error")
                        return _render_folders_new_form(folder_options, parent_prefill, form_data=form_data)
                existing = _find_same_parent_folder(conn, name, parent_id if parent_id_raw else None)
                if existing:
                    flash("Já existe uma pasta com esse nome nesse nível.", "error")
                    return _render_folders_new_form(folder_options, parent_prefill, form_data=form_data)
                existing_other = _find_other_parent_folder(conn, name, parent_id if parent_id_raw else None)
                if existing_other and form_data["confirm_duplicate_name"] != "1":
                    return _render_folders_new_form(
                        folder_options,
                        parent_prefill,
                        form_data=form_data,
                        duplicate_name_warning={
                            "name": name,
                            "current_folder": folder_labels.get(parent_id, "raiz") if parent_id_raw else "raiz",
                            "existing_folder": folder_labels.get(existing_other["parent_id"], "raiz") if existing_other["parent_id"] else "raiz",
                        },
                    )
                conn.execute(
                    "INSERT INTO folders (name, parent_id, sort_order, created_at) VALUES (?, ?, 0, ?)",
                    (name, parent_id if parent_id_raw else None, now_iso()),
                )
                conn.commit()
                return redirect(url_for("index"))
            except sqlite3.IntegrityError:
                flash("Já existe uma pasta com esse nome nesse nível.", "error")
                return _render_folders_new_form(folder_options, parent_prefill, form_data=form_data)
    finally:
        conn.close()
    return _render_folders_new_form(folder_options, parent_prefill)


@app.route("/folders/<int:folder_id>/edit", methods=["GET", "POST"])
@admin_required
def folders_edit(folder_id):
    conn = connect()
    try:
        folder = conn.execute("SELECT * FROM folders WHERE id = ?", (folder_id,)).fetchone()
        if not folder:
            abort(404)
        all_folders = conn.execute("SELECT * FROM folders ORDER BY sort_order, name").fetchall()
        by_parent, by_id = _build_folder_tree(all_folders)
        folder_labels = _folder_label_map(all_folders)
        exclude_ids = _folder_descendants(by_parent, folder_id)
        exclude_ids.add(folder_id)
        folder_options = _folder_options(all_folders, exclude_ids=exclude_ids)
        if request.method == "POST":
            try:
                form_data = {
                    "name": request.form.get("name", "").strip(),
                    "parent_id": (request.form.get("parent_id") or "").strip(),
                    "confirm_duplicate_name": (request.form.get("confirm_duplicate_name") or "").strip(),
                }
                name = request.form.get("name", "").strip()
                if not name:
                    flash("Preencha o nome da pasta.", "error")
                    return _render_folders_edit_form(folder, folder_options, form_data=form_data)
                parent_id_raw = request.form.get("parent_id") or None
                if parent_id_raw:
                    try:
                        parent_id = int(parent_id_raw)
                    except ValueError:
                        flash("Pasta pai inválida.", "error")
                        return _render_folders_edit_form(folder, folder_options, form_data=form_data)
                    parent = by_id.get(parent_id)
                    if not parent or parent_id in exclude_ids:
                        flash("Pasta pai inválida.", "error")
                        return _render_folders_edit_form(folder, folder_options, form_data=form_data)
                    if _max_depth_for_parent(by_id, parent_id) > 2:
                        flash("Profundidade máxima atingida (pasta > subpasta > device).", "error")
                        return _render_folders_edit_form(folder, folder_options, form_data=form_data)
                existing = _find_same_parent_folder(conn, name, parent_id if parent_id_raw else None, exclude_folder_id=folder_id)
                if existing:
                    flash("Já existe uma pasta com esse nome nesse nível.", "error")
                    return _render_folders_edit_form(folder, folder_options, form_data=form_data)
                existing_other = _find_other_parent_folder(conn, name, parent_id if parent_id_raw else None, exclude_folder_id=folder_id)
                if existing_other and form_data["confirm_duplicate_name"] != "1":
                    return _render_folders_edit_form(
                        folder,
                        folder_options,
                        form_data=form_data,
                        duplicate_name_warning={
                            "name": name,
                            "current_folder": folder_labels.get(parent_id, "raiz") if parent_id_raw else "raiz",
                            "existing_folder": folder_labels.get(existing_other["parent_id"], "raiz") if existing_other["parent_id"] else "raiz",
                        },
                    )
                conn.execute(
                    "UPDATE folders SET name = ?, parent_id = ? WHERE id = ?",
                    (name, parent_id if parent_id_raw else None, folder_id),
                )
                conn.commit()
                return redirect(url_for("folder_detail", folder_id=folder_id))
            except sqlite3.IntegrityError:
                flash("Já existe uma pasta com esse nome nesse nível.", "error")
                return _render_folders_edit_form(folder, folder_options, form_data=form_data)
    finally:
        conn.close()
    return _render_folders_edit_form(folder, folder_options)




def _run_backup_task(device_id):
    conn = connect()
    try:
        device = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        if not device:
            return
        dev_password = decrypt_secret(device["dev_password_enc"])
        script_override, _ = _get_script_override(device["script_id"])
        override = script_override or _get_vendor_script_override(device["vendor"].lower())
        log_lines = []
        def log_cb(msg):
            ts = datetime.now().strftime("%H:%M:%S")
            line = f"[{ts}] {msg}"
            log_lines.append(line)
            if len(log_lines) > 200:
                log_lines[:] = log_lines[-200:]
            conn.execute(
                "UPDATE devices SET last_debug = ?, last_debug_at = ? WHERE id = ?",
                ("\n".join(log_lines), now_iso(), device_id),
            )
            conn.commit()
        try:
            content, meta = run_backup(device, device["dev_username"], dev_password, device["command_override"], override, log_cb=log_cb)
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
                    path or "",
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
            interval = _global_interval_minutes(conn)
            conn.execute(
                "UPDATE devices SET last_run_at = ?, next_run_at = ?, running = 0, run_started_at = NULL WHERE id = ?",
                (now_iso(), _next_run_iso(interval), device_id),
            )
            conn.commit()
        except Exception as exc:
            conn.execute(
                "INSERT INTO backups (device_id, path, created_at, size_bytes, status, message, debug_log, duration_seconds, line_count, content_hash, firmware, diff_summary) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (device_id, "", now_iso(), 0, "error", str(exc), "\n".join(log_lines), None, None, None, None, None),
            )
            interval = _global_interval_minutes(conn)
            conn.execute(
                "UPDATE devices SET last_run_at = ?, next_run_at = ?, running = 0, run_started_at = NULL WHERE id = ?",
                (now_iso(), _next_run_iso(interval), device_id),
            )
            conn.commit()
    finally:
        conn.close()


@app.route("/devices/new", methods=["GET", "POST"])
@admin_required
def devices_new():
    folder_prefill = request.args.get("folder_id")
    vendor_prefill = request.args.get("vendor")
    conn = connect()
    vendors = conn.execute("SELECT * FROM vendors ORDER BY name").fetchall()
    scripts = conn.execute("SELECT * FROM scripts ORDER BY name").fetchall()
    folders = conn.execute("SELECT * FROM folders ORDER BY sort_order, name").fetchall()
    folder_options = _folder_options(folders)
    folder_labels = _folder_label_map(folders)
    device_users = _device_users(conn)
    conn.close()

    if request.method == "POST":
        form_data = {
            "name": request.form.get("name", "").strip(),
            "folder_id": request.form.get("folder_id", "").strip(),
            "script_id": request.form.get("script_id", "").strip(),
            "ipaddr": request.form.get("ipaddr", "").strip(),
            "port": request.form.get("port", "22").strip(),
            "user_id": (request.form.get("user_id") or "").strip(),
            "command_override": request.form.get("command_override", "").strip(),
            "confirm_duplicate_name": (request.form.get("confirm_duplicate_name") or "").strip(),
        }
        name = request.form.get("name", "").strip()
        folder_id = request.form.get("folder_id")
        script_id = request.form.get("script_id")
        vendor = request.form.get("vendor", "").strip().lower()
        ipaddr = request.form.get("ipaddr", "").strip()
        port = _parse_port(request.form.get("port", "22"))
        user_id = request.form.get("user_id") or None
        command_override = request.form.get("command_override", "").strip() or None

        if not all([name, ipaddr, folder_id, script_id, user_id]):
            flash("Preencha todos os campos obrigatórios.", "error")
            return _render_devices_new_form(vendors, scripts, folder_options, device_users, vendor_prefill, folder_prefill, form_data=form_data)
        if port is None:
            flash("Porta inválida.", "error")
            return _render_devices_new_form(vendors, scripts, folder_options, device_users, vendor_prefill, folder_prefill, form_data=form_data)
        try:
            folder_id_int = int(folder_id)
            script_id_int = int(script_id)
            user_id_int = int(user_id)
        except (TypeError, ValueError):
            flash("Dados do formulário inválidos.", "error")
            return _render_devices_new_form(vendors, scripts, folder_options, device_users, vendor_prefill, folder_prefill, form_data=form_data)

        script_override, script_vendor = _get_script_override(script_id)
        if not script_vendor:
            flash("Tipo de coleta inválido.", "error")
            return _render_devices_new_form(vendors, scripts, folder_options, device_users, vendor_prefill, folder_prefill, form_data=form_data)
        vendor = script_vendor

        conn = connect()
        try:
            next_run_at = _next_run_iso(_global_interval_minutes(conn))
            try:
                dev_username, dev_password = _resolve_device_credentials(conn, user_id_int)
            except ValueError as exc:
                flash(str(exc), "error")
                return _render_devices_new_form(vendors, scripts, folder_options, device_users, vendor_prefill, folder_prefill, form_data=form_data)
            existing_same_folder = _find_same_folder_device(conn, name, folder_id_int)
            if existing_same_folder:
                flash(f"Já existe um equipamento com esse nome nesta pasta: {existing_same_folder['name']}.", "error")
                return _render_devices_new_form(vendors, scripts, folder_options, device_users, vendor_prefill, folder_prefill, form_data=form_data)
            existing_other_folder = _find_other_folder_device(conn, name, folder_id_int)
            if existing_other_folder and form_data["confirm_duplicate_name"] != "1":
                return _render_devices_new_form(
                    vendors,
                    scripts,
                    folder_options,
                    device_users,
                    vendor_prefill,
                    folder_prefill,
                    form_data=form_data,
                    duplicate_name_warning={
                        "name": name,
                        "current_folder": folder_labels.get(folder_id_int, str(folder_id_int)),
                        "existing_folder": folder_labels.get(existing_other_folder["folder_id"], str(existing_other_folder["folder_id"])),
                    },
                )
            slug = _build_unique_device_slug(conn, name)
            conn.execute(
                """
                INSERT INTO devices (name, slug, vendor, user_id, script_id, folder_id, ipaddr, port, dev_username, dev_password_enc, command_override, interval_minutes, next_run_at, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
                """,
                (
                    name,
                    slug,
                    vendor,
                    user_id_int,
                    script_id_int,
                    folder_id_int,
                    ipaddr,
                    port,
                    dev_username,
                    encrypt_secret(dev_password),
                    command_override,
                    next_run_at,
                    now_iso(),
                ),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            flash("Conflito ao salvar o equipamento. Revise o nome e tente novamente.", "error")
            return _render_devices_new_form(vendors, scripts, folder_options, device_users, vendor_prefill, folder_prefill, form_data=form_data)
        finally:
            conn.close()
        ensure_device_dir({"vendor": vendor, "slug": slug})
        return redirect(url_for("index"))
    return _render_devices_new_form(vendors, scripts, folder_options, device_users, vendor_prefill, folder_prefill)


@app.route("/devices/<int:device_id>/edit", methods=["GET", "POST"])
@admin_required
def devices_edit(device_id):
    device = get_device_or_404(device_id)
    conn = connect()
    vendors = conn.execute("SELECT * FROM vendors ORDER BY name").fetchall()
    scripts = conn.execute("SELECT * FROM scripts ORDER BY name").fetchall()
    folders = conn.execute("SELECT * FROM folders ORDER BY sort_order, name").fetchall()
    folder_options = _folder_options(folders)
    folder_labels = _folder_label_map(folders)
    device_users = _device_users(conn, selected_device_id=device_id)
    assigned_user = conn.execute(
        "SELECT * FROM users WHERE role = 'device' AND id = ? ORDER BY id LIMIT 1",
        (device["user_id"],),
    ).fetchone()
    conn.close()

    if request.method == "POST":
        form_data = {
            "name": request.form.get("name", "").strip(),
            "folder_id": request.form.get("folder_id", "").strip(),
            "script_id": request.form.get("script_id", "").strip(),
            "ipaddr": request.form.get("ipaddr", "").strip(),
            "port": request.form.get("port", "22").strip(),
            "user_id": (request.form.get("user_id") or "").strip(),
            "command_override": request.form.get("command_override", "").strip(),
            "confirm_duplicate_name": (request.form.get("confirm_duplicate_name") or "").strip(),
        }
        name = request.form.get("name", "").strip()
        folder_id = request.form.get("folder_id")
        script_id = request.form.get("script_id")
        vendor = request.form.get("vendor", "").strip().lower()
        ipaddr = request.form.get("ipaddr", "").strip()
        port = _parse_port(request.form.get("port", "22"))
        user_id = request.form.get("user_id") or None
        command_override = request.form.get("command_override", "").strip() or None

        if not all([name, ipaddr, folder_id, script_id, user_id]):
            flash("Preencha todos os campos obrigatórios.", "error")
            return _render_devices_edit_form(device, vendors, scripts, folder_options, device_users, assigned_user, form_data=form_data)
        if port is None:
            flash("Porta inválida.", "error")
            return _render_devices_edit_form(device, vendors, scripts, folder_options, device_users, assigned_user, form_data=form_data)
        try:
            folder_id_int = int(folder_id)
            script_id_int = int(script_id)
            user_id_int = int(user_id)
        except (TypeError, ValueError):
            flash("Dados do formulário inválidos.", "error")
            return _render_devices_edit_form(device, vendors, scripts, folder_options, device_users, assigned_user, form_data=form_data)

        script_override, script_vendor = _get_script_override(script_id)
        if not script_vendor:
            flash("Tipo de coleta inválido.", "error")
            return _render_devices_edit_form(device, vendors, scripts, folder_options, device_users, assigned_user, form_data=form_data)
        vendor = script_vendor

        conn = connect()
        try:
            try:
                resolved_username, resolved_password = _resolve_device_credentials(conn, user_id_int)
            except ValueError as exc:
                flash(str(exc), "error")
                return _render_devices_edit_form(device, vendors, scripts, folder_options, device_users, assigned_user, form_data=form_data)
            existing_same_folder = _find_same_folder_device(conn, name, folder_id_int, exclude_device_id=device_id)
            if existing_same_folder:
                flash(f"Já existe outro equipamento com esse nome nesta pasta: {existing_same_folder['name']}.", "error")
                return _render_devices_edit_form(device, vendors, scripts, folder_options, device_users, assigned_user, form_data=form_data)
            existing_other_folder = _find_other_folder_device(conn, name, folder_id_int, exclude_device_id=device_id)
            if existing_other_folder and form_data["confirm_duplicate_name"] != "1":
                return _render_devices_edit_form(
                    device,
                    vendors,
                    scripts,
                    folder_options,
                    device_users,
                    assigned_user,
                    form_data=form_data,
                    duplicate_name_warning={
                        "name": name,
                        "current_folder": folder_labels.get(folder_id_int, str(folder_id_int)),
                        "existing_folder": folder_labels.get(existing_other_folder["folder_id"], str(existing_other_folder["folder_id"])),
                    },
                )
            preferred_slug = device["slug"] if slugify(name) == slugify(device["name"]) else None
            new_slug = _build_unique_device_slug(conn, name, exclude_device_id=device_id, preferred_slug=preferred_slug)
            conn.execute(
                """
                UPDATE devices
                SET name = ?, slug = ?, vendor = ?, user_id = ?, script_id = ?, ipaddr = ?, port = ?, dev_username = ?, dev_password_enc = ?,
                    command_override = ?, folder_id = ?, interval_minutes = NULL
                WHERE id = ?
                """,
                (
                    name,
                    new_slug,
                    vendor,
                    user_id_int,
                    script_id_int,
                    ipaddr,
                    port,
                    resolved_username,
                    encrypt_secret(resolved_password),
                    command_override,
                    folder_id_int,
                    device_id,
                ),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            flash("Conflito ao salvar o equipamento. Revise o nome e tente novamente.", "error")
            return _render_devices_edit_form(device, vendors, scripts, folder_options, device_users, assigned_user, form_data=form_data)
        finally:
            conn.close()
        old_dir = Path(BACKUP_ROOT) / device["vendor"] / device["slug"]
        new_dir = Path(BACKUP_ROOT) / vendor / new_slug
        if old_dir.exists() and not new_dir.exists():
            try:
                new_dir.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(old_dir), str(new_dir))
            except Exception:
                pass
        ensure_device_dir({"vendor": vendor, "slug": new_slug})
        return redirect(url_for("device_detail", device_id=device_id))
    return _render_devices_edit_form(device, vendors, scripts, folder_options, device_users, assigned_user)


@app.route("/folder/<int:folder_id>")
@login_required
def folder_detail(folder_id):
    user = current_user()
    conn = connect()
    try:
        folder_row = conn.execute("SELECT * FROM folders WHERE id = ?", (folder_id,)).fetchone()
        if not folder_row:
            abort(404)
        folders = conn.execute("SELECT * FROM folders ORDER BY sort_order, name").fetchall()
        by_parent, by_id = _build_folder_tree(folders)
        folder_path = _folder_path(by_id, folder_id)
        subfolders = by_parent.get(folder_id, [])
        subfolder_tree = _folder_tree_nodes(by_parent, folder_id)
        folder_options = _folder_options(folders)
        device_rows = conn.execute(
            "SELECT folder_id, COUNT(1) AS c, MAX(b.created_at) AS last_backup "
            "FROM devices d LEFT JOIN backups b ON b.device_id = d.id GROUP BY folder_id"
        ).fetchall()
        direct_counts = {r["folder_id"]: r["c"] for r in device_rows}
        direct_last = {r["folder_id"]: r["last_backup"] for r in device_rows}
        vendors = conn.execute("SELECT * FROM vendors ORDER BY name").fetchall()
        if user["role"] == "admin":
            devices = conn.execute(
                """
                SELECT d.*, v.name AS vendor_label, s.name AS script_label
                FROM devices d
                LEFT JOIN vendors v ON v.key = d.vendor
                LEFT JOIN scripts s ON s.id = d.script_id
                WHERE d.folder_id = ?
                ORDER BY d.name
                """,
                (folder_id,),
            ).fetchall()
        else:
            devices = conn.execute(
                """
                SELECT d.*, v.name AS vendor_label, s.name AS script_label
                FROM devices d
                LEFT JOIN vendors v ON v.key = d.vendor
                LEFT JOIN scripts s ON s.id = d.script_id
                WHERE d.folder_id = ? AND (d.user_id = ? OR d.id = ?)
                """,
                (folder_id, user["id"], user["device_id"]),
            ).fetchall()
        last = conn.execute(
            """
            SELECT MAX(b.created_at) AS last_backup
            FROM devices d
            LEFT JOIN backups b ON b.device_id = d.id
            WHERE d.folder_id = ?
            """,
            (folder_id,),
        ).fetchone()
        last_backup = last["last_backup"] if last else None
        global_interval = _global_interval_minutes(conn)
        device_ids = [d["id"] for d in devices]
        status_counts = {"ok": 0, "error": 0, "warn": 0}
        latest_status = {}
        if device_ids:
            placeholders = ",".join(["?"] * len(device_ids))
            rows = conn.execute(
                f"""
                SELECT b.status, COUNT(1) AS c
                FROM backups b
                JOIN (
                    SELECT device_id, MAX(id) AS max_id
                    FROM backups
                    WHERE device_id IN ({placeholders})
                    GROUP BY device_id
                ) lb ON lb.max_id = b.id
                GROUP BY b.status
                """,
                device_ids,
            ).fetchall()
            for r in rows:
                status = (r["status"] or "").lower()
                if status == "ok":
                    status_counts["ok"] += r["c"]
                elif status == "error":
                    status_counts["error"] += r["c"]
                else:
                    status_counts["warn"] += r["c"]
            rows = conn.execute(
                f"""
                SELECT b.device_id, b.status
                FROM backups b
                JOIN (
                    SELECT device_id, MAX(id) AS max_id
                    FROM backups
                    WHERE device_id IN ({placeholders})
                    GROUP BY device_id
                ) lb ON lb.max_id = b.id
                """,
                device_ids,
            ).fetchall()
            for r in rows:
                latest_status[r["device_id"]] = (r["status"] or "ok").lower()
    finally:
        conn.close()

    def _folder_total_count(fid):
        total = direct_counts.get(fid, 0)
        for child in by_parent.get(fid, []):
            total += _folder_total_count(child["id"])
        return total

    def _folder_last_backup(fid):
        latest = direct_last.get(fid)
        for child in by_parent.get(fid, []):
            child_latest = _folder_last_backup(child["id"])
            if not latest:
                latest = child_latest
            elif child_latest and child_latest > latest:
                latest = child_latest
        return latest

    return render_template(
        "folder_detail.html",
        user=user,
        folder_id=folder_id,
        folder_label=folder_row["name"],
        folder_path=folder_path,
        subfolders=subfolders,
        subfolder_tree=subfolder_tree,
        devices=devices,
        latest_status=latest_status,
        status_counts=status_counts,
        vendors=vendors,
        folders=folders,
        folder_options=folder_options,
        last_backup=last_backup,
        global_interval=global_interval,
        folder_counts={f["id"]: _folder_total_count(f["id"]) for f in folders},
        folder_summaries={f["id"]: _folder_last_backup(f["id"]) for f in folders},
        current_folder_id=folder_id,
        active_path=[p["id"] for p in folder_path],
        humanize=_humanize_since,
    )




@app.route("/folder/<int:folder_id>/delete", methods=["POST"])
@admin_required
def folder_delete(folder_id):
    conn = connect()
    try:
        row = conn.execute("SELECT * FROM folders WHERE id = ?", (folder_id,)).fetchone()
        if not row:
            abort(404)
        child_count = conn.execute(
            "SELECT COUNT(1) AS c FROM folders WHERE parent_id = ?",
            (folder_id,),
        ).fetchone()["c"]
        count = conn.execute("SELECT COUNT(1) AS c FROM devices WHERE folder_id = ?", (folder_id,)).fetchone()["c"]
        if count > 0 or child_count > 0:
            flash("Não é possível excluir esta pasta porque ainda existem subpastas ou equipamentos vinculados a ela.", "error")
            return redirect(url_for("folder_detail", folder_id=folder_id))
        conn.execute("DELETE FROM folders WHERE id = ?", (folder_id,))
        conn.commit()
    finally:
        conn.close()
    flash("Pasta excluída com sucesso.", "success")
    return redirect(url_for("index"))


@app.route("/folders/<int:folder_id>/move", methods=["POST"])
@admin_required
def folder_move(folder_id):
    target_parent_raw = request.form.get("target_parent", "").strip()
    try:
        target_parent = int(target_parent_raw) if target_parent_raw else None
    except ValueError:
        flash("Pasta de destino inválida.", "error")
        return redirect(url_for("folder_detail", folder_id=folder_id))

    conn = connect()
    try:
        folder = conn.execute("SELECT * FROM folders WHERE id = ?", (folder_id,)).fetchone()
        if not folder:
            abort(404)
        folders = conn.execute("SELECT * FROM folders ORDER BY sort_order, name").fetchall()
        by_parent, by_id = _build_folder_tree(folders)
        descendants = _folder_descendants(by_parent, folder_id)
        if target_parent == folder_id or (target_parent in descendants):
            flash("Não é possível mover uma pasta para ela mesma ou para uma subpasta.", "error")
            return redirect(url_for("folder_detail", folder_id=folder_id))
        if target_parent is not None:
            if target_parent not in by_id:
                flash("Pasta de destino inválida.", "error")
                return redirect(url_for("folder_detail", folder_id=folder_id))
            if _max_depth_for_parent(by_id, target_parent) > 2:
                flash("Profundidade máxima atingida (pasta > subpasta > device).", "error")
                return redirect(url_for("folder_detail", folder_id=folder_id))
        existing_same_parent = _find_same_parent_folder(conn, folder["name"], target_parent, exclude_folder_id=folder_id)
        if existing_same_parent:
            flash("Já existe uma pasta com esse nome no destino.", "error")
            return redirect(url_for("folder_detail", folder_id=folder_id))
        conn.execute("UPDATE folders SET parent_id = ? WHERE id = ?", (target_parent, folder_id))
        conn.commit()
    except sqlite3.IntegrityError:
        flash("Já existe uma pasta com esse nome no destino.", "error")
        return redirect(url_for("folder_detail", folder_id=folder_id))
    finally:
        conn.close()

    flash("Subpasta movida com sucesso.", "success")
    return redirect(url_for("folder_detail", folder_id=folder_id))




@app.route("/devices/<int:device_id>/move", methods=["POST"])
@admin_required
def device_move(device_id):
    target_folder_raw = request.form.get("target_folder", "").strip()
    conn = connect()
    try:
        device = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        if not device:
            abort(404)
        redirect_target = url_for("index")
        if device["folder_id"]:
            redirect_target = url_for("folder_detail", folder_id=device["folder_id"])
        if not target_folder_raw:
            flash("Selecione a pasta de destino.", "error")
            return redirect(redirect_target)
        try:
            target_folder = int(target_folder_raw)
        except ValueError:
            flash("Pasta de destino inválida.", "error")
            return redirect(redirect_target)
        folder_row = conn.execute("SELECT * FROM folders WHERE id = ?", (target_folder,)).fetchone()
        if not folder_row:
            flash("Pasta de destino inválida.", "error")
            return redirect(redirect_target)

        if device["folder_id"] == target_folder:
            flash("O equipamento já está nessa pasta.", "error")
            return redirect(redirect_target)
        existing_same_folder = _find_same_folder_device(conn, device["name"], target_folder, exclude_device_id=device_id)
        if existing_same_folder:
            flash(f"Já existe um equipamento com esse nome na pasta de destino: {existing_same_folder['name']}.", "error")
            return redirect(redirect_target)

        conn.execute("UPDATE devices SET folder_id = ? WHERE id = ?", (target_folder, device_id))

        conn.commit()
    finally:
        conn.close()

    flash("Equipamento movido com sucesso.", "success")
    return redirect(url_for("folder_detail", folder_id=target_folder))


@app.route("/users/new", methods=["GET", "POST"])
@admin_required
def users_new():
    conn = connect()
    raw_users = conn.execute("SELECT * FROM users ORDER BY role, username").fetchall()
    conn.close()
    users = []
    for item in raw_users:
        row = dict(item)
        row["plain_password"] = None
        if row["role"] == "device" and row.get("device_password_enc"):
            try:
                row["plain_password"] = decrypt_secret(row["device_password_enc"])
            except Exception:
                row["plain_password"] = None
        users.append(row)

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        login_username = request.form.get("login_username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "device")

        if not username or not password:
            flash("Preencha todos os campos obrigatórios.", "error")
            return render_template("users_new.html", user=current_user(), users=users, format_datetime=_format_datetime_display)
        if role == "device" and not login_username:
            flash("Informe o login real do equipamento.", "error")
            return render_template("users_new.html", user=current_user(), users=users, format_datetime=_format_datetime_display)

        conn = connect()
        try:
            existing = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if existing:
                if existing["role"] == "device" and role == "device":
                    conn.execute(
                        """
                        UPDATE users
                        SET login_username = ?, password_hash = ?, device_password_enc = ?
                        WHERE id = ?
                        """,
                        (
                            login_username,
                            hash_password(password),
                            encrypt_secret(password),
                            existing["id"],
                        ),
                    )
                    conn.commit()
                    flash("Senha do usuário de equipamento atualizada.", "success")
                    return redirect(url_for("users_new"))
                flash("Já existe um usuário com esse identificador.", "error")
                return render_template("users_new.html", user=current_user(), users=users, format_datetime=_format_datetime_display)
            conn.execute(
                "INSERT INTO users (username, login_username, password_hash, device_password_enc, role, device_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    username,
                    login_username or username,
                    hash_password(password),
                    encrypt_secret(password) if role == "device" else None,
                    role,
                    None,
                    now_iso(),
                ),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            flash("Já existe um usuário com esse identificador.", "error")
            return render_template("users_new.html", user=current_user(), users=users, format_datetime=_format_datetime_display)
        finally:
            conn.close()
        return redirect(url_for("index"))

    return render_template("users_new.html", user=current_user(), users=users, format_datetime=_format_datetime_display)


@app.route("/settings/storage", methods=["POST"])
@admin_required
def settings_storage():
    value = request.form.get("storage_total_gb", "")
    try:
        storage_gb = _parse_storage_gb(value)
    except Exception:
        flash("Informe uma capacidade válida. Ex.: 10 ou 10GB.", "error")
        return redirect(url_for("index"))

    conn = connect()
    try:
        _set_setting(conn, "storage_total_gb", storage_gb)
        conn.commit()
    finally:
        conn.close()
    flash("Capacidade de armazenamento atualizada.", "success")
    return redirect(url_for("index"))


@app.route("/users/<int:user_id>/password", methods=["POST"])
@admin_required
def users_password(user_id):
    password = request.form.get("password", "")
    if not password:
        flash("Informe a nova senha.", "error")
        return redirect(url_for("users_new"))

    conn = connect()
    try:
        existing = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not existing:
            abort(404)
        conn.execute(
            """
            UPDATE users
            SET password_hash = ?, device_password_enc = ?
            WHERE id = ?
            """,
            (
                hash_password(password),
                encrypt_secret(password) if existing["role"] == "device" else existing["device_password_enc"],
                user_id,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    flash("Senha atualizada com sucesso.", "success")
    return redirect(url_for("users_new"))


@app.route("/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def users_delete(user_id):
    current = current_user()
    if current and current["id"] == user_id:
        flash("Não é possível excluir o usuário atualmente logado.", "error")
        return redirect(url_for("users_new"))
    conn = connect()
    try:
        existing = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not existing:
            abort(404)
        conn.execute("UPDATE devices SET user_id = NULL WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
    finally:
        conn.close()
    flash("Usuário excluído com sucesso.", "success")
    return redirect(url_for("users_new"))


@app.route("/devices/<int:device_id>/delete", methods=["POST"])
@admin_required
def device_delete(device_id):
    conn = connect()
    try:
        device = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        if not device:
            abort(404)
        redirect_target = url_for("index")
        if device["folder_id"]:
            redirect_target = url_for("folder_detail", folder_id=device["folder_id"])
        # remove backups records
        conn.execute("DELETE FROM backups WHERE device_id = ?", (device_id,))
        # delete device
        conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))
        conn.commit()
    finally:
        conn.close()

    # remove files on disk
    base = Path(BACKUP_ROOT)
    device_dir = base / device["vendor"] / device["slug"]
    if device_dir.exists():
        import shutil
        shutil.rmtree(device_dir, ignore_errors=True)

    flash("Equipamento excluído com sucesso.", "success")
    return redirect(redirect_target)


@app.route("/devices/<int:device_id>/collect_async", methods=["POST"])
@login_required
def device_collect_async(device_id):
    user = current_user()
    device = get_device_or_404(device_id)
    if not check_device_access(user, device):
        abort(403)

    conn = connect()
    try:
        current_row = conn.execute(
            "SELECT id, running, run_started_at, script_id, last_debug, last_debug_at FROM devices WHERE id = ?",
            (device_id,),
        ).fetchone()
        if current_row:
            _reset_stale_running_for_device(conn, current_row)
        cur = conn.execute(
            "UPDATE devices SET running = 1, run_started_at = ? WHERE id = ? AND (running IS NULL OR running = 0)",
            (now_iso(), device_id),
        )
        conn.commit()
        if cur.rowcount == 0:
            return {"status": "already_running"}
    finally:
        conn.close()

    t = threading.Thread(target=_run_backup_task, args=(device_id,), daemon=True)
    t.start()
    return {"status": "started"}


@app.route("/devices/<int:device_id>/status")
@login_required
def device_status(device_id):
    user = current_user()
    device = get_device_or_404(device_id)
    if not check_device_access(user, device):
        abort(403)
    conn = connect()
    try:
        row = conn.execute(
            "SELECT id, running, run_started_at, script_id, last_debug, last_debug_at FROM devices WHERE id = ?",
            (device_id,),
        ).fetchone()
        stale_reset = _reset_stale_running_for_device(conn, row)
        if stale_reset:
            row = conn.execute(
                "SELECT id, running, run_started_at, script_id, last_debug, last_debug_at FROM devices WHERE id = ?",
                (device_id,),
            ).fetchone()
        script = None
        if row and row["script_id"]:
            script = conn.execute("SELECT name, timeout_seconds FROM scripts WHERE id = ?", (row["script_id"],)).fetchone()
    finally:
        conn.close()
    latest_rows = []
    latest_backup = None
    previous_backup = None
    latest_compare_url = None
    latest_change_label = None
    if row and not row["running"]:
        conn = connect()
        try:
            latest_rows = _recent_backup_rows(conn, device_id, limit=12)
        finally:
            conn.close()
        latest_backup = latest_rows[0] if latest_rows else None
        current_compare_backup, previous_backup = _select_compare_pair(latest_rows)
        latest_change_label = _display_change_label(
            latest_backup,
            current_compare_backup,
            previous_backup,
            device["vendor"],
        ) if latest_backup else None
        latest_compare_url = _latest_compare_url(current_compare_backup, previous_backup)
    return {
        "running": row["running"] if row else 0,
        "run_started_at": row["run_started_at"] if row else None,
        "last_debug": row["last_debug"] if row else None,
        "last_debug_at": row["last_debug_at"] if row else None,
        "script_name": script["name"] if script else None,
        "timeout_seconds": script["timeout_seconds"] if script else None,
        "stale_reset": stale_reset,
        "latest_backup_status": latest_backup["status"] if latest_backup else None,
        "latest_backup_created_at": latest_backup["created_at"] if latest_backup else None,
        "latest_change_label": latest_change_label,
        "latest_compare_url": latest_compare_url,
    }


@app.route("/devices/<int:device_id>")
@login_required
def device_detail(device_id):
    user = current_user()
    device = get_device_or_404(device_id)
    if not check_device_access(user, device):
        abort(403)

    conn = connect()
    try:
        current_row = conn.execute(
            "SELECT id, running, run_started_at, script_id, last_debug, last_debug_at FROM devices WHERE id = ?",
            (device_id,),
        ).fetchone()
        if current_row:
            _reset_stale_running_for_device(conn, current_row)
            device = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        script = None
        folder = None
        folder_path = []
        if device["script_id"]:
            script = conn.execute("SELECT * FROM scripts WHERE id = ?", (device["script_id"],)).fetchone()
        if not script:
            script = conn.execute("SELECT * FROM scripts WHERE vendor = ? ORDER BY id LIMIT 1", (device["vendor"],)).fetchone()
        if device["folder_id"]:
            folder = conn.execute("SELECT * FROM folders WHERE id = ?", (device["folder_id"],)).fetchone()
            all_folders = conn.execute("SELECT * FROM folders ORDER BY name").fetchall()
            _, by_id = _build_folder_tree(all_folders)
            folder_path = _folder_path(by_id, device["folder_id"])
        global_interval = _global_interval_minutes(conn)
        last_row = conn.execute("SELECT debug_log FROM backups WHERE device_id = ? ORDER BY id DESC LIMIT 1", (device_id,)).fetchone()
        latest_log = last_row["debug_log"] if last_row else None
        live_log = device["last_debug"]
        backup_rows = _recent_backup_rows(conn, device_id, limit=3)
    finally:
        conn.close()

    backups = list_backups(device)
    latest_backup = backup_rows[0] if backup_rows else None
    current_compare_backup, previous_backup = _select_compare_pair(backup_rows)
    latest_change_label = _display_change_label(
        latest_backup,
        current_compare_backup,
        previous_backup,
        device["vendor"],
    )
    latest_compare_url = _latest_compare_url(current_compare_backup, previous_backup)
    latest_has_compare = bool(latest_compare_url)
    return render_template(
        "device_detail.html",
        user=user,
        device=device,
        folder=folder,
        folder_path=folder_path,
        backups=backups,
        backup_rows=backup_rows,
        latest_backup=latest_backup,
        backup_root=BACKUP_ROOT,
        humanize=_humanize_since,
        script=script,
        global_interval=global_interval,
        latest_log=latest_log,
        live_log=live_log,
        previous_backup=previous_backup,
        latest_change_label=latest_change_label,
        latest_has_compare=latest_has_compare,
        latest_compare_url=latest_compare_url,
    )


@app.route("/devices/<int:device_id>/collect", methods=["POST"])
@login_required
def device_collect(device_id):
    user = current_user()
    device = get_device_or_404(device_id)
    if not check_device_access(user, device):
        abort(403)

    conn = connect()
    try:
        try:
            conn.execute(
                "UPDATE devices SET running = 1, run_started_at = ? WHERE id = ?",
                (now_iso(), device_id),
            )
            conn.commit()
            dev_password = decrypt_secret(device["dev_password_enc"])
            script_override, _ = _get_script_override(device["script_id"])
            override = script_override or _get_vendor_script_override(device["vendor"].lower())
            log_lines = []
            def log_cb(msg):
                log_lines.append(msg)
            content, meta = run_backup(device, device["dev_username"], dev_password, device["command_override"], override, log_cb=log_cb)
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
                    path or "",
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
            interval = _global_interval_minutes(conn)
            conn.execute(
                "UPDATE devices SET last_run_at = ?, next_run_at = ? WHERE id = ?",
                (now_iso(), _next_run_iso(interval), device_id),
            )
            conn.commit()
            if status == "ok":
                flash("Backup concluído com sucesso.", "success")
            elif status == "same":
                flash("Nenhuma alteração detectada. O backup não precisou ser salvo novamente.", "success")
            elif status == "invalid":
                flash(f"Backup inválido: {message}", "error")
            else:
                flash(f"Backup concluído, mas o conteúdo ficou muito curto: {message}", "error")
        except Exception as exc:
            conn.execute(
                "INSERT INTO backups (device_id, path, created_at, size_bytes, status, message, debug_log, duration_seconds, line_count, content_hash, firmware, diff_summary) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (device_id, "", now_iso(), 0, "error", str(exc), "\n".join(log_lines), None, None, None, None, None),
            )
            interval = _global_interval_minutes(conn)
            conn.execute(
                "UPDATE devices SET last_run_at = ?, next_run_at = ? WHERE id = ?",
                (now_iso(), _next_run_iso(interval), device_id),
            )
            conn.commit()
            flash(f"Falha ao executar o backup: {exc}", "error")
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

    return redirect(url_for("device_detail", device_id=device_id))


@app.route("/download")
@login_required
def download_backup():
    user = current_user()
    path = request.args.get("path")
    if not path:
        abort(400)
    file_path = Path(path)
    if not file_path.exists():
        abort(404)
    allowed_root = Path(BACKUP_ROOT)
    if not _is_under_root(file_path, allowed_root):
        abort(403)

    # Access control: device users can only download files inside their device folder
    conn = connect()
    try:
        if user["role"] == "device":
            devices = conn.execute(
                "SELECT * FROM devices WHERE user_id = ? OR id = ?",
                (user["id"], user["device_id"]),
            ).fetchall()
            if not devices:
                abort(403)
            allowed = any(
                _is_under_root(file_path, Path(BACKUP_ROOT) / d["vendor"].lower() / d["slug"])
                for d in devices
            )
            if not allowed:
                abort(403)
    finally:
        conn.close()

    return send_file(file_path, as_attachment=True)


@app.route("/view")
@login_required
def view_backup():
    user = current_user()
    path = request.args.get("path")
    if not path:
        abort(400)
    file_path = Path(path)
    if not file_path.exists():
        abort(404)

    allowed_root = Path(BACKUP_ROOT)
    if not _is_under_root(file_path, allowed_root):
        abort(403)

    conn = connect()
    device = None
    try:
        device = _resolve_device_for_backup_access(conn, user, file_path)
    finally:
        conn.close()

    max_bytes = 2 * 1024 * 1024
    content = _load_backup_content(file_path, device["vendor"] if device else "")
    if len(content) > max_bytes:
        content = content[:max_bytes] + "\n\n[conteudo truncado]"
    backup_name = file_path.name
    return render_template(
        "view_backup.html",
        user=user,
        device=device,
        backup_path=str(file_path),
        backup_name=backup_name,
        content=content,
    )


@app.route("/compare")
@login_required
def compare_backup():
    user = current_user()
    current_path = request.args.get("current")
    previous_path = request.args.get("previous")
    if not current_path or not previous_path:
        abort(400)

    current_file = Path(current_path)
    previous_file = Path(previous_path)
    if not current_file.exists() or not previous_file.exists():
        abort(404)

    allowed_root = Path(BACKUP_ROOT)
    if not _is_under_root(current_file, allowed_root) or not _is_under_root(previous_file, allowed_root):
        abort(403)

    conn = connect()
    try:
        device = _resolve_device_for_backup_access(conn, user, current_file)
        if not device or not _is_under_root(previous_file, Path(BACKUP_ROOT) / device["vendor"].lower() / device["slug"]):
            abort(403)
    finally:
        conn.close()

    current_content = _load_backup_content(current_file, device["vendor"])
    previous_content = _load_backup_content(previous_file, device["vendor"])
    added, removed = _parse_diff_summary(_diff_summary(previous_content, current_content))
    diff_snippets = _build_diff_snippets(previous_content, current_content)

    return render_template(
        "compare_backup.html",
        user=user,
        device=device,
        current_path=str(current_file),
        previous_path=str(previous_file),
        current_name=current_file.name,
        previous_name=previous_file.name,
        added_lines=added,
        removed_lines=removed,
        diff_snippets=diff_snippets,
    )


@app.route("/scripts", methods=["GET", "POST"])
@admin_required
def scripts():
    conn = connect()
    try:
        scripts = conn.execute("SELECT * FROM scripts WHERE vendor != 'cisco' ORDER BY vendor, name").fetchall()
    finally:
        conn.close()

    if request.method == "POST":
        conn = connect()
        try:
            for s in scripts:
                sid = s["id"]
                name = request.form.get(f"name_{sid}", "").strip()
                vendor = request.form.get(f"vendor_{sid}", "").strip().lower()
                pre_text = request.form.get(f"pre_{sid}", "")
                cmd = request.form.get(f"cmd_{sid}", "")
                prompt = request.form.get(f"prompt_{sid}", "")
                read_mode = request.form.get(f"read_mode_{sid}", "shell")
                sleep_val = request.form.get(f"sleep_{sid}", "0")
                timeout_val = request.form.get(f"timeout_{sid}", "180")
                if not name or not vendor:
                    continue
                try:
                    sleep = int(sleep_val) if sleep_val else 0
                    timeout_seconds = int(timeout_val) if timeout_val else 180
                except ValueError:
                    flash(f"Valores inválidos no perfil {s['name']}.", "error")
                    return redirect(url_for("scripts"))
                existing = conn.execute(
                    "SELECT id FROM scripts WHERE name = ? AND id != ?",
                    (name, sid),
                ).fetchone()
                if existing:
                    flash(f"Já existe outro perfil com o nome {name}.", "error")
                    return redirect(url_for("scripts"))
                conn.execute(
                    """
                    UPDATE scripts
                    SET name = ?, vendor = ?, pre_text = ?, cmd = ?, prompt = ?, read_mode = ?, sleep = ?, timeout_seconds = ?
                    WHERE id = ?
                    """,
                    (name, vendor, pre_text, cmd, prompt, read_mode, sleep, timeout_seconds, sid),
                )
            conn.commit()
        except sqlite3.IntegrityError:
            flash("Conflito ao salvar perfis de coleta. Revise nomes duplicados.", "error")
            return redirect(url_for("scripts"))
        finally:
            conn.close()
        flash("Perfis de coleta atualizados com sucesso.", "success")
        return redirect(url_for("scripts"))

    return render_template("scripts.html", user=current_user(), scripts=scripts)


@app.route("/health")
def health():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}


if __name__ == "__main__":
    init_db()
    app.run(host=FLASK_HOST, port=FLASK_PORT)
