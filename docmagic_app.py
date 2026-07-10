import os
import sqlite3
import json
import csv
import html
import re
import base64
import urllib.request
import subprocess
import tempfile
import shutil
import secrets
import hashlib
import hmac
import unicodedata
from fastapi import FastAPI, Form, File, UploadFile, Response, Request, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from PIL import Image, ImageDraw, ImageFont
import io
import traceback
import ssl
from datetime import datetime, timedelta
from typing import List, Optional
from contextvars import ContextVar
from pathlib import Path

try:
    import uvicorn
except Exception:
    uvicorn = None

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.utils import ImageReader
    from reportlab.lib.units import mm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import HRFlowable, Image as RLImage, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False

app = FastAPI()
security = HTTPBasic(auto_error=False)
BASE_DIR = Path(__file__).resolve().parent
FONT_DIR = BASE_DIR / "assets" / "fonts"
CACHE_FONT_DIR = Path(os.environ.get("DOCMAGIC_FONT_CACHE", "/tmp/docmagic-fonts"))
APP_NAME = "DK Admin V10"
APP_TAGLINE = "軍團報價、發票、收據與薪酬管理系統"


@app.middleware("http")
async def _db_server_mode_middleware(request: Request, call_next):
    token = None
    if request.url.path.startswith("/api/db/"):
        token = DB_SERVER_MODE.set(True)
    try:
        return await call_next(request)
    finally:
        if token is not None:
            DB_SERVER_MODE.reset(token)


@app.on_event("startup")
async def _enable_db_proxy_runtime():
    global DB_RUNTIME_PROXY_ENABLED
    DB_RUNTIME_PROXY_ENABLED = True

# ---------------------------------------------------------
# 安全認證設定
# ---------------------------------------------------------
ADMIN_USER = "admin"
ADMIN_PASS = "Dk122112"
PASSWORD_PREFIX = "pbkdf2_sha256"
PASSWORD_ITERATIONS = 210000
SESSION_TTL_HOURS = 12
LOCK_DURATION_MINUTES = 15
LOCK_THRESHOLD = 5
ROLE_ALIASES = {
    "admin": "admin",
    "manager": "manager",
    "finance": "finance",
    "tutor": "tutor",
    # Legacy roles kept for backward compatibility.
    "staff": "manager",
    "viewer": "tutor",
}


def _now():
    return datetime.now().replace(microsecond=0)


def _fmt_dt(value: datetime):
    return value.strftime("%Y-%m-%d %H:%M:%S")


def _parse_dt(value):
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.strptime(str(value), "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def _normalize_role(role: str):
    value = str(role or "").strip().lower()
    return ROLE_ALIASES.get(value, value or "tutor")


def _role_allowed(role: str, allowed_roles):
    normalized = _normalize_role(role)
    allowed = {_normalize_role(item) for item in allowed_roles}
    return normalized == "admin" or normalized in allowed


def _hash_password(password: str, salt: Optional[str] = None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PASSWORD_ITERATIONS,
    ).hex()
    return f"{PASSWORD_PREFIX}${PASSWORD_ITERATIONS}${salt}${digest}"


def _verify_password(password: str, stored: str):
    if not stored:
        return False, None
    if stored.startswith(f"{PASSWORD_PREFIX}$"):
        try:
            _, iterations, salt, digest = stored.split("$", 3)
            candidate = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                salt.encode("utf-8"),
                int(iterations),
            ).hex()
            return hmac.compare_digest(candidate, digest), None
        except Exception:
            return False, None
    return hmac.compare_digest(password, stored), _hash_password(password)


def _basic_auth_user(request: Request):
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("basic "):
        return None
    try:
        token = header.split(" ", 1)[1].strip()
        raw = base64.b64decode(token).decode("utf-8")
        username, password = raw.split(":", 1)
    except Exception:
        return None

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, password, display_name, role, is_active, failed_attempts, locked_until FROM app_users WHERE username=?",
        (username.strip(),),
    )
    row = cursor.fetchone()
    conn.close()
    if not row or row[5] != 1:
        return None
    ok, _ = _verify_password(password, row[2])
    if not ok:
        return None
    return row

def _ensure_user_table():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS app_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            display_name TEXT,
            role TEXT DEFAULT 'staff',
            is_active INTEGER DEFAULT 1,
            failed_attempts INTEGER DEFAULT 0,
            locked_until TEXT,
            password_updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("PRAGMA table_info(app_users)")
    cols = {row[1] for row in cursor.fetchall()}
    for col_name, col_def in [
        ("failed_attempts", "INTEGER DEFAULT 0"),
        ("locked_until", "TEXT"),
        # SQLite cannot add a column with a non-constant default, so keep this nullable.
        ("password_updated_at", "TEXT"),
    ]:
        if col_name not in cols:
            cursor.execute(f"ALTER TABLE app_users ADD COLUMN {col_name} {col_def}")
    conn.commit()
    conn.close()


def _ensure_session_table():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS app_sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            display_name TEXT,
            expires_at TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("PRAGMA table_info(app_sessions)")
    cols = {row[1] for row in cursor.fetchall()}
    if "expires_at" not in cols:
        cursor.execute("ALTER TABLE app_sessions ADD COLUMN expires_at TEXT")
    conn.commit()
    conn.close()


def _ensure_common_clients_table():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS common_clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            client_name TEXT NOT NULL,
            project_name TEXT,
            doc_type TEXT DEFAULT '報價單',
            category TEXT DEFAULT '',
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("PRAGMA table_info(common_clients)")
    cols = {row[1] for row in cursor.fetchall()}
    if "category" not in cols:
        cursor.execute("ALTER TABLE common_clients ADD COLUMN category TEXT DEFAULT ''")
    cursor.execute("""
        UPDATE common_clients
        SET category = COALESCE(NULLIF(category, ''), notes, '')
        WHERE category IS NULL OR category = ''
    """)
    conn.commit()
    conn.close()


def _seed_common_clients():
    # Keep the requested NGO entry available even if the database is rebuilt.
    seed_rows = [
        (
            "香港基督教女⻘年會將軍澳綜合社會服務處",
            "香港基督教女⻘年會將軍澳綜合社會服務處",
            "",
            "報價單",
            "NGO",
            "NGO",
        ),
    ]
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    for name, client_name, project_name, doc_type, category, notes in seed_rows:
        cursor.execute("SELECT id FROM common_clients WHERE name=?", (name,))
        row = cursor.fetchone()
        if row:
            cursor.execute(
                "UPDATE common_clients SET client_name=?, project_name=?, doc_type=?, category=?, notes=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (client_name, project_name, doc_type, category, notes, row[0]),
            )
        else:
            cursor.execute(
                "INSERT INTO common_clients (name, client_name, project_name, doc_type, category, notes) VALUES (?, ?, ?, ?, ?, ?)",
                (name, client_name, project_name, doc_type, category, notes),
            )
    conn.commit()
    conn.close()


def _normalize_common_client_name(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value or ""))
    text = text.replace("⻘", "青")
    text = re.sub(r"\s+", "", text)
    return text.strip().lower()


def _unique_common_client_rows(rows):
    grouped = {}
    for row in rows or []:
        key = _normalize_common_client_name(row[1] if len(row) > 1 else "")
        if not key:
            continue
        current = grouped.get(key)
        if current is None:
            grouped[key] = row
            continue
        current_score = (
            1 if (current[5] if len(current) > 5 else "") else 0,
            1 if (current[6] if len(current) > 6 else "") else 0,
            current[7] if len(current) > 7 else "",
            current[0] if len(current) > 0 else 0,
        )
        row_score = (
            1 if (row[5] if len(row) > 5 else "") else 0,
            1 if (row[6] if len(row) > 6 else "") else 0,
            row[7] if len(row) > 7 else "",
            row[0] if len(row) > 0 else 0,
        )
        if row_score > current_score:
            grouped[key] = row
    ordered = sorted(
        grouped.values(),
        key=lambda r: (
            _common_client_category_order(r[5] if len(r) > 5 else ""),
            _normalize_common_client_name(r[1] if len(r) > 1 else r[2] if len(r) > 2 else ""),
        ),
    )
    return ordered


def _dedupe_common_clients():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, client_name, project_name, doc_type, category, notes, updated_at FROM common_clients ORDER BY COALESCE(updated_at, ''), id")
    rows = cursor.fetchall()
    grouped = {}
    for row in rows:
        key = _normalize_common_client_name(row[1] or row[2])
        if not key:
            continue
        grouped.setdefault(key, []).append(row)

    changed = False
    for group_rows in grouped.values():
        if len(group_rows) < 2:
            continue
        master = group_rows[-1]
        master_id = master[0]
        master_name = master[1] or master[2]
        master_client_name = master[2] or master[1]
        master_project_name = master[3] or ""
        master_doc_type = master[4] or "報價單"
        master_category = master[5] or ""
        master_notes = master[6] or ""

        for row in group_rows[:-1]:
            if not master_project_name and row[3]:
                master_project_name = row[3]
            if not master_doc_type and row[4]:
                master_doc_type = row[4]
            if not master_category and row[5]:
                master_category = row[5]
            if not master_notes and row[6]:
                master_notes = row[6]

        cursor.execute(
            """
            UPDATE common_clients
            SET name=?, client_name=?, project_name=?, doc_type=?, category=?, notes=?, updated_at=CURRENT_TIMESTAMP
            WHERE id=?
            """,
            (master_name, master_client_name, master_project_name, master_doc_type, master_category, master_notes, master_id),
        )
        delete_ids = [row[0] for row in group_rows if row[0] != master_id]
        if delete_ids:
            cursor.executemany("DELETE FROM common_clients WHERE id=?", [(row_id,) for row_id in delete_ids])
            changed = True

    if changed:
        conn.commit()
    conn.close()


def _common_client_category_order(category: str):
    order = {
        "小學": 0,
        "中學": 1,
        "特殊學校/群育學校": 2,
        "幼稚園": 3,
        "NGO": 4,
        "": 5,
    }
    return order.get((category or "").strip(), 99)


def _common_client_label(row):
    name = row[1] or ""
    client_name = row[2] or ""
    if client_name and client_name != name:
        return f"{name}｜{client_name}"
    return name


def _common_client_option_label(row):
    category = _common_client_category(row)
    label = _common_client_label(row)
    return f"【{category}】{label}" if category else label


def _common_client_category(row):
    category = ""
    if len(row) > 5:
        category = (row[5] or "").strip()
    if category:
        return category
    project_name = (row[3] if len(row) > 3 else "") or ""
    notes = (row[6] if len(row) > 6 else "") or ""
    for candidate in (project_name, notes):
        candidate = str(candidate).strip()
        if candidate in {"小學", "中學", "特殊學校/群育學校", "幼稚園", "NGO"}:
            return candidate
    return ""


def _render_common_client_option_groups(rows):
    normalized = _unique_common_client_rows(rows)
    pieces = ['<option value="">— 選擇常用客戶 —</option>']
    grouped = {}
    uncategorized = []
    for row in normalized:
        category = _common_client_category(row)
        if not category:
            uncategorized.append(row)
            continue
        grouped.setdefault(category, []).append(row)
    category_order = ["小學", "中學", "特殊學校/群育學校", "幼稚園", "NGO"]
    ordered_categories = [cat for cat in category_order if cat in grouped]
    ordered_categories.extend([cat for cat in grouped.keys() if cat not in ordered_categories])
    for category in ordered_categories:
        group_rows = grouped[category]
        pieces.append(f'<option value="" disabled>──── {html.escape(category)} ────</option>')
        pieces.append(f'<optgroup label="------{html.escape(category)}------">')
        for row in group_rows:
            value = row[0]
            label = _common_client_option_label(row)
            pieces.append(f'<option value="{html.escape(str(value))}">{html.escape(label)}</option>')
        pieces.append('</optgroup>')
    if uncategorized:
        pieces.append('<option value="" disabled>──── 未分類 / 其他 ────</option>')
    for row in uncategorized:
        value = row[0]
        label = _common_client_option_label(row)
        pieces.append(f'<option value="{html.escape(str(value))}">{html.escape(label)}</option>')
    return "".join(pieces)


def _delete_common_client_by_key(client_key):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    key = str(client_key).strip()
    deleted = 0
    if key.isdigit():
        cursor.execute("DELETE FROM common_clients WHERE id=?", (int(key),))
        deleted = cursor.rowcount or 0
    if not deleted and key:
        canonical = _normalize_common_client_name(key)
        cursor.execute("SELECT id, name, client_name FROM common_clients")
        rows = cursor.fetchall()
        ids = [row[0] for row in rows if _normalize_common_client_name(row[1] or row[2]) == canonical]
        if ids:
            cursor.executemany("DELETE FROM common_clients WHERE id=?", [(row_id,) for row_id in ids])
            deleted = len(ids)
        else:
            cursor.execute("DELETE FROM common_clients WHERE name=?", (key,))
            deleted = cursor.rowcount or 0
    conn.commit()
    conn.close()
    return bool(deleted)


def _ensure_announcements_table():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS announcements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            pinned INTEGER DEFAULT 0,
            created_by TEXT,
            image_filename TEXT,
            image_mime TEXT,
            image_blob BLOB,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("PRAGMA table_info(announcements)")
    cols = {row[1] for row in cursor.fetchall()}
    for col_name, col_def in [
        ("image_filename", "TEXT"),
        ("image_mime", "TEXT"),
        ("image_blob", "BLOB"),
    ]:
        if col_name not in cols:
            cursor.execute(f"ALTER TABLE announcements ADD COLUMN {col_name} {col_def}")
    conn.commit()
    conn.close()


def _lock_until(minutes: int):
    return _fmt_dt(_now() + timedelta(minutes=minutes))


def _session_expires_at():
    return _fmt_dt(_now() + timedelta(hours=SESSION_TTL_HOURS))


def _cleanup_expired_sessions(conn=None):
    own_conn = False
    if conn is None:
        conn = sqlite3.connect(DB_PATH)
        own_conn = True
    cursor = conn.cursor()
    cursor.execute("DELETE FROM app_sessions WHERE expires_at IS NOT NULL AND expires_at < ?", (_fmt_dt(_now()),))
    if own_conn:
        conn.commit()
        conn.close()


def _get_user_by_username(username: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, password, display_name, role, is_active, failed_attempts, locked_until FROM app_users WHERE username=?",
        (username,),
    )
    row = cursor.fetchone()
    conn.close()
    return row


def _get_user_by_token(token: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT u.id, u.username, u.display_name, u.role, u.is_active, s.expires_at
        FROM app_sessions s
        JOIN app_users u ON u.username = s.username
        WHERE s.token=? AND u.is_active=1
        """,
        (token,),
    )
    row = cursor.fetchone()
    conn.close()
    return row


def _seed_admin_user():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, password, role, display_name FROM app_users WHERE username=?", (ADMIN_USER,))
    row = cursor.fetchone()
    if not row:
        cursor.execute(
            "INSERT INTO app_users (username, password, display_name, role, is_active, failed_attempts) VALUES (?, ?, ?, ?, 1, 0)",
            (ADMIN_USER, _hash_password(ADMIN_PASS), "系統管理員", "admin"),
        )
        conn.commit()
    elif row and not str(row[1]).startswith(f"{PASSWORD_PREFIX}$"):
        cursor.execute(
            "UPDATE app_users SET password=?, role=COALESCE(role, 'admin'), display_name=COALESCE(display_name, '系統管理員') WHERE id=?",
            (_hash_password(ADMIN_PASS), row[0]),
        )
        conn.commit()
    conn.close()


def _clear_admin_lock():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE app_users SET failed_attempts=0, locked_until=NULL, updated_at=CURRENT_TIMESTAMP WHERE username=?",
        (ADMIN_USER,),
    )
    conn.commit()
    conn.close()


def authenticate(request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    token = request.cookies.get("docmagic_session")
    if token:
        row = _get_user_by_token(token)
        if row:
            expires_at = _parse_dt(row[5])
            if expires_at and expires_at < _now():
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute("DELETE FROM app_sessions WHERE token=?", (token,))
                conn.commit()
                conn.close()
            else:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute("UPDATE app_sessions SET last_seen=CURRENT_TIMESTAMP WHERE token=?", (token,))
                conn.commit()
                conn.close()
                return row[1]

    if credentials and credentials.username and credentials.password:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password, display_name, role, is_active, failed_attempts, locked_until FROM app_users WHERE username=?", (credentials.username,))
        row = cursor.fetchone()
        if row and row[5] == 1:
            locked_until = _parse_dt(row[7])
            if locked_until and locked_until > _now():
                conn.close()
                raise HTTPException(status_code=423, detail="Account locked")
            ok, new_hash = _verify_password(credentials.password, row[2])
            if ok:
                if new_hash:
                    cursor.execute(
                        "UPDATE app_users SET password=?, failed_attempts=0, locked_until=NULL, password_updated_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                        (new_hash, row[0]),
                    )
                else:
                    cursor.execute(
                        "UPDATE app_users SET failed_attempts=0, locked_until=NULL, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                        (row[0],),
                    )
                token = secrets.token_hex(24)
                cursor.execute(
                    "INSERT OR REPLACE INTO app_sessions (token, username, display_name, expires_at, last_seen) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
                    (token, row[1], row[3] or row[1], _session_expires_at()),
                )
                conn.commit()
                conn.close()
                request.state.docmagic_session = token
                return row[1]

            failed_attempts = (row[6] or 0) + 1
            lock_until = _lock_until(LOCK_DURATION_MINUTES) if failed_attempts >= LOCK_THRESHOLD else None
            cursor.execute(
                "UPDATE app_users SET failed_attempts=?, locked_until=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (failed_attempts if failed_attempts < LOCK_THRESHOLD else 0, lock_until, row[0]),
            )
            conn.commit()
            conn.close()
            raise HTTPException(status_code=401, detail="Incorrect username or password")
        conn.close()

    raise HTTPException(
        status_code=401,
        detail="Incorrect username or password",
        headers={"WWW-Authenticate": "Basic"},
    )

# ---------------------------------------------------------
# 資料庫初始化 (SQLite)
# ---------------------------------------------------------
def _default_icloud_db_path():
    cloud_docs = Path.home() / "Library" / "Mobile Documents" / "com~apple~CloudDocs"
    if cloud_docs.exists():
        return cloud_docs / "DocMagic" / "docmagic.db"
    return None


def _db_file_is_writable(path: Path):
    try:
        if path.exists():
            return os.access(path, os.W_OK)
        path.parent.mkdir(parents=True, exist_ok=True)
        probe = path.parent / f".docmagic-write-test-{secrets.token_hex(8)}"
        probe.write_text("1", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return True
    except Exception:
        return False


def _clone_db_if_needed(source: Path, target: Path):
    try:
        if source.exists() and source.resolve() != target.resolve() and not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            return True
    except Exception:
        return False
    return target.exists()


def _resolve_db_path():
    override = os.environ.get("DOCMAGIC_DB_PATH")
    if override:
        override_path = Path(override).expanduser()
        if _db_file_is_writable(override_path):
            return str(override_path)
    data_dir = os.environ.get("DOCMAGIC_DATA_DIR")
    if data_dir:
        data_path = Path(data_dir).expanduser() / "docmagic.db"
        if _db_file_is_writable(data_path):
            _clone_db_if_needed(Path(__file__).resolve().parent / "docmagic.db", data_path)
            return str(data_path)
    workspace_db = Path(__file__).resolve().parent / "docmagic.db"
    if workspace_db.exists() and _db_file_is_writable(workspace_db):
        return str(workspace_db)
    icloud_path = _default_icloud_db_path()
    if icloud_path is not None and _db_file_is_writable(icloud_path):
        _clone_db_if_needed(workspace_db, icloud_path)
        return str(icloud_path)
    home_db = Path.home() / ".docmagic" / "docmagic.db"
    if _db_file_is_writable(home_db):
        _clone_db_if_needed(workspace_db, home_db)
        return str(home_db)
    if workspace_db.exists():
        _clone_db_if_needed(workspace_db, Path("/tmp/docmagic.db"))
        return "/tmp/docmagic.db"
    if os.environ.get("VERCEL") or os.environ.get("VERCEL_ENV") or os.environ.get("VERCEL_URL"):
        return "/tmp/docmagic.db"
    return "docmagic.db"


DB_PATH = _resolve_db_path()
DB_IS_EPHEMERAL = str(DB_PATH).startswith("/tmp/")
DB_PROXY_BASE_URL = os.environ.get("DOCMAGIC_DB_BASE_URL", "").strip().rstrip("/")
DB_PROXY_ENABLED = bool(DB_PROXY_BASE_URL) and os.environ.get("DOCMAGIC_DB_PROXY", "1") != "0"
DB_RUNTIME_PROXY_ENABLED = False
DB_SERVER_MODE = ContextVar("docmagic_db_server_mode", default=False)
_REAL_SQLITE_CONNECT = sqlite3.connect
_BOOTSTRAP_DB_TOKEN = DB_SERVER_MODE.set(True)


def _auth_headers():
    token = base64.b64encode(f"{ADMIN_USER}:{ADMIN_PASS}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def _remote_db_request(payload):
    url = f"{DB_PROXY_BASE_URL}/api/db/query"
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            **_auth_headers(),
        },
        method="POST",
    )
    context = ssl._create_unverified_context()
    with urllib.request.urlopen(req, timeout=30, context=context) as resp:
        return json.loads(resp.read().decode("utf-8"))


class _RemoteCursor:
    def __init__(self, connection):
        self._connection = connection
        self._rows = []
        self._idx = 0
        self.rowcount = -1
        self.lastrowid = None
        self.description = None

    def execute(self, sql, params=()):
        payload = {
            "sql": sql,
            "params": list(params or []),
            "fetch": True,
        }
        result = _remote_db_request(payload)
        self._rows = result.get("rows") or []
        self._idx = 0
        self.rowcount = result.get("rowcount", -1)
        self.lastrowid = result.get("lastrowid")
        columns = result.get("columns") or []
        self.description = [(col, None, None, None, None, None, None) for col in columns]
        return self

    def fetchone(self):
        if self._idx >= len(self._rows):
            return None
        row = self._rows[self._idx]
        self._idx += 1
        return tuple(row)

    def fetchall(self):
        remaining = self._rows[self._idx:]
        self._idx = len(self._rows)
        return [tuple(row) for row in remaining]

    def close(self):
        return None


class _RemoteConnection:
    def __init__(self, path):
        self.path = path

    def cursor(self):
        return _RemoteCursor(self)

    def commit(self):
        return None

    def close(self):
        return None

    def execute(self, sql, params=()):
        return self.cursor().execute(sql, params)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False


def _connect_proxy_or_sqlite(path=DB_PATH, *args, **kwargs):
    if DB_SERVER_MODE.get():
        return _REAL_SQLITE_CONNECT(path, *args, **kwargs)
    if DB_PROXY_ENABLED and DB_RUNTIME_PROXY_ENABLED and DB_PROXY_BASE_URL:
        return _RemoteConnection(path)
    return _REAL_SQLITE_CONNECT(path, *args, **kwargs)


sqlite3.connect = _connect_proxy_or_sqlite


def _ensure_db_parent_dir():
    try:
        Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


_ensure_db_parent_dir()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            doc_no TEXT,
            doc_type TEXT,
            client TEXT,
            project TEXT,
            total_amount REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

init_db()

def init_preset_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS form_presets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            payload TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

init_preset_db()
_ensure_user_table()
_ensure_session_table()
_ensure_common_clients_table()
_seed_common_clients()
_dedupe_common_clients()
_ensure_announcements_table()
_seed_admin_user()
_clear_admin_lock()
DB_SERVER_MODE.reset(_BOOTSTRAP_DB_TOKEN)

# ---------------------------------------------------------
# 靜態資源支援
# ---------------------------------------------------------
@app.get("/logo.png")
async def get_logo():
    logo_path = BASE_DIR / "logo.png"
    if logo_path.exists():
        return FileResponse(str(logo_path))
    return Response(status_code=404)

# ---------------------------------------------------------
# PDF 生成核心
# ---------------------------------------------------------
def _ensure_font_file(filename, download_url=None):
    candidates = [
        FONT_DIR / filename,
        CACHE_FONT_DIR / filename,
        BASE_DIR / filename,
    ]
    for candidate in candidates:
        try:
            if candidate.exists() and candidate.stat().st_size > 100_000:
                return str(candidate)
        except Exception:
            pass

    if not download_url:
        return None

    try:
        CACHE_FONT_DIR.mkdir(parents=True, exist_ok=True)
        target = CACHE_FONT_DIR / filename
        if (not target.exists()) or target.stat().st_size < 100_000:
            with urllib.request.urlopen(download_url, timeout=20) as resp, open(target, "wb") as f:
                f.write(resp.read())
        if target.exists() and target.stat().st_size > 100_000:
            return str(target)
    except Exception:
        pass
    return None


def _register_reportlab_font_family(prefix, candidates):
    if not REPORTLAB_AVAILABLE:
        return None
    for idx, (filename, url) in enumerate(candidates):
        path = _ensure_font_file(filename, url)
        if not path:
            continue
        font_name = f"{prefix}_{idx}"
        try:
            pdfmetrics.registerFont(TTFont(font_name, path))
            return font_name
        except Exception:
            continue
    return None


def _para(text):
    return html.escape("" if text is None else str(text)).replace("\n", "<br/>")


def _fit_box(orig_w, orig_h, max_w, max_h):
    if not orig_w or not orig_h:
        return max_w, max_h
    scale = min(max_w / orig_w, max_h / orig_h)
    return orig_w * scale, orig_h * scale


def _chrome_binary():
    candidates = [
        os.environ.get("CHROME_BIN"),
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        shutil.which("google-chrome"),
        shutil.which("chromium"),
        shutil.which("chromium-browser"),
        shutil.which("chrome"),
    ]
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            return candidate
    return None


def _doc_meta(doc_type):
    suffix_map = {
        "報價單": ("Quotation", "QUOTATION"),
        "發票": ("Invoice", "INVOICE"),
        "收據": ("Receipt", "RECEIPT"),
    }
    title_en, title_sub = suffix_map.get(doc_type, ("Document", "DOCUMENT"))
    if doc_type == "報價單":
        no_label = "報價單編號 Quotation No."
    elif doc_type == "收據":
        no_label = "收據編號 Receipt No."
    else:
        no_label = "發票編號 Invoice No."
    return {
        "title_main": doc_type or "文件",
        "title_sub": title_sub,
        "no_label": no_label,
        "title_en": title_en,
    }


def _doc_remarks(doc_type, custom_remarks=None):
    if custom_remarks and custom_remarks.strip():
        return [line.strip() for line in custom_remarks.splitlines() if line.strip()]
    if doc_type == "報價單":
        return [
            "1. 以上報價以最終確認內容為準。",
            "2. 如有任何查詢，請致電 (852) 6010 0005。",
            "3. 銀行戶口：中國銀行 012-882-0-0082760",
            "4. 戶口名稱：Di2da Dance School",
        ]
    if doc_type == "發票":
        return [
            "1. 請於收到發票後30天內付款。",
            "2. 如有任何查詢，請致電 (852) 3525 0134。",
            "3. 銀行戶口：中國銀行 012-882-0-0082760 (Di2da Dance School)",
        ]
    if doc_type == "收據":
        return [
            "1. 上述款項已全數收妥。",
            "2. 如有任何查詢，請致電 (852) 3525 0134。",
            "3. 銀行戶口：中國銀行 012-882-0-0082760 (Di2da Dance School)",
        ]
    return ["1. 查詢電話：67004444", "2. 感謝 貴校對本校之支持與信任。"]


def _render_public_announcements(limit: int = 3):
    rows = _get_recent_announcements(limit)
    if not rows:
        return '<div class="announce-empty">暫時未有公告。</div>'

    cards = []
    for r in rows:
        img_html = ""
        if r[7]:
            mime = html.escape(r[6] or "image/png")
            alt = html.escape(r[5] or "announcement image")
            img_data = base64.b64encode(r[7]).decode("ascii")
            img_html = f'<img class="announce-img" src="data:{mime};base64,{img_data}" alt="{alt}">'

        body = html.escape(r[2]).replace("\n", "<br>")
        cards.append(f"""
            <article class="announce-card">
                <div class="announce-meta">
                    <span class="announce-tag">{'置頂' if r[3] else '公告'}</span>
                    <span>{html.escape(r[4] or 'system')}</span>
                    <span>{html.escape(r[8] or '')}</span>
                </div>
                <h3>{html.escape(r[1])}</h3>
                <p>{body}</p>
                {img_html}
            </article>
        """)

    return "".join(cards)


def _render_doc_html(doc_type, client_name, project_name, items_list, date_str, doc_no, with_sign=True, custom_remarks=None):
    meta = _doc_meta(doc_type)
    remarks = _doc_remarks(doc_type, custom_remarks)

    def esc(value):
        return html.escape("" if value is None else str(value)).replace("\n", "<br>")

    header_left = []
    header_left.append(f'<div class="line"><b>致 To：</b>{esc(client_name)}</div>')
    if project_name:
        header_left.append(f'<div class="line"><b>項目 Project：</b>{esc(project_name)}</div>')
    header_right = [
        f'<div class="line"><b>{esc(meta["no_label"])}：</b>{esc(doc_no)}</div>',
        f'<div class="line"><b>日期 Date：</b>{esc(date_str)}</div>',
    ]

    item_rows = []
    total_val = 0
    for idx, item in enumerate(items_list, start=1):
        desc, price, qty = item
        try:
            price = int(price)
        except Exception:
            price = 0
        try:
            qty = int(qty)
        except Exception:
            qty = 0
        amount = price * qty
        total_val += amount
        desc_html = esc(desc)
        calc_text = f"${price:,} x {qty}"
        amount_text = f"${amount:,.2f}"
        item_rows.append(
            f"""
            <tr>
              <td>
                <b>ITEM {idx}：{desc_html}</b>
              </td>
              <td>{esc(calc_text)}</td>
              <td>{esc(amount_text)}</td>
            </tr>
            """
        )

    if not item_rows:
        item_rows.append(
            """
            <tr>
              <td><b>ITEM 1：-</b></td>
              <td>$0 x 0</td>
              <td>$0.00</td>
            </tr>
            """
        )

    if doc_type == "收據":
        title_extra = '<br><span class="paid-badge">PAID 已收款</span>'
    else:
        title_extra = ""

    sig_html = ""
    if with_sign:
        sig_src = f"file://{(BASE_DIR / 'signature.png').as_posix()}"
        stamp_src = f"file://{(BASE_DIR / 'stamp.png').as_posix()}"
        sig_html = f"""
        <div class="sig-stamp-area">
          <img class="sig" src="{sig_src}" alt="signature">
          <img class="stamp" src="{stamp_src}" alt="stamp">
        </div>
        """

    logo_src = f"file://{(BASE_DIR / 'logo.png').as_posix()}"
    return f"""
<!DOCTYPE html>
<html lang="zh-HK">
<head>
<meta charset="utf-8">
<style>
  @page {{ size: A4; margin: 0; }}
  body {{
    font-family: "PingFang HK", "PingFang TC", "Microsoft JhengHei", "Noto Sans TC", Arial, sans-serif;
    font-size: 10pt;
    color: #111;
    margin: 0;
    padding: 0;
    background: #fff;
  }}
  .page {{
    width: 210mm;
    min-height: 297mm;
    padding: 15mm 18mm;
    box-sizing: border-box;
    background: #fff;
  }}
  .logo-wrap {{ text-align: center; margin-bottom: 6px; }}
  .logo-wrap img {{ width: 160px; height: auto; display: block; margin: 0 auto; }}
  .company-info {{ text-align: center; font-size: 9.5pt; color: #333; margin-top: 4px; line-height: 1.5; }}
  .company-divider {{ border: none; border-top: 1px solid #ccc; width: 80%; margin: 6px auto 16px auto; }}
  .header-block {{ display: flex; justify-content: space-between; gap: 16px; margin-bottom: 12px; font-size: 10pt; color: #111; }}
  .header-block .line {{ margin-bottom: 3px; }}
  .header-left {{ flex: 1; }}
  .header-right {{ text-align: right; width: 230px; }}
  .title-wrap {{ text-align: center; margin: 16px 0 6px 0; }}
  .title-main {{ font-size: 22pt; font-weight: bold; letter-spacing: 4px; color: #111; }}
  .title-sub {{ font-size: 12pt; font-weight: normal; letter-spacing: 2px; color: #555; }}
  .paid-badge {{ display: inline-block; border: 1px solid #111; padding: 0 14px; font-size: 10pt; font-weight: bold; letter-spacing: 2px; color: #111; margin: 2px 0; }}
  .title-underline {{ border: none; border-top: 1px solid #111; width: 220px; margin: 3px auto 12px auto; }}
  table.items {{ width: 100%; border-collapse: collapse; border: 1px solid #111; font-size: 10pt; }}
  table.items th, table.items td {{ border: 1px solid #111; padding: 6px 8px; }}
  table.items th {{ background: #fff; font-size: 10pt; text-align: center; color: #111; font-weight: bold; }}
  table.items th:nth-child(1) {{ width: 50%; text-align: left; }}
  table.items th:nth-child(2) {{ width: 22%; }}
  table.items th:nth-child(3) {{ width: 28%; }}
  table.items td:nth-child(1) {{ vertical-align: top; padding: 10px 10px; line-height: 1.7; }}
  table.items td:nth-child(2) {{ text-align: center; vertical-align: middle; }}
  table.items td:nth-child(3) {{ text-align: center; vertical-align: middle; }}
  .total-row td {{ font-weight: bold; border-top: 2px solid #111 !important; }}
  .total-label-cell {{ text-align: right; padding-right: 10px !important; font-size: 10pt; }}
  .total-amount-cell {{ text-align: center; font-size: 10pt; }}
  .bottom {{
    display: flex;
    justify-content: space-between;
    gap: 18px;
    margin-top: 18px;
    min-height: 140px;
  }}
  .bottom-notes {{ flex: 1; font-size: 9pt; line-height: 1.8; color: #111; }}
  .bottom-notes b {{ font-size: 9.5pt; }}
  .bottom-sign {{ width: 300px; text-align: right; position: relative; padding-top: 10px; }}
  .sig-stamp-area {{
    display: flex;
    flex-direction: row;
    align-items: center;
    justify-content: flex-end;
    gap: 10px;
    margin-bottom: 8px;
    min-height: 80px;
  }}
  .sig-stamp-area img.sig {{ width: 180px; height: auto; display: block; }}
  .sig-stamp-area img.stamp {{ width: 70px; height: auto; display: block; }}
  .sig-line {{ border-top: 1px solid #111; width: 280px; margin: 2px 0 4px auto; padding-top: 4px; font-size: 8.5pt; color: #555; text-align: center; }}
  .sig-entity {{ font-size: 8pt; color: #888; text-align: center; }}
</style>
</head>
<body>
<div class="page">
  <div class="logo-wrap">
    <img src="{logo_src}" alt="Di2da Dance School">
  </div>
  <div class="company-info">
    地址：九龍紅磡鶴園街2G號恒豐工業大廈1期3樓C室 &nbsp;&nbsp;&nbsp;電話：60100005 &nbsp;&nbsp;&nbsp;電郵：admin@dancekingdom.com.hk
  </div>
  <hr class="company-divider">
  <div class="header-block">
    <div class="header-left">
      {''.join(header_left)}
    </div>
    <div class="header-right">
      {''.join(header_right)}
    </div>
  </div>
  <div class="title-wrap">
    <span class="title-main">{esc(meta["title_main"])}</span> <span class="title-sub">{esc(meta["title_sub"])}</span>{title_extra}
  </div>
  <hr class="title-underline">
  <table class="items">
    <tr>
      <th>摘要 DESCRIPTION</th>
      <th>金額 HKD</th>
      <th>費用 AMOUNT</th>
    </tr>
    {''.join(item_rows)}
    <tr class="total-row">
      <td colspan="2" class="total-label-cell">總計 Total</td>
      <td class="total-amount-cell">${total_val:,.2f}</td>
    </tr>
  </table>
    <div class="bottom">
    <div class="bottom-notes">
      <b>備註：</b><br>
      {''.join(f'{esc(remark)}<br>' for remark in remarks)}
    </div>
    <div class="bottom-sign">
      {sig_html}
      <div class="sig-line">授權人簽署 Authorized Signature</div>
      <div class="sig-entity">狄易達軍團跳舞學校 Di2da Dance School</div>
    </div>
  </div>
</div>
</body>
</html>
"""


def _build_pdf_html(doc_type, client_name, project_name, items_list, date_str, doc_no, with_sign=True, custom_remarks=None):
    chrome = _chrome_binary()
    if not chrome:
        raise RuntimeError("Chrome binary not found")

    html_content = _render_doc_html(doc_type, client_name, project_name, items_list, date_str, doc_no, with_sign, custom_remarks)
    with tempfile.TemporaryDirectory(prefix="docmagic-html-") as tmpdir:
        html_path = Path(tmpdir) / "doc.html"
        pdf_path = Path(tmpdir) / "doc.pdf"
        html_path.write_text(html_content, encoding="utf-8")
        cmd = [
            chrome,
            "--headless",
            "--disable-gpu",
            "--no-sandbox",
            "--allow-file-access-from-files",
            "--hide-scrollbars",
            "--run-all-compositor-stages-before-draw",
            f"--print-to-pdf={pdf_path}",
            html_path.as_uri(),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
        if result.returncode != 0 or not pdf_path.exists():
            raise RuntimeError((result.stderr or result.stdout or "Chrome PDF generation failed").strip())
        return pdf_path.read_bytes()


def _build_pdf_reportlab(doc_type, client_name, project_name, items_list, date_str, doc_no, with_sign=True, custom_remarks=None):
    regular_font = _register_reportlab_font_family("DocMagicRegular", [
        (
            "NotoSansCJKtc-Regular.otf",
            "https://raw.githubusercontent.com/notofonts/noto-cjk/main/Sans/OTF/TraditionalChinese/NotoSansCJKtc-Regular.otf",
        ),
        (
            "NotoSansTC-wght.ttf",
            "https://raw.githubusercontent.com/google/fonts/main/ofl/notosanstc/NotoSansTC%5Bwght%5D.ttf",
        ),
    ])
    bold_font = _register_reportlab_font_family("DocMagicBold", [
        (
            "NotoSansCJKtc-Bold.otf",
            "https://raw.githubusercontent.com/notofonts/noto-cjk/main/Sans/OTF/TraditionalChinese/NotoSansCJKtc-Bold.otf",
        ),
        (
            "NotoSansTC-wght.ttf",
            "https://raw.githubusercontent.com/google/fonts/main/ofl/notosanstc/NotoSansTC%5Bwght%5D.ttf",
        ),
    ]) or regular_font

    if not regular_font:
        raise RuntimeError("ReportLab font registration failed")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=14 * mm,
        rightMargin=14 * mm,
        topMargin=14 * mm,
        bottomMargin=14 * mm,
    )
    usable_width = A4[0] - doc.leftMargin - doc.rightMargin
    styles = getSampleStyleSheet()
    body = ParagraphStyle(
        "DMBody",
        parent=styles["BodyText"],
        fontName=regular_font,
        fontSize=12.5,
        leading=16,
        textColor=colors.black,
        wordWrap="CJK",
    )
    body_center = ParagraphStyle(
        "DMBodyCenter",
        parent=body,
        alignment=TA_CENTER,
    )
    body_right = ParagraphStyle(
        "DMBodyRight",
        parent=body,
        alignment=TA_RIGHT,
    )
    body_bold = ParagraphStyle(
        "DMBold",
        parent=body,
        fontName=bold_font or regular_font,
        fontSize=12.5,
        leading=16,
    )
    header = ParagraphStyle(
        "DMHeader",
        parent=body_bold,
        fontSize=13.5,
        leading=17,
        alignment=TA_CENTER,
    )
    title = ParagraphStyle(
        "DMTitle",
        parent=body_bold,
        fontSize=24,
        leading=28,
        alignment=TA_CENTER,
    )
    small = ParagraphStyle(
        "DMSmall",
        parent=body,
        fontSize=10.5,
        leading=13,
    )
    small_center = ParagraphStyle(
        "DMSmallCenter",
        parent=small,
        alignment=TA_CENTER,
    )
    total_amount_style = ParagraphStyle(
        "DMTotalAmount",
        parent=body_bold,
        fontSize=14,
        leading=17,
        alignment=TA_RIGHT,
    )

    story = []
    logo_path = BASE_DIR / "logo.png"
    if logo_path.exists():
        try:
            with Image.open(logo_path) as im:
                logo_w = 46 * mm
                logo_h = logo_w * im.height / im.width
            story.append(RLImage(str(logo_path), width=logo_w, height=logo_h))
            story.append(Spacer(1, 4 * mm))
        except Exception:
            pass

    addr_text = "地址：九龍紅磡鶴園街2G號恒豐工業大廈1期3樓C室   電話：60100005   電郵：admin@dancekingdom.com.hk"
    story.append(Paragraph(_para(addr_text), small_center))
    story.append(Spacer(1, 3 * mm))
    story.append(HRFlowable(width="100%", thickness=0.7, color=colors.HexColor("#CCCCCC")))
    story.append(Spacer(1, 5 * mm))

    left_top = Paragraph(f"<b>致：</b>{_para(client_name)}", body)
    right_top = Paragraph(f"<b>{_para(doc_type)}號碼：</b>{_para(doc_no)}", body_right)
    left_bottom = Paragraph(f"<b>項目：</b>{_para(project_name)}", body)
    right_bottom = Paragraph(f"<b>日期：</b>{_para(date_str)}", body_right)
    info_table = Table(
        [[left_top, right_top], [left_bottom, right_bottom]],
        colWidths=[usable_width * 0.66, usable_width * 0.34],
    )
    info_table.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 5 * mm))

    doc_en = {"報價單": "QUOTATION", "發票": "INVOICE", "收據": "RECEIPT"}.get(doc_type, "DOCUMENT")
    story.append(Paragraph(f"<b>{_para(doc_type)} {doc_en}</b>", title))
    story.append(Spacer(1, 1.5 * mm))
    story.append(HRFlowable(width=usable_width * 0.32, thickness=1.2, color=colors.black, hAlign="CENTER"))
    story.append(Spacer(1, 5 * mm))

    col1_w = usable_width * 0.50
    col2_w = usable_width * 0.22
    col3_w = usable_width * 0.28
    table_data = [
        [Paragraph("摘 要 Description", header), Paragraph("數量/計算", header), Paragraph("費用 (HKD)", header)]
    ]
    total_val = 0
    for desc, price, qty in items_list:
        amount = int(price) * int(qty)
        total_val += amount
        table_data.append([
            Paragraph(_para(desc), body),
            Paragraph(f"${int(price):,} x {int(qty)}", body_center),
            Paragraph(f"${amount:,.2f}", body_right),
        ])

    total_row_idx = len(table_data)
    table_data.append([
        Paragraph("總計 Total", body_bold),
        "",
        Paragraph(f"${total_val:,.2f}", total_amount_style),
    ])
    items_table = Table(table_data, colWidths=[col1_w, col2_w, col3_w], repeatRows=1)
    items_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.8, colors.black),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F3F3F3")),
        ("BACKGROUND", (0, total_row_idx), (-1, total_row_idx), colors.HexColor("#F9F9F9")),
        ("SPAN", (0, total_row_idx), (1, total_row_idx)),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (1, 1), (1, -1), "CENTER"),
        ("ALIGN", (2, 1), (2, -1), "RIGHT"),
    ]))
    story.append(items_table)
    story.append(Spacer(1, 6 * mm))

    if custom_remarks and custom_remarks.strip():
        remarks = [r.strip() for r in custom_remarks.split("\n") if r.strip()]
    else:
        if doc_type == "報價單":
            remarks = ["請簽回或蓋印報價單確認合約。"]
        elif doc_type == "發票":
            remarks = [
                "1. 將全數款項支票交給項目負責人或直接存入「狄易達軍團跳舞學校」戶口。",
                "2. 支票抬頭：Di2da Dance School",
                "3. 中國銀行：012 882 000 82760",
                "4. 本校只接受支票付款。/ 查詢電話：67004444",
            ]
        else:
            remarks = ["1. 查詢電話：67004444", "2. 感謝 貴校對本校之支持與信任。"]

    story.append(Paragraph("備註：", body_bold))
    story.append(Spacer(1, 1.5 * mm))
    for remark in remarks:
        story.append(Paragraph(_para(remark), small))
        story.append(Spacer(1, 1.8 * mm))

    sig_path = BASE_DIR / "signature.png"
    stamp_path = BASE_DIR / "stamp.png"
    signature_rows = []
    if with_sign:
        signature_image_row = [
            None,
            None,
        ]
        if sig_path.exists():
            with Image.open(sig_path) as im:
                sw, sh = _fit_box(im.width, im.height, 48 * mm, 26 * mm)
            signature_image_row[0] = RLImage(str(sig_path), width=sw, height=sh)
        else:
            signature_image_row[0] = Spacer(1, 1)
        if stamp_path.exists():
            with Image.open(stamp_path) as im:
                tw, th = _fit_box(im.width, im.height, 22 * mm, 22 * mm)
            signature_image_row[1] = RLImage(str(stamp_path), width=tw, height=th)
        else:
            signature_image_row[1] = Spacer(1, 1)
        if sig_path.exists() or stamp_path.exists():
            signature_rows.append(Table([signature_image_row], hAlign="RIGHT", colWidths=[48 * mm, 22 * mm]))
        signature_rows.append(Spacer(1, 2 * mm))
    signature_rows.append(HRFlowable(width="100%", thickness=1, color=colors.black, hAlign="RIGHT"))
    signature_rows.append(Paragraph("授權人簽署 Authorized Signature", small_center))
    signature_box = Table(
        [[Spacer(1, 1), signature_rows]],
        colWidths=[usable_width * 0.52, usable_width * 0.48],
    )
    signature_box.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("VALIGN", (0, 0), (-1, -1), "BOTTOM"),
        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
    ]))
    story.append(Spacer(1, 12 * mm))
    story.append(signature_box)

    doc.build(story)
    return buffer.getvalue()


def _build_pdf_pil(doc_type, client_name, project_name, items_list, date_str, doc_no, with_sign=True, custom_remarks=None):
    scale = 2
    width, height = 1240 * scale, 1754 * scale
    image = Image.new("RGB", (width, height), color="#FFFFFF")
    draw = ImageDraw.Draw(image)

    def get_font(size, bold=False):
        font_cache = get_font.cache
        cache_key = (size, bold)
        if cache_key in font_cache:
            return font_cache[cache_key]
        google_tc_font = _ensure_font_file(
            "NotoSansTC-wght.ttf",
            "https://raw.githubusercontent.com/google/fonts/main/ofl/notosanstc/NotoSansTC%5Bwght%5D.ttf",
        )
        font_paths_regular = [
            _ensure_font_file(
                "NotoSansCJKtc-Regular.otf",
                "https://raw.githubusercontent.com/notofonts/noto-cjk/main/Sans/OTF/TraditionalChinese/NotoSansCJKtc-Regular.otf",
            ),
            _ensure_font_file(
                "NotoSansCJKtc-Regular.ttf",
                "https://raw.githubusercontent.com/notofonts/noto-cjk/main/Sans/OTF/TraditionalChinese/NotoSansCJKtc-Regular.otf",
            ),
            google_tc_font,
            str(BASE_DIR / "assets" / "fonts" / "NotoSansCJKtc-Regular.otf"),
            str(BASE_DIR / "assets" / "fonts" / "NotoSansCJKtc-Regular.ttf"),
        ]
        font_paths_bold = [
            _ensure_font_file(
                "NotoSansCJKtc-Bold.otf",
                "https://raw.githubusercontent.com/notofonts/noto-cjk/main/Sans/OTF/TraditionalChinese/NotoSansCJKtc-Bold.otf",
            ),
            _ensure_font_file(
                "NotoSansCJKtc-Bold.ttf",
                "https://raw.githubusercontent.com/notofonts/noto-cjk/main/Sans/OTF/TraditionalChinese/NotoSansCJKtc-Bold.otf",
            ),
            google_tc_font,
            str(BASE_DIR / "assets" / "fonts" / "NotoSansCJKtc-Bold.otf"),
            str(BASE_DIR / "assets" / "fonts" / "NotoSansCJKtc-Bold.ttf"),
        ]
        for path in (font_paths_bold if bold else font_paths_regular):
            try:
                if path and os.path.exists(path):
                    font = ImageFont.truetype(path, size)
                    font_cache[cache_key] = font
                    return font
            except Exception:
                continue
        font_cache[cache_key] = ImageFont.load_default()
        return font_cache[cache_key]

    get_font.cache = {}

    def line_height(font):
        bbox = draw.textbbox((0, 0), "Ag", font=font)
        return bbox[3] - bbox[1]

    def wrap_text(text, font, max_width):
        text = "" if text is None else str(text)
        wrapped_lines = []
        paragraphs = text.splitlines() or [""]
        for paragraph in paragraphs:
            if paragraph == "":
                wrapped_lines.append("")
                continue
            current = ""
            for ch in paragraph:
                test = current + ch
                if not current or draw.textlength(test, font=font) <= max_width:
                    current = test
                else:
                    wrapped_lines.append(current)
                    current = ch
            if current:
                wrapped_lines.append(current)
        return wrapped_lines or [""]

    def draw_wrapped_text(x, y, text, font, fill, max_width, spacing=8):
        lines = wrap_text(text, font, max_width)
        lh = line_height(font)
        for idx, line in enumerate(lines):
            draw.text((x, y + idx * (lh + spacing)), line, font=font, fill=fill, anchor="la")
        return len(lines) * lh + max(0, len(lines) - 1) * spacing

    def wrapped_text_height(text, font, max_width, spacing=8):
        lines = wrap_text(text, font, max_width)
        lh = line_height(font)
        return len(lines) * lh + max(0, len(lines) - 1) * spacing

    f_title = get_font(76, bold=True)
    f_info = get_font(44, bold=True)
    f_table_hdr = get_font(42, bold=True)
    f_item = get_font(38, bold=True)
    f_calc = get_font(34, bold=False)
    f_total = get_font(44, bold=True)
    f_remark = get_font(28, bold=False)
    f_addr = get_font(24, bold=False)

    margin = 240
    y = 140

    logo_path = BASE_DIR / "logo.png"
    try:
        if logo_path.exists():
            logo = Image.open(logo_path).convert("RGBA")
            logo_w = 440
            logo_h = int(logo_w * logo.height / logo.width)
            resized = logo.resize((logo_w, logo_h))
            image.paste(resized, (width // 2 - logo_w // 2, y), resized)
            y += logo_h + 40
    except Exception:
        y += 60

    addr_text = "地址：九龍紅磡鶴園街2G號恒豐工業大廈1期3樓C室   電話：60100005   電郵：admin@dancekingdom.com.hk"
    draw.text((width // 2, y), addr_text, font=f_addr, fill="#333333", anchor="mm")
    y += 60
    draw.line([margin, y, width - margin, y], fill="#CCCCCC", width=2)
    y += 90

    client_label_w = draw.textlength("致：", font=f_info)
    draw.text((margin, y), "致：", font=f_info, fill="black")
    client_height = draw_wrapped_text(margin + client_label_w, y, client_name, f_info, "black", width - margin * 2 - 360)
    draw.text((width - margin, y), f"{doc_type}號碼：{doc_no}", font=f_info, fill="black", anchor="ra")
    y += max(client_height, line_height(f_info)) + 22

    project_label_w = draw.textlength("項目：", font=f_info)
    draw.text((margin, y), "項目：", font=f_info, fill="black")
    project_height = draw_wrapped_text(margin + project_label_w, y, project_name, f_info, "black", width - margin * 2 - 360)
    draw.text((width - margin, y), f"日期：{date_str}", font=f_info, fill="black", anchor="ra")
    y += max(project_height, line_height(f_info)) + 52

    doc_en = {"報價單": "QUOTATION", "發票": "INVOICE", "收據": "RECEIPT"}.get(doc_type, "DOCUMENT")
    draw.text((width // 2, y), f"{doc_type} {doc_en}", font=f_title, fill="black", anchor="mm")
    draw.line([width // 2 - 240, y + 36, width // 2 + 240, y + 36], fill="black", width=3)
    y += 152

    col1_w, col2_w, col3_w = 1100, 420, 480
    table_x = margin
    table_w = col1_w + col2_w + col3_w
    header_h = 120
    draw.rectangle([table_x, y, table_x + table_w, y + header_h], outline="black", width=3)
    draw.text((table_x + col1_w // 2, y + header_h // 2), "摘 要 Description", font=f_table_hdr, fill="black", anchor="mm")
    draw.text((table_x + col1_w + col2_w // 2, y + header_h // 2), "數量/計算", font=f_table_hdr, fill="black", anchor="mm")
    draw.text((table_x + table_w - col3_w // 2, y + header_h // 2), "費用 (HKD)", font=f_table_hdr, fill="black", anchor="mm")
    y += header_h

    total_val = 0
    for desc, price, qty in items_list:
        amt = int(price) * int(qty)
        total_val += amt
        desc_max_width = col1_w - 60
        desc_height = wrapped_text_height(desc, f_item, desc_max_width)
        calc_height = line_height(f_calc)
        amt_height = line_height(f_total)
        row_h = max(desc_height, calc_height, amt_height) + 44
        draw.rectangle([table_x, y, table_x + table_w, y + row_h], outline="black", width=2)
        draw_wrapped_text(table_x + 30, y + 16, desc, f_item, "black", desc_max_width)
        draw.text((table_x + col1_w + col2_w // 2, y + row_h // 2), f"${int(price):,} x {int(qty)}", font=f_calc, fill="black", anchor="mm")
        draw.text((table_x + table_w - 28, y + row_h // 2), f"${amt:,.2f}", font=f_total, fill="black", anchor="rm")
        y += row_h

    draw.rectangle([table_x, y, table_x + table_w, y + 108], outline="black", width=3, fill="#F9F9F9")
    draw.text((table_x + col1_w + col2_w - 28, y + 54), "總計 Total:", font=f_total, fill="black", anchor="rm")
    draw.text((table_x + table_w - 28, y + 54), f"${total_val:,.2f}", font=f_total, fill="black", anchor="rm")
    y += 140

    if custom_remarks and custom_remarks.strip():
        remarks = [r.strip() for r in custom_remarks.split("\n") if r.strip()]
    else:
        if doc_type == "報價單":
            remarks = ["請簽回或蓋印報價單確認合約。"]
        elif doc_type == "發票":
            remarks = [
                "1. 將全數款項支票交給項目負責人或直接存入「狄易達軍團跳舞學校」戶口。",
                "2. 支票抬頭：Di2da Dance School",
                "3. 中國銀行：012 882 000 82760",
                "4. 本校只接受支票付款。/ 查詢電話：67004444",
            ]
        else:
            remarks = ["1. 查詢電話：67004444", "2. 感謝 貴校對本校之支持與信任。"]

    draw.text((margin, y), "備註：", font=f_item, fill="black")
    y += 48
    for remark in remarks:
        draw_wrapped_text(margin, y, remark, f_remark, "black", width - margin * 2 - 40)
        y += wrapped_text_height(remark, f_remark, width - margin * 2 - 40) + 16

    sig_line_y = height - 430
    line_x_start = width - 620
    line_x_end = width - margin
    if with_sign:
        try:
            if sig_path.exists():
                s = Image.open(sig_path).convert("RGBA")
                fit_w, fit_h = _fit_box(s.width, s.height, 260, 130)
                s = s.resize((max(1, int(fit_w)), max(1, int(fit_h))), Image.Resampling.LANCZOS)
                image.paste(s, (line_x_start + 18, sig_line_y - 12), s)
            if stamp_path.exists():
                st = Image.open(stamp_path).convert("RGBA")
                fit_w, fit_h = _fit_box(st.width, st.height, 180, 180)
                st = st.resize((max(1, int(fit_w)), max(1, int(fit_h))), Image.Resampling.LANCZOS)
                image.paste(st, (line_x_end - int(fit_w) - 12, sig_line_y - 62), st)
        except Exception:
            pass

    draw.line([line_x_start, sig_line_y + 120, line_x_end, sig_line_y + 120], fill="black", width=3)
    draw.text((line_x_start + (line_x_end - line_x_start) // 2, sig_line_y + 154), "授權人簽署 Authorized Signature", font=f_remark, fill="black", anchor="mm")

    pdf_buffer = io.BytesIO()
    image.save(pdf_buffer, format="PDF")
    return pdf_buffer.getvalue()


def _generate_pdf_modern(doc_type, client_name, project_name, items_list, date_str, doc_no, with_sign=True, custom_remarks=None):
    try:
        return _build_pdf_html(doc_type, client_name, project_name, items_list, date_str, doc_no, with_sign, custom_remarks)
    except Exception:
        pass
    if REPORTLAB_AVAILABLE:
        try:
            return _build_pdf_reportlab(doc_type, client_name, project_name, items_list, date_str, doc_no, with_sign, custom_remarks)
        except Exception:
            pass
    return _build_pdf_pil(doc_type, client_name, project_name, items_list, date_str, doc_no, with_sign, custom_remarks)


def generate_pdf_logic(doc_type, client_name, project_name, items_list, date_str, doc_no, with_sign=True, custom_remarks=None):
    return _generate_pdf_modern(doc_type, client_name, project_name, items_list, date_str, doc_no, with_sign, custom_remarks)
    width, height = 1240, 1754
    image = Image.new('RGB', (width, height), color='#FFFFFF')
    draw = ImageDraw.Draw(image)
    
    def ensure_font_file(filename, download_url):
        local_candidates = [
            FONT_DIR / filename,
            CACHE_FONT_DIR / filename,
        ]
        for candidate in local_candidates:
            try:
                if candidate.exists() and candidate.stat().st_size > 1024 * 1024:
                    return str(candidate)
            except Exception:
                pass

        try:
            CACHE_FONT_DIR.mkdir(parents=True, exist_ok=True)
            target = CACHE_FONT_DIR / filename
            if (not target.exists()) or target.stat().st_size < 1024 * 1024:
                with urllib.request.urlopen(download_url, timeout=20) as resp, open(target, "wb") as f:
                    f.write(resp.read())
            if target.exists() and target.stat().st_size > 1024 * 1024:
                return str(target)
        except Exception:
            pass

        return str(FONT_DIR / filename)

    # 針對 Mac / Linux / Vercel 的字體適配
    font_paths_regular = [
        ensure_font_file(
            "NotoSansCJKtc-Regular.otf",
            "https://raw.githubusercontent.com/notofonts/noto-cjk/main/Sans/OTF/TraditionalChinese/NotoSansCJKtc-Regular.otf",
        ),
        ensure_font_file(
            "NotoSansCJKtc-Regular.ttf",
            "https://raw.githubusercontent.com/notofonts/noto-cjk/main/Sans/OTF/TraditionalChinese/NotoSansCJKtc-Regular.otf",
        ),
        google_tc_font,
        "/System/Library/AssetsV2/com_apple_MobileAsset_Font8/86ba2c91f017a3749571a82f2c6d890ac7ffb2fb.asset/AssetData/PingFang.ttc",
        "/System/Library/Fonts/PingFang.ttc",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    ]
    google_tc_font = ensure_font_file(
        "NotoSansTC-wght.ttf",
        "https://raw.githubusercontent.com/google/fonts/main/ofl/notosanstc/NotoSansTC%5Bwght%5D.ttf",
    )
    font_paths_bold = [
        ensure_font_file(
            "NotoSansCJKtc-Bold.otf",
            "https://raw.githubusercontent.com/notofonts/noto-cjk/main/Sans/OTF/TraditionalChinese/NotoSansCJKtc-Bold.otf",
        ),
        ensure_font_file(
            "NotoSansCJKtc-Bold.ttf",
            "https://raw.githubusercontent.com/notofonts/noto-cjk/main/Sans/OTF/TraditionalChinese/NotoSansCJKtc-Bold.otf",
        ),
        "/System/Library/AssetsV2/com_apple_MobileAsset_Font8/86ba2c91f017a3749571a82f2c6d890ac7ffb2fb.asset/AssetData/PingFang.ttc",
        "/System/Library/Fonts/PingFang.ttc",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
        google_tc_font,
    ]
    font_cache = {}

    def _load_font(path, size):
        try:
            if path and os.path.exists(path):
                return ImageFont.truetype(path, size)
        except Exception:
            pass
        return None

    def get_font(size, bold=False):
        cache_key = (size, bold)
        if cache_key in font_cache:
            return font_cache[cache_key]
        paths = font_paths_bold if bold else font_paths_regular
        for path in paths:
            font = _load_font(path, size)
            if font:
                font_cache[cache_key] = font
                return font
        # 最後兜底：盡量用系統預設，但避免完全崩潰
        font_cache[cache_key] = ImageFont.load_default()
        return font_cache[cache_key]

    def line_height(font):
        bbox = draw.textbbox((0, 0), "Ag", font=font)
        return bbox[3] - bbox[1]

    def wrap_text(text, font, max_width):
        text = "" if text is None else str(text)
        wrapped_lines = []
        paragraphs = text.splitlines() or [""]
        for paragraph in paragraphs:
            if paragraph == "":
                wrapped_lines.append("")
                continue
            current = ""
            for ch in paragraph:
                test = current + ch
                if not current or draw.textlength(test, font=font) <= max_width:
                    current = test
                else:
                    wrapped_lines.append(current)
                    current = ch
            if current:
                wrapped_lines.append(current)
        return wrapped_lines or [""]

    def draw_wrapped_text(x, y, text, font, fill, max_width, spacing=6):
        lines = wrap_text(text, font, max_width)
        lh = line_height(font)
        for idx, line in enumerate(lines):
            draw.text((x, y + idx * (lh + spacing)), line, font=font, fill=fill, anchor="la")
        return len(lines) * lh + max(0, len(lines) - 1) * spacing

    def wrapped_text_height(text, font, max_width, spacing=6):
        lines = wrap_text(text, font, max_width)
        lh = line_height(font)
        return len(lines) * lh + max(0, len(lines) - 1) * spacing

    f_title = get_font(38, bold=True)
    f_info = get_font(26, bold=True)
    f_table_hdr = get_font(27, bold=True)
    f_item = get_font(24, bold=True)
    f_calc = get_font(22, bold=False)
    f_total = get_font(32, bold=True)
    f_remark = get_font(21, bold=False)
    f_addr = get_font(20, bold=False)

    margin = 120
    y = 80

    # LOGO
    try:
        if os.path.exists("logo.png"):
            logo = Image.open("logo.png").convert("RGBA")
            logo_w = 220
            logo_h = int(logo_w * logo.height / logo.width)
            image.paste(logo.resize((logo_w, logo_h)), (width//2 - logo_w//2, y), logo.resize((logo_w, logo_h)))
            y += logo_h + 30
    except: y += 60

    addr_text = "地址：九龍紅磡鶴園街2G號恒豐工業大廈1期3樓C室   電話：60100005   電郵：admin@dancekingdom.com.hk"
    draw.text((width//2, y), addr_text, font=f_addr, fill='#333333', anchor="mm")
    y += 30
    draw.line([margin, y, width-margin, y], fill='#CCCCCC', width=1)
    y += 58

    doc_en = {"報價單": "QUOTATION", "發票": "INVOICE", "收據": "RECEIPT"}.get(doc_type, "DOCUMENT")
    client_label = "致："
    client_label_w = draw.textlength(client_label, font=f_info)
    client_text_x = margin + client_label_w
    client_max_width = width - margin * 2 - 220
    draw.text((margin, y), client_label, font=f_info, fill='black')
    client_height = draw_wrapped_text(client_text_x, y, client_name, f_info, 'black', client_max_width)
    draw.text((width - margin, y), f"{doc_type}號碼：{doc_no}", font=f_info, fill='black', anchor="ra")
    y += max(client_height, line_height(f_info)) + 12
    project_label_w = draw.textlength("項目：", font=f_info)
    project_text_x = margin + project_label_w
    project_max_width = width - margin * 2 - 240
    draw.text((margin, y), "項目：", font=f_info, fill='black')
    project_height = draw_wrapped_text(project_text_x, y, project_name, f_info, 'black', project_max_width)
    draw.text((width - margin, y), f"日期：{date_str}", font=f_info, fill='black', anchor="ra")
    y += max(project_height, line_height(f_info)) + 38

    title_text = f"{doc_type} {doc_en}"
    draw.text((width//2, y), title_text, font=f_title, fill='black', anchor="mm")
    draw.line([width//2 - 120, y + 25, width//2 + 120, y + 25], fill='black', width=2)
    y += 106

    # Table
    col1_w, col2_w, col3_w = 550, 200, 250
    table_x = margin
    table_w = col1_w + col2_w + col3_w
    header_h = 82
    draw.rectangle([table_x, y, table_x + table_w, y + header_h], outline='black', width=2)
    draw.text((table_x + col1_w//2, y + header_h//2), "摘 要 Description", font=f_table_hdr, fill='black', anchor="mm")
    draw.text((table_x + col1_w + col2_w//2, y + header_h//2), "數量/計算", font=f_table_hdr, fill='black', anchor="mm")
    draw.text((table_x + table_w - col3_w//2, y + header_h//2), "費用 (HKD)", font=f_table_hdr, fill='black', anchor="mm")
    y += header_h

    total_val = 0
    for desc, price, qty in items_list:
        amt = price * qty
        total_val += amt
        desc_max_width = col1_w - 40
        desc_height = wrapped_text_height(desc, f_item, desc_max_width)
        calc_height = line_height(f_calc)
        amt_height = line_height(f_total)
        row_h = max(desc_height, calc_height, amt_height) + 32
        draw.rectangle([table_x, y, table_x + table_w, y + row_h], outline='black', width=1)
        draw_wrapped_text(table_x + 20, y + 12, desc, f_item, 'black', desc_max_width)
        draw.text((table_x + col1_w + col2_w//2, y + row_h//2), f"${price:,} x {qty}", font=f_calc, fill='black', anchor="mm")
        draw.text((table_x + table_w - 20, y + row_h//2), f"${amt:,.2f}", font=f_total, fill='black', anchor="rm")
        y += row_h

    draw.rectangle([table_x, y, table_x + table_w, y + 74], outline='black', width=2, fill="#F9F9F9")
    draw.text((table_x + col1_w + col2_w - 20, y + 37), "總計 Total:", font=f_total, fill='black', anchor="rm")
    draw.text((table_x + table_w - 20, y + 37), f"${total_val:,.2f}", font=f_total, fill='black', anchor="rm")
    y += 96

    if custom_remarks and custom_remarks.strip():
        remarks = [r.strip() for r in custom_remarks.split('\n') if r.strip()]
    else:
        if doc_type == "報價單":
            remarks = ["請簽回或蓋印報價單確認合約。"]
        elif doc_type == "發票":
            remarks = [
                "1. 將全數款項支票交給項目負責人或直接存入” 狄易達軍團跳舞學校 ” 戶口。",
                "2. 支票抬頭： “ Di2da Dance School ”",
                "3. 中國銀行：012 882 000 82760",
                "4. 本校只接受支票付款。/ 查詢電話：67004444"
            ]
        else:
            remarks = ["1. 查詢電話：67004444", "2. 感謝 貴校對本校之支持與信任。"]
    
    draw.text((margin, y), "備註：", font=f_item, fill='black')
    y += 35
    for r in remarks:
        draw.text((margin, y), r, font=f_remark, fill='black')
        y += 30

    y_sig_base = height - 380
    line_x_start = width - 500
    line_x_end = width - margin
    draw.line([line_x_start, y_sig_base + 120, line_x_end, y_sig_base + 120], fill='black', width=2)
    draw.text((line_x_start + (line_x_end - line_x_start)//2, y_sig_base + 145), "授權人簽署 Authorized Signature", font=f_remark, fill='black', anchor="mm")
    
    if with_sign:
        try:
            if os.path.exists("signature.png"):
                s = Image.open("signature.png").convert("RGBA")
                s.thumbnail((200, 100))
                image.paste(s, (line_x_start + 20, y_sig_base - 10), s)
            if os.path.exists("stamp.png"):
                st = Image.open("stamp.png").convert("RGBA")
                st.thumbnail((160, 160))
                image.paste(st, (line_x_end - 180, y_sig_base - 40), st)
        except: pass

    pdf_buffer = io.BytesIO()
    image.save(pdf_buffer, format='PDF')
    return pdf_buffer.getvalue()

# ---------------------------------------------------------
# Web UI
# ---------------------------------------------------------
def _current_display_name(request: Request):
    token = request.cookies.get("docmagic_session")
    if not token:
        return "Boss"
    row = _get_user_by_token(token)
    if row:
        expires_at = _parse_dt(row[5])
        if expires_at and expires_at < _now():
            return "Boss"
        return row[2] or row[1] or "Boss"
    return "Boss"


def _current_user_record(request: Request):
    token = request.cookies.get("docmagic_session")
    if not token:
        return None
    row = _get_user_by_token(token)
    if not row:
        return None
    expires_at = _parse_dt(row[5])
    if expires_at and expires_at < _now():
        return None
    return row


def _require_admin(request: Request):
    user = _current_user_record(request)
    if not user:
        raise HTTPException(status_code=303, detail="Redirect", headers={"Location": "/"})
    if (user[3] or "").lower() != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return user


def _require_admin_username(username: str = Depends(authenticate)):
    user = _get_user_by_username(username)
    if not user or not user[5]:
        raise HTTPException(status_code=403, detail="Admin only")
    if _normalize_role(user[4]) != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return username


def require_roles(*roles, allow_basic_auth: bool = False):
    allowed_roles = {_normalize_role(role) for role in roles}

    def _dep(request: Request, credentials: HTTPBasicCredentials = Depends(security)):
        user = _current_user_record(request)
        if not user and allow_basic_auth:
            user = _basic_auth_user(request)
        if not user and credentials and credentials.username and credentials.password:
            # Login flow is still handled separately; this branch keeps compatibility
            # with existing Basic Auth based internal calls.
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, username, password, display_name, role, is_active, failed_attempts, locked_until FROM app_users WHERE username=?",
                (credentials.username,),
            )
            row = cursor.fetchone()
            conn.close()
            if row and row[5] == 1:
                ok, _ = _verify_password(credentials.password, row[2])
                if ok:
                    user = row
        if not user:
            raise HTTPException(
                status_code=401,
                detail="Unauthorized",
                headers={"WWW-Authenticate": "Basic"},
            )
        if not _role_allowed(user[3], allowed_roles):
            raise HTTPException(status_code=403, detail="Forbidden")
        return user

    return _dep


def _render_login_page(error: str = ""):
    error_html = f'<div class="error">{html.escape(error)}</div>' if error else ""
    logo_html = f'<img src="/logo.png" alt="Di2da Dance School">' if (BASE_DIR / "logo.png").exists() else ""
    return f"""
    <html lang="zh-HK">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{APP_NAME} - 登入</title>
        <style>
            :root {{
                --bg1: #0f172a;
                --bg2: #111827;
                --panel: rgba(255,255,255,0.08);
                --panel-border: rgba(255,255,255,0.16);
                --text: #f8fafc;
                --muted: #cbd5e1;
                --accent: #d6b46d;
            }}
            * {{ box-sizing: border-box; }}
            body {{
                margin: 0;
                min-height: 100vh;
                font-family: -apple-system, BlinkMacSystemFont, "PingFang HK", "Noto Sans TC", sans-serif;
                color: var(--text);
                background:
                    radial-gradient(circle at top left, rgba(214,180,109,.24), transparent 28%),
                    radial-gradient(circle at bottom right, rgba(255,255,255,.08), transparent 24%),
                    linear-gradient(160deg, var(--bg1), var(--bg2));
                display: grid;
                place-items: center;
                padding: 24px;
            }}
            .wrap {{
                width: min(1080px, 100%);
                display: grid;
                grid-template-columns: 1.05fr .95fr;
                gap: 22px;
                align-items: stretch;
            }}
            .hero, .panel {{
                border: 1px solid var(--panel-border);
                border-radius: 28px;
                background: var(--panel);
                backdrop-filter: blur(18px);
                box-shadow: 0 28px 80px rgba(0,0,0,.24);
            }}
            .hero {{
                padding: 34px;
                display: flex;
                flex-direction: column;
                justify-content: space-between;
                min-height: 620px;
            }}
            .brand img {{
                display: block;
                max-width: 240px;
                width: 100%;
                background: rgba(255,255,255,.95);
                padding: 14px 18px;
                border-radius: 20px;
            }}
            .eyebrow {{
                color: var(--accent);
                letter-spacing: .22em;
                font-size: 12px;
                text-transform: uppercase;
                margin-bottom: 14px;
            }}
            h1 {{
                margin: 0;
                font-size: clamp(34px, 4vw, 58px);
                line-height: 1.02;
                letter-spacing: -0.04em;
            }}
            .lead {{
                margin: 18px 0 0;
                color: var(--muted);
                font-size: 16px;
                line-height: 1.8;
                max-width: 42ch;
            }}
            .chips {{
                display: flex;
                gap: 10px;
                flex-wrap: wrap;
                margin-top: 24px;
            }}
            .chip {{
                display: inline-flex;
                align-items: center;
                padding: 10px 14px;
                border-radius: 999px;
                background: rgba(255,255,255,.08);
                border: 1px solid rgba(255,255,255,.12);
                color: #fff;
                font-size: 12px;
            }}
            .panel {{
                padding: 30px;
            }}
            .panel h2 {{
                margin: 0 0 8px;
                font-size: 28px;
            }}
            .panel p {{
                margin: 0 0 22px;
                color: var(--muted);
                line-height: 1.7;
            }}
            .error {{
                margin-bottom: 16px;
                padding: 12px 14px;
                border-radius: 14px;
                background: rgba(248, 113, 113, .16);
                color: #fecaca;
                border: 1px solid rgba(248, 113, 113, .25);
            }}
            label {{
                display: block;
                margin: 14px 0 8px;
                color: #e5e7eb;
                font-size: 13px;
                letter-spacing: .02em;
            }}
            input {{
                width: 100%;
                padding: 14px 16px;
                border-radius: 14px;
                border: 1px solid rgba(255,255,255,.14);
                background: rgba(15,23,42,.56);
                color: #fff;
                outline: none;
                font-size: 15px;
            }}
            input:focus {{
                border-color: rgba(214,180,109,.8);
                box-shadow: 0 0 0 3px rgba(214,180,109,.18);
            }}
            button {{
                margin-top: 20px;
                width: 100%;
                border: 0;
                border-radius: 14px;
                padding: 14px 16px;
                background: linear-gradient(135deg, #d6b46d, #f4d89c);
                color: #111827;
                font-size: 16px;
                font-weight: 800;
                cursor: pointer;
            }}
            .foot {{
                margin-top: 14px;
                font-size: 12px;
                color: #94a3b8;
                line-height: 1.6;
            }}
            .announce-wrap {{
                margin-top: 18px;
                padding: 16px;
                border-radius: 20px;
                background: rgba(255,255,255,.07);
                border: 1px solid rgba(255,255,255,.10);
            }}
            .announce-title {{
                display: flex;
                justify-content: space-between;
                gap: 10px;
                align-items: baseline;
                margin-bottom: 12px;
            }}
            .announce-title h3 {{
                margin: 0;
                font-size: 18px;
            }}
            .announce-title span {{
                color: #cbd5e1;
                font-size: 12px;
            }}
            .announce-list {{
                display: grid;
                gap: 12px;
                max-height: 260px;
                overflow: auto;
                padding-right: 4px;
            }}
            .announce-card {{
                background: rgba(15,23,42,.52);
                border: 1px solid rgba(255,255,255,.10);
                border-radius: 18px;
                padding: 14px;
            }}
            .announce-meta {{
                display: flex;
                flex-wrap: wrap;
                gap: 8px;
                color: #cbd5e1;
                font-size: 11px;
                margin-bottom: 8px;
            }}
            .announce-tag {{
                display: inline-block;
                padding: 2px 8px;
                border-radius: 999px;
                background: rgba(214,180,109,.16);
                color: #f4d89c;
                font-weight: 700;
            }}
            .announce-card h4 {{
                margin: 0 0 6px;
                font-size: 15px;
                line-height: 1.4;
            }}
            .announce-card p {{
                margin: 0;
                color: #e5e7eb;
                line-height: 1.6;
                font-size: 13px;
            }}
            .announce-img {{
                display: block;
                width: 100%;
                margin-top: 10px;
                border-radius: 14px;
                border: 1px solid rgba(255,255,255,.10);
                background: rgba(255,255,255,.05);
            }}
            .announce-empty {{
                padding: 14px;
                border-radius: 16px;
                border: 1px dashed rgba(255,255,255,.14);
                color: #cbd5e1;
                background: rgba(255,255,255,.04);
            }}
            @media (max-width: 880px) {{
                .wrap {{ grid-template-columns: 1fr; }}
                .hero {{ min-height: auto; }}
            }}
        </style>
    </head>
    <body>
        <div class="wrap">
            <div class="hero">
                <div>
                    <div class="eyebrow">Di2da Admin</div>
                    <h1>軍團行政系統</h1>
                    <p class="lead">登入後可進入導師列表、班別列表、薪酬管理同軍團公告。發票系統只限 admin 使用。介面已預留多帳戶架構，之後可以逐步加入更多登入帳戶。</p>
                    <div class="chips">
                        <span class="chip">導師列表</span>
                        <span class="chip">班別列表</span>
                        <span class="chip">薪酬管理</span>
                        <span class="chip">軍團公告</span>
                    </div>
                    <div class="announce-wrap">
                        <div class="announce-title">
                            <h3>最新軍團公告</h3>
                            <span>登入前先睇更新</span>
                        </div>
                        <div class="announce-list">
                            {_render_public_announcements(3)}
                        </div>
                    </div>
                </div>
                <div class="brand">{logo_html}</div>
            </div>
            <div class="panel">
                <h2>登入</h2>
                <p>請輸入帳戶名稱同密碼以進入管理後台。</p>
                {error_html}
                <form action="/login" method="post">
                    <label for="username">登入帳戶</label>
                    <input id="username" name="username" autocomplete="username" required>
                    <label for="password">密碼</label>
                    <input id="password" name="password" type="password" autocomplete="current-password" required>
                    <button type="submit">登入系統</button>
                </form>
                <div class="foot">
                    系統已支援多帳戶模式，資料表可以輕鬆擴展到 10 個以上登入帳戶。
                </div>
            </div>
        </div>
    </body>
    </html>
    """


def _render_dashboard_page(request: Request):
    today = datetime.now().strftime("%Y年%m月%d日")
    display_name = _current_display_name(request)
    user = _current_user_record(request)
    role_label = "Guest"
    if user:
        role_value = _normalize_role(user[3])
        role_label = role_value.capitalize()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT COUNT(*) FROM app_users WHERE is_active=1")
        account_count = cursor.fetchone()[0]
    except Exception:
        account_count = 0
    try:
        cursor.execute("SELECT COUNT(*) FROM teachers WHERE is_active=1")
        teacher_count = cursor.fetchone()[0]
    except Exception:
        teacher_count = 0
    try:
        cursor.execute("SELECT COUNT(*) FROM school_classes WHERE is_active=1")
        class_count = cursor.fetchone()[0]
    except Exception:
        class_count = 0
    try:
        cursor.execute("SELECT COUNT(*) FROM common_clients")
        client_count = cursor.fetchone()[0]
    except Exception:
        client_count = 0
    try:
        cursor.execute("SELECT COUNT(*) FROM form_presets")
        preset_count = cursor.fetchone()[0]
    except Exception:
        preset_count = 0
    try:
        cursor.execute("SELECT COUNT(*) FROM announcements")
        announcement_count = cursor.fetchone()[0]
    except Exception:
        announcement_count = 0
    try:
        cursor.execute(
            "SELECT title, body, pinned, created_at FROM announcements ORDER BY pinned DESC, created_at DESC, id DESC LIMIT 3"
        )
        announcement_rows = cursor.fetchall()
    except Exception:
        announcement_rows = []
    conn.close()

    logo_html = f'<img src="/logo.png" alt="Di2da Dance School">' if (BASE_DIR / "logo.png").exists() else ""
    return f"""
    <html lang="zh-HK">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{APP_NAME} - 主選單</title>
        <style>
            :root {{
                --bg: #f5f1e8;
                --paper: #ffffff;
                --ink: #101114;
                --muted: #5f646d;
                --line: rgba(16,17,20,.10);
                --accent: #b89d5d;
                --accent-soft: #f4ead2;
            }}
            * {{ box-sizing: border-box; }}
            body {{
                margin: 0;
                font-family: -apple-system, BlinkMacSystemFont, "PingFang HK", "Noto Sans TC", sans-serif;
                background:
                    radial-gradient(circle at top right, rgba(184,157,93,.16), transparent 22%),
                    linear-gradient(135deg, #faf7f0 0%, #efe8d8 100%);
                color: var(--ink);
                padding: 22px;
            }}
            .shell {{ max-width: 1240px; margin: 0 auto; }}
            .hero {{
                display: flex;
                justify-content: space-between;
                gap: 18px;
                align-items: flex-end;
                flex-wrap: wrap;
                background: rgba(255,255,255,.88);
                border: 1px solid var(--line);
                border-radius: 28px;
                padding: 26px 28px;
                box-shadow: 0 20px 60px rgba(16,17,20,.08);
                margin-bottom: 18px;
            }}
            .hero h1 {{ margin: 0; font-size: 34px; letter-spacing: -0.03em; }}
            .hero p {{ margin: 8px 0 0; color: var(--muted); line-height: 1.7; }}
            .meta {{
                display: flex;
                gap: 10px;
                flex-wrap: wrap;
            }}
            .pill {{
                background: var(--accent-soft);
                color: #5b4a18;
                border-radius: 999px;
                padding: 9px 14px;
                font-size: 12px;
                font-weight: 700;
            }}
            .grid {{
                display: grid;
                grid-template-columns: repeat(12, minmax(0, 1fr));
                gap: 18px;
            }}
            .card {{
                grid-column: span 6;
                background: rgba(255,255,255,.92);
                border: 1px solid var(--line);
                border-radius: 24px;
                padding: 22px;
                box-shadow: 0 16px 40px rgba(16,17,20,.06);
            }}
            .card h3 {{ margin: 0 0 8px; font-size: 20px; }}
            .card p {{ margin: 0; color: var(--muted); line-height: 1.65; }}
            .stats {{
                display: grid;
                grid-template-columns: repeat(3, minmax(0, 1fr));
                gap: 14px;
                margin: 18px 0 0;
            }}
            .stat {{
                background: #fff;
                border: 1px solid var(--line);
                border-radius: 18px;
                padding: 16px;
            }}
            .stat .num {{ font-size: 26px; font-weight: 800; }}
            .stat .label {{ color: var(--muted); font-size: 12px; margin-top: 6px; }}
            .muted {{ color: var(--muted); font-size: 13px; line-height: 1.6; }}
            .links {{
                display: grid;
                grid-template-columns: repeat(2, minmax(0, 1fr));
                gap: 12px;
                margin-top: 16px;
            }}
            .link {{
                text-decoration: none;
                color: var(--ink);
                background: #fff;
                border: 1px solid var(--line);
                border-radius: 18px;
                padding: 18px;
                min-height: 118px;
                display: flex;
                flex-direction: column;
                justify-content: space-between;
                transition: transform .16s ease, box-shadow .16s ease, border-color .16s ease;
            }}
            .link:hover {{
                transform: translateY(-2px);
                box-shadow: 0 14px 30px rgba(16,17,20,.09);
                border-color: rgba(184,157,93,.55);
            }}
            .link strong {{ font-size: 18px; }}
            .link span {{ color: var(--muted); line-height: 1.5; margin-top: 8px; }}
            .top-logo img {{
                width: 180px;
                display: block;
                background: white;
                border-radius: 16px;
                padding: 10px 12px;
            }}
            .toolbar a {{
                display: inline-block;
                text-decoration: none;
                color: var(--ink);
                background: #fff;
                border: 1px solid var(--line);
                border-radius: 999px;
                padding: 10px 14px;
                font-size: 13px;
                margin-left: 8px;
            }}
            @media (max-width: 900px) {{
                .card {{ grid-column: span 12; }}
                .stats, .links {{ grid-template-columns: 1fr; }}
            }}
        </style>
    </head>
    <body>
        <div class="shell">
            <div class="hero">
                <div>
                    <div style="color: var(--accent); font-weight: 800; letter-spacing: .18em; text-transform: uppercase; font-size: 12px;">Welcome</div>
                    <h1>Hi, {html.escape(display_name)}</h1>
                    <p>今日係 {today}。你可以先揀功能模組，再進入導師、班別、薪酬同發票工作區。</p>
                </div>
                <div class="meta">
                    <span class="pill">{role_label}</span>
                    {'' if role_label == 'Admin' else '<span class="pill">發票系統已停用</span>'}
                </div>
                <div class="toolbar">
                    <a href="/logout">登出</a>
                    {"<a href='/admin/accounts'>帳戶管理</a>" if user and (user[3] or "").lower() == "admin" else ""}
                    <a href="/announcements">軍團公告</a>
                    {"<a href='/invoice/clients'>常用客戶</a>" if user and (user[3] or "").lower() == "admin" else ""}
                    {"<a href='/invoice'>發票系統</a>" if user and (user[3] or "").lower() == "admin" else ""}
                </div>
            </div>
            <div class="grid">
                <div class="card">
                    <h3>工作入口</h3>
                    <p>先揀你要處理嘅模組，再進入對應頁面。</p>
                    <div class="links">
                        <a class="link" href="/salary/teachers"><strong>導師列表</strong><span>查看各導師班數、狀態與薪酬詳情。</span></a>
                        <a class="link" href="/salary/classes"><strong>班別列表</strong><span>整理學校、星期、導師同時薪資料。</span></a>
                        <a class="link" href="/salary"><strong>薪酬管理</strong><span>查看薪酬總覽、匯入資料與計算記錄。</span></a>
                        <a class="link" href="/announcements"><strong>軍團公告</strong><span>查看最新通知、時間表同內部消息。</span></a>
                        {f'<a class="link" href="/invoice"><strong>發票系統</strong><span>生成報價單、發票、收據同常用範本。</span></a>' if user and (user[3] or "").lower() == "admin" else '<div class="link" style="opacity:.55; pointer-events:none;"><strong>發票系統</strong><span>只限 admin 使用。</span></div>'}
                    </div>
                </div>
                <div class="card">
                    <h3>系統概覽</h3>
                    <p>現有架構已預留多帳戶登入能力，並已將發票系統限制為 admin 使用。</p>
                    <div class="stats">
                        <div class="stat"><div class="num">{account_count}</div><div class="label">登入帳戶</div></div>
                        <div class="stat"><div class="num">{teacher_count}</div><div class="label">導師</div></div>
                        <div class="stat"><div class="num">{class_count}</div><div class="label">班別</div></div>
                        <div class="stat"><div class="num">{client_count}</div><div class="label">常用客戶</div></div>
                        <div class="stat"><div class="num">{preset_count}</div><div class="label">文件範本</div></div>
                        <div class="stat"><div class="num">{announcement_count}</div><div class="label">公告</div></div>
                    </div>
                    <div style="margin-top:18px;" class="top-logo">{logo_html}</div>
                </div>
                <div class="card">
                    <h3>最新公告</h3>
                    <p>由「軍團公告」版面同步到主選單，方便快速查看。</p>
                    <div class="list">
                        {''.join([
                            f"<div style='padding:14px 0;border-bottom:1px solid #e5e7eb;'><strong>{html.escape(r[0])}</strong><div style='color:#6b7280;font-size:12px;margin-top:4px;'>{'置頂' if r[2] else '公告'} · {html.escape(r[3] or '')}</div><div style='margin-top:8px;line-height:1.7;white-space:pre-wrap;'>{html.escape(r[1])}</div></div>"
                            for r in announcement_rows
                        ]) or '<div class="muted">暫時未有公告。</div>'}
                    </div>
                    <div class="hint" style="margin-top:12px;">
                        需要發佈新公告可以去 <a href="/announcements">軍團公告版面</a>。
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    """


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    if _current_user_record(request):
        return HTMLResponse(_render_dashboard_page(request))
    return HTMLResponse(_render_login_page())


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if _current_user_record(request):
        return RedirectResponse("/dashboard", status_code=303)
    return HTMLResponse(_render_login_page())


@app.post("/login")
async def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password, display_name, role, is_active, failed_attempts, locked_until FROM app_users WHERE username=?", (username.strip(),))
    row = cursor.fetchone()
    if not row or row[5] != 1:
        conn.close()
        return HTMLResponse(_render_login_page("帳戶名稱或密碼唔正確"), status_code=401)
    locked_until = _parse_dt(row[7])
    if locked_until and locked_until > _now():
        conn.close()
        return HTMLResponse(_render_login_page("帳戶暫時鎖定，請稍後再試"), status_code=423)
    ok, new_hash = _verify_password(password, row[2])
    if not ok:
        failed_attempts = (row[6] or 0) + 1
        lock_until = _lock_until(LOCK_DURATION_MINUTES) if failed_attempts >= LOCK_THRESHOLD else None
        cursor.execute(
            "UPDATE app_users SET failed_attempts=?, locked_until=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (failed_attempts if failed_attempts < LOCK_THRESHOLD else 0, lock_until, row[0]),
        )
        conn.commit()
        conn.close()
        return HTMLResponse(_render_login_page("帳戶名稱或密碼唔正確"), status_code=401)
    if new_hash:
        cursor.execute(
            "UPDATE app_users SET password=?, failed_attempts=0, locked_until=NULL, password_updated_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (new_hash, row[0]),
        )
    else:
        cursor.execute(
            "UPDATE app_users SET failed_attempts=0, locked_until=NULL, updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (row[0],),
        )
    token = secrets.token_hex(24)
    cursor.execute(
        "INSERT OR REPLACE INTO app_sessions (token, username, display_name, expires_at, last_seen) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
        (token, row[1], row[3] or row[1], _session_expires_at()),
    )
    conn.commit()
    conn.close()
    response = RedirectResponse("/dashboard", status_code=303)
    response.set_cookie("docmagic_session", token, httponly=True, samesite="lax", max_age=SESSION_TTL_HOURS * 3600)
    return response


@app.get("/logout")
async def logout(request: Request):
    token = request.cookies.get("docmagic_session")
    if token:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM app_sessions WHERE token=?", (token,))
        conn.commit()
        conn.close()
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie("docmagic_session")
    return response


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    if not _current_user_record(request):
        return RedirectResponse("/", status_code=303)
    return HTMLResponse(_render_dashboard_page(request))


def _render_accounts_page(request: Request, notice: str = ""):
    user = _require_admin(request)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, username, display_name, role, is_active, failed_attempts, locked_until, updated_at
        FROM app_users
        ORDER BY CASE WHEN role='admin' THEN 0 ELSE 1 END, username
    """)
    rows = cursor.fetchall()
    conn.close()

    extra_notice = ""
    if DB_IS_EPHEMERAL:
        extra_notice = "目前仍係暫存模式；要電話同電腦永久共用，請將 `DOCMAGIC_DB_PATH` 指去有持久磁碟的位置。"
    merged_notice = " ".join(part for part in [notice, extra_notice] if part).strip()
    notice_html = f'<div class="notice">{html.escape(merged_notice)}</div>' if merged_notice else ""
    row_html = ""
    for r in rows:
        status = "啟用" if r[4] else "停用"
        lock_text = f" | 鎖定至 {html.escape(r[6])}" if r[6] else ""
        row_html += f"""
        <tr>
            <td><strong>{html.escape(r[1])}</strong></td>
            <td>{html.escape(r[2] or r[1])}</td>
            <td><span class="badge">{html.escape(r[3] or 'staff')}</span></td>
            <td>{status}{lock_text}</td>
            <td>{r[5] or 0}</td>
            <td>{html.escape(r[7] or '')}</td>
            <td>
                <form class="inline" action="/admin/accounts/{r[0]}/toggle" method="post">
                    <button type="submit">{'停用' if r[4] else '啟用'}</button>
                </form>
                <form class="inline" action="/admin/accounts/{r[0]}/reset-password" method="post">
                    <input name="password" type="text" placeholder="新密碼">
                    <button type="submit">重設密碼</button>
                </form>
            </td>
        </tr>
        """

    return f"""
    <html lang="zh-HK">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{APP_NAME} - 帳戶管理</title>
        <style>
            body {{
                margin: 0;
                font-family: -apple-system, BlinkMacSystemFont, "PingFang HK", "Noto Sans TC", sans-serif;
                background: linear-gradient(135deg, #faf7f0 0%, #efe8d8 100%);
                color: #111;
                padding: 22px;
            }}
            .shell {{ max-width: 1180px; margin: 0 auto; }}
            .topbar {{
                display: flex; justify-content: space-between; gap: 12px; align-items: center; flex-wrap: wrap;
                padding: 20px 22px; background: rgba(255,255,255,.92); border: 1px solid rgba(17,24,39,.08); border-radius: 22px; margin-bottom: 18px;
            }}
            .topbar a {{
                text-decoration: none; color: #111; background: #fff; border: 1px solid #ddd; border-radius: 999px; padding: 10px 14px;
            }}
            .card {{
                background: rgba(255,255,255,.94); border: 1px solid rgba(17,24,39,.08); border-radius: 22px; padding: 22px; box-shadow: 0 14px 40px rgba(17,24,39,.06);
            }}
            h1, h2 {{ margin: 0 0 10px; }}
            .notice {{ margin-bottom: 14px; padding: 12px 14px; border-radius: 14px; background: #f4ead2; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
            th, td {{ padding: 12px 10px; border-bottom: 1px solid #e5e7eb; vertical-align: top; text-align: left; }}
            th {{ font-size: 12px; text-transform: uppercase; letter-spacing: .08em; color: #6b7280; }}
            .badge {{ display: inline-block; padding: 4px 10px; border-radius: 999px; background: #f4ead2; font-size: 12px; }}
            .grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }}
            label {{ display:block; font-size: 12px; font-weight: 700; margin: 4px 0 6px; }}
            input, select {{ width: 100%; padding: 12px 13px; border: 1px solid #d1d5db; border-radius: 12px; }}
            button {{ padding: 10px 12px; border-radius: 12px; border: 1px solid #d1d5db; background: #111; color: #fff; cursor: pointer; }}
            .inline {{ display: inline-flex; gap: 8px; align-items: center; margin: 0 8px 8px 0; }}
            .inline input {{ width: 170px; }}
            .actions {{ margin-top: 14px; display: flex; gap: 10px; flex-wrap: wrap; }}
            .muted {{ color: #6b7280; font-size: 13px; line-height: 1.6; }}
            .stats {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-bottom: 16px; }}
            .stat {{ background: #fff; border: 1px solid #e5e7eb; border-radius: 18px; padding: 16px; }}
            .stat .num {{ font-size: 24px; font-weight: 800; }}
            .stat .label {{ color: #6b7280; font-size: 12px; margin-top: 4px; }}
            @media (max-width: 900px) {{
                .grid, .stats {{ grid-template-columns: 1fr; }}
            }}
        </style>
    </head>
    <body>
        <div class="shell">
            <div class="topbar">
                <div>
                    <div class="muted">Admin only</div>
                    <h1>帳戶管理</h1>
                </div>
                <div>
                    <a href="/dashboard">返回主選單</a>
                    <a href="/invoice">發票系統</a>
                </div>
            </div>
            <div class="stats">
                <div class="stat"><div class="num">{len(rows)}</div><div class="label">總帳戶</div></div>
                <div class="stat"><div class="num">{sum(1 for r in rows if r[3]=='admin')}</div><div class="label">Admin</div></div>
                <div class="stat"><div class="num">{sum(1 for r in rows if r[4])}</div><div class="label">啟用中</div></div>
                <div class="stat"><div class="num">{sum(1 for r in rows if not r[4])}</div><div class="label">停用</div></div>
            </div>
            <div class="card">
                <h2>新增帳戶</h2>
                <p class="muted">支援 10 個以上帳戶。建議每個使用者用獨立登入，便於審計同停用。</p>
                {notice_html}
                <form action="/admin/accounts/create" method="post">
                    <div class="grid">
                        <div><label>登入帳戶</label><input name="username" required></div>
                        <div><label>顯示名稱</label><input name="display_name" required></div>
                        <div><label>密碼</label><input name="password" type="text" required></div>
                        <div><label>角色</label>
                            <select name="role">
                                <option value="admin">admin</option>
                                <option value="manager">manager</option>
                                <option value="finance">finance</option>
                                <option value="tutor">tutor</option>
                            </select>
                        </div>
                    </div>
                    <div class="actions"><button type="submit">建立帳戶</button></div>
                </form>
                <table>
                    <thead><tr><th>帳戶</th><th>顯示名</th><th>角色</th><th>狀態</th><th>失敗次數</th><th>更新</th><th>操作</th></tr></thead>
                    <tbody>{row_html}</tbody>
                </table>
            </div>
        </div>
    </body>
    </html>
    """


def _get_recent_announcements(limit: int = 5):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, title, body, pinned, created_by, image_filename, image_mime, image_blob, created_at
        FROM announcements
        ORDER BY pinned DESC, created_at DESC, id DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


def _render_announcements_page(request: Request, notice: str = ""):
    user = _current_user_record(request)
    is_admin = bool(user and _normalize_role(user[3]) == "admin")
    rows = _get_recent_announcements(20)
    notice_html = f'<div class="notice">{html.escape(notice)}</div>' if notice else ""
    items_html = ""
    for r in rows:
        delete_html = ""
        if is_admin:
            delete_html = f"""
            <form class="inline" action="/announcements/{r[0]}/delete" method="post" style="margin-top:12px;">
                <button type="submit">刪除</button>
            </form>
            """
        img_html = ""
        if r[7]:
            mime = html.escape(r[6] or "image/png")
            alt = html.escape(r[5] or "announcement image")
            img_data = base64.b64encode(r[7]).decode("ascii")
            img_html = f'<div style="margin-top:14px;"><img src="data:{mime};base64,{img_data}" alt="{alt}" style="max-width:100%;border-radius:16px;border:1px solid #e5e7eb;display:block;"></div>'
        items_html += f"""
        <article class="item">
            <div class="meta">
                <span class="tag">{'置頂' if r[3] else '公告'}</span>
                <span>{html.escape(r[4] or 'system')}</span>
                <span>{html.escape(r[8] or '')}</span>
            </div>
            <h3>{html.escape(r[1])}</h3>
            <p>{html.escape(r[2]).replace(chr(10), '<br>')}</p>
            {img_html}
            {delete_html}
        </article>
        """
    form_html = ""
    if is_admin:
        form_html = """
            <div class="card">
                <h2>新增公告</h2>
                <form action="/announcements" method="post" enctype="multipart/form-data">
                    <div class="grid">
                        <div><label>標題</label><input name="title" required></div>
                        <div><label>置頂</label>
                            <select name="pinned">
                                <option value="0">否</option>
                                <option value="1">是</option>
                            </select>
                        </div>
                    </div>
                    <label>內容</label>
                    <textarea name="body" rows="6" required></textarea>
                    <label style="margin-top:12px;">上載圖片（PNG / JPEG）</label>
                    <input type="file" name="image" accept="image/png,image/jpeg">
                    <div class="hint">支援單張圖片，會直接顯示喺公告卡片。</div>
                    <div class="actions"><button type="submit">發佈公告</button></div>
                </form>
            </div>
        """
    return f"""
    <html lang="zh-HK">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{APP_NAME} - 軍團公告</title>
        <style>
            body {{
                margin: 0;
                font-family: -apple-system, BlinkMacSystemFont, "PingFang HK", "Noto Sans TC", sans-serif;
                background: linear-gradient(135deg, #faf7f0 0%, #efe8d8 100%);
                color: #111;
                padding: 22px;
            }}
            .shell {{ max-width: 1180px; margin: 0 auto; }}
            .topbar {{
                display:flex; justify-content:space-between; gap:12px; align-items:center; flex-wrap:wrap;
                padding:20px 22px; background:rgba(255,255,255,.92); border:1px solid rgba(17,24,39,.08); border-radius:22px; margin-bottom:18px;
            }}
            .topbar a {{ text-decoration:none; color:#111; background:#fff; border:1px solid #ddd; border-radius:999px; padding:10px 14px; }}
            .notice {{ margin-bottom: 14px; padding: 12px 14px; border-radius: 14px; background: #f4ead2; }}
            .grid {{ display:grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }}
            .card {{ background:rgba(255,255,255,.94); border:1px solid rgba(17,24,39,.08); border-radius:22px; padding:22px; box-shadow:0 14px 40px rgba(17,24,39,.06); }}
            label {{ display:block; font-size:12px; font-weight:700; margin:4px 0 6px; }}
            input, select, textarea {{ width:100%; padding:12px 13px; border:1px solid #d1d5db; border-radius:12px; }}
            textarea {{ resize: vertical; }}
            button {{ padding:10px 12px; border-radius:12px; border:1px solid #d1d5db; background:#111; color:#fff; cursor:pointer; }}
            .actions {{ margin-top: 14px; display:flex; gap:10px; flex-wrap:wrap; }}
            .list {{ display:grid; gap:14px; }}
            .item {{ background:#fff; border:1px solid #e5e7eb; border-radius:18px; padding:18px; }}
            .item h3 {{ margin: 8px 0 8px; font-size: 18px; }}
            .item p {{ margin: 0; line-height: 1.8; white-space: pre-wrap; }}
            .meta {{ display:flex; gap:8px; flex-wrap:wrap; color:#6b7280; font-size:12px; }}
            .tag {{ display:inline-block; padding:2px 8px; border-radius:999px; background:#f4ead2; color:#111; font-weight:700; }}
            @media (max-width: 900px) {{ .grid {{ grid-template-columns: 1fr; }} }}
        </style>
    </head>
    <body>
        <div class="shell">
            <div class="topbar">
                <div>
                    <div style="color:#6b7280;font-size:12px;">Gang notice board</div>
                    <h1 style="margin:0;">軍團公告版面</h1>
                </div>
                <div>
                    <a href="/dashboard">返回主選單</a>
                    <a href="/login">登入頁</a>
                </div>
            </div>
            {notice_html}
            <div class="grid">
                <div class="card">
                    <h2 style="margin-top:0;">最新公告</h2>
                    <div class="list">{items_html or '<p class="muted">暫時未有公告。</p>'}</div>
                </div>
                {form_html}
            </div>
        </div>
    </body>
    </html>
    """


@app.get("/admin/accounts", response_class=HTMLResponse)
async def admin_accounts(request: Request):
    _require_admin(request)
    return HTMLResponse(_render_accounts_page(request))


@app.post("/admin/accounts/create")
async def admin_accounts_create(
    request: Request,
    username: str = Form(...),
    display_name: str = Form(...),
    password: str = Form(...),
    role: str = Form("staff"),
):
    _require_admin(request)
    username = username.strip()
    display_name = display_name.strip()
    role = _normalize_role(role or "tutor")
    if role not in {"admin", "manager", "finance", "tutor"}:
        role = "tutor"
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO app_users (username, password, display_name, role, is_active, failed_attempts, password_updated_at, updated_at) VALUES (?, ?, ?, ?, 1, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
            (username, _hash_password(password), display_name, role),
        )
        conn.commit()
        notice = f"已建立帳戶：{username}"
    except sqlite3.IntegrityError:
        notice = "帳戶名稱已存在"
    conn.close()
    return HTMLResponse(_render_accounts_page(request, notice))


@app.post("/admin/accounts/{user_id}/toggle")
async def admin_accounts_toggle(request: Request, user_id: int):
    _require_admin(request)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE app_users SET is_active = CASE WHEN is_active=1 THEN 0 ELSE 1 END, updated_at=CURRENT_TIMESTAMP WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return RedirectResponse("/admin/accounts", status_code=303)


@app.post("/admin/accounts/{user_id}/reset-password")
async def admin_accounts_reset_password(request: Request, user_id: int, password: str = Form(...)):
    _require_admin(request)
    password = password.strip()
    if not password:
        return HTMLResponse(_render_accounts_page(request, "密碼不可留空"))
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE app_users SET password=?, failed_attempts=0, locked_until=NULL, password_updated_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE id=?",
        (_hash_password(password), user_id),
    )
    conn.commit()
    conn.close()
    return RedirectResponse("/admin/accounts", status_code=303)


@app.get("/invoice", response_class=HTMLResponse)
async def invoice_home(username: str = Depends(_require_admin_username)):
    today = datetime.now().strftime("%Y年%m月%d日")
    logo_html = '<div style="text-align:center; margin-bottom:40px;"><img src="/logo.png" style="max-width:220px; background:white; padding:10px; border-radius:4px;"></div>' if (BASE_DIR / "logo.png").exists() else ""
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT doc_no, doc_type, client, total_amount FROM records ORDER BY created_at DESC LIMIT 5")
        recent_rows = cursor.fetchall()
    except:
        recent_rows = []
    try:
        cursor.execute("SELECT id, name, updated_at FROM form_presets ORDER BY updated_at DESC, id DESC")
        preset_rows = cursor.fetchall()
    except:
        preset_rows = []
    try:
        cursor.execute("SELECT id, name, client_name, project_name, doc_type, category, notes, updated_at FROM common_clients ORDER BY updated_at DESC, id DESC")
        common_client_rows = cursor.fetchall()
    except:
        common_client_rows = []
    conn.close()
    common_client_rows = _unique_common_client_rows(common_client_rows)

    history_html = "".join([f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td><td>${r[3]:,.2f}</td></tr>" for r in recent_rows])
    preset_options_html = '<option value="">— 選擇已儲存範本 —</option>' + "".join(
        [f'<option value="{r[0]}">{html.escape(r[1])}（{html.escape(r[2] or "")}）</option>' for r in preset_rows]
    )
    common_client_options_html = _render_common_client_option_groups(common_client_rows)
    common_clients_json = json.dumps(
        [
            {
                "id": r[0],
                "name": r[1],
                "client_name": r[2],
                "project_name": r[3],
                "doc_type": r[4],
                "category": r[5],
                "notes": r[6],
                "updated_at": r[7],
            }
            for r in common_client_rows
        ],
        ensure_ascii=False,
    ).replace("</", "<\\/")

    return f"""
    <html>
        <head>
            <title>{APP_NAME}</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                :root {{
                    --bg: #f3f4f6;
                    --paper: #ffffff;
                    --ink: #111111;
                    --muted: #6b7280;
                    --line: #d1d5db;
                    --accent: #111111;
                    --accent-soft: #eef0f2;
                    --gold: #b89d5d;
                }}
                * {{ box-sizing: border-box; }}
                body {{
                    margin: 0;
                    font-family: -apple-system, BlinkMacSystemFont, "PingFang HK", "Microsoft JhengHei", sans-serif;
                    background:
                        radial-gradient(circle at top left, rgba(185,157,93,.10), transparent 28%),
                        linear-gradient(135deg, #fafafa 0%, #f1f3f5 100%);
                    color: var(--ink);
                    padding: 24px;
                }}
                .shell {{ max-width: 1320px; margin: 0 auto; }}
                .hero {{
                    background: rgba(255,255,255,.92);
                    border: 1px solid rgba(17,24,39,.08);
                    border-radius: 28px;
                    box-shadow: 0 20px 60px rgba(17,24,39,.06);
                    padding: 28px 30px;
                    margin-bottom: 18px;
                }}
                .hero-top {{
                    display: flex;
                    gap: 18px;
                    align-items: center;
                    justify-content: space-between;
                    flex-wrap: wrap;
                }}
                .hero h1 {{ margin: 0; font-size: 28px; font-weight: 800; letter-spacing: -0.03em; }}
                .hero p {{ margin: 8px 0 0; color: var(--muted); line-height: 1.6; }}
                .hero-badges {{ display: flex; gap: 10px; flex-wrap: wrap; }}
                .badge {{
                    display: inline-flex;
                    align-items: center;
                    gap: 8px;
                    padding: 9px 14px;
                    border-radius: 999px;
                    background: var(--accent-soft);
                    color: var(--accent);
                    font-size: 12px;
                    font-weight: 700;
                }}
                .grid {{
                    display: grid;
                    grid-template-columns: repeat(12, minmax(0, 1fr));
                    gap: 18px;
                }}
                .card {{
                    background: rgba(255,255,255,.92);
                    padding: 26px;
                    border-radius: 24px;
                    border: 1px solid rgba(17,24,39,.08);
                    box-shadow: 0 18px 50px rgba(17,24,39,.05);
                }}
                .span-8 {{ grid-column: span 8; }}
                .span-4 {{ grid-column: span 4; }}
                .section-title {{ font-size: 16px; margin: 0 0 14px; color: var(--accent); font-weight: 800; }}
                .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }}
                label {{ color: #6b7280; font-size: 11px; letter-spacing: 2px; text-transform: uppercase; display: block; margin-bottom: 5px; }}
                input, select, textarea {{ width: 100%; padding: 12px; background: #ffffff; border: 1px solid #d1d5db; color: #111111; border-radius: 10px; box-sizing: border-box; }}
                input::placeholder, textarea::placeholder {{ color: #9ca3af; }}
                textarea {{ resize: vertical; min-height: 56px; line-height: 1.5; }}
                .item-row {{ border: 1px solid #d1d5db; padding: 15px; margin-bottom: 10px; background: #fafafa; border-radius: 12px; }}
                .add-btn {{ background: none; color: #b89d5d; border: 1px solid #b89d5d; padding: 10px 20px; cursor: pointer; margin-bottom: 20px; border-radius: 999px; }}
                .preset-bar {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; align-items: start; margin-bottom: 20px; padding: 15px; border: 1px solid #d1d5db; border-radius: 16px; background: #f8fafc; }}
                .preset-block {{ display: flex; flex-direction: column; gap: 8px; min-width: 0; }}
                .preset-actions {{ display: flex; gap: 10px; margin-top: 2px; flex-wrap: wrap; }}
                .preset-actions > button {{ flex: 1 1 140px; min-width: 0; }}
                .preset-bar button {{ width: 100%; padding: 11px 14px; border-radius: 10px; border: 1px solid #d1d5db; background: #ffffff; color: #111111; cursor: pointer; }}
                .preset-bar button.primary {{ background: #b89d5d; color: #111111; border-color: #b89d5d; font-weight: 800; }}
                .preset-bar button.danger {{ border-color: #d1d5db; color: #6b7280; }}
                .client-bar {{ display: grid; grid-template-columns: minmax(0, 1.15fr) minmax(0, 1fr); gap: 20px; align-items: stretch; margin-bottom: 20px; padding: 15px; border: 1px solid #d1d5db; border-radius: 16px; background: #fcfcfb; }}
                .client-actions {{ display: flex; gap: 10px; margin-top: 2px; flex-wrap: wrap; }}
                .client-actions > button {{ flex: 1 1 120px; min-width: 0; }}
                .client-picker {{ display: grid; gap: 12px; }}
                .client-group {{
                    border: 1px solid #d1d5db;
                    border-radius: 18px;
                    background: #ffffff;
                    padding: 14px;
                }}
                .client-group-head {{
                    display: flex;
                    justify-content: space-between;
                    align-items: flex-end;
                    gap: 12px;
                    margin-bottom: 12px;
                }}
                .client-group-kicker {{
                    font-size: 11px;
                    font-weight: 800;
                    letter-spacing: .18em;
                    color: #9ca3af;
                    text-transform: uppercase;
                }}
                .client-group-title {{ font-size: 15px; font-weight: 800; color: #111111; margin-top: 4px; }}
                .client-card-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                    gap: 10px;
                }}
                .client-card {{
                    appearance: none;
                    text-align: left;
                    border: 1px solid #d1d5db;
                    border-radius: 14px;
                    background: #f8fafc;
                    padding: 12px 13px;
                    cursor: pointer;
                    color: #111111;
                    min-height: 84px;
                    display: flex;
                    flex-direction: column;
                    gap: 8px;
                    justify-content: space-between;
                    transition: transform .14s ease, box-shadow .14s ease, border-color .14s ease, background .14s ease;
                }}
                .client-card:hover {{
                    transform: translateY(-1px);
                    border-color: #b89d5d;
                    box-shadow: 0 10px 20px rgba(17,24,39,.07);
                }}
                .client-card.active {{
                    border-color: #b89d5d;
                    background: #fff8e8;
                    box-shadow: 0 0 0 3px rgba(184,157,93,.16);
                }}
                .client-card-title {{ font-size: 14px; font-weight: 800; line-height: 1.45; }}
                .client-card-sub {{ font-size: 12px; color: #6b7280; line-height: 1.5; }}
                .hint {{ font-size: 12px; color: #6b7280; margin-top: 6px; line-height: 1.4; }}
                button[type="submit"] {{ width: 100%; padding: 18px; background: #b89d5d; color: #111111; border: none; font-weight: 800; cursor: pointer; border-radius: 12px; font-size: 16px; }}
                table {{ width: 100%; margin-top: 40px; border-collapse: collapse; font-size: 13px; }}
                th {{ color: #6b7280; text-align: left; padding: 10px; border-bottom: 2px solid #d1d5db; }}
                td {{ padding: 10px; border-bottom: 1px solid #e5e7eb; }}
                .quick-links {{
                    display: grid;
                    grid-template-columns: repeat(2, minmax(0, 1fr));
                    gap: 12px;
                }}
                .quick-links a {{
                    display: block;
                    text-decoration: none;
                    color: var(--ink);
                    background: white;
                    border: 1px solid var(--line);
                    border-radius: 18px;
                    padding: 16px;
                    transition: transform .15s ease, box-shadow .15s ease, border-color .15s ease;
                }}
                .quick-links a:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 12px 24px rgba(17,24,39,.08);
                    border-color: #c4b18a;
                }}
                .quick-links strong {{ display: block; margin-bottom: 6px; }}
                @media (max-width: 980px) {{
                    .span-8, .span-4 {{ grid-column: span 12; }}
                }}
                @media (max-width: 720px) {{
                    body {{ padding: 14px; }}
                    .hero, .card {{ padding: 18px; border-radius: 20px; }}
                    .quick-links {{ grid-template-columns: 1fr; }}
                    .client-bar,
                    .preset-bar {{
                        grid-template-columns: 1fr;
                    }}
                }}
            </style>
            <script>
                const DRAFT_KEY = 'docmagic_draft_v2';
                const COMMON_CLIENTS_KEY = 'docmagic_common_clients_v1';
                const SERVER_COMMON_CLIENTS = {common_clients_json};

                function escapeHtml(value) {{
                    return String(value ?? '')
                        .replaceAll('&', '&amp;')
                        .replaceAll('<', '&lt;')
                        .replaceAll('>', '&gt;')
                        .replaceAll('"', '&quot;')
                        .replaceAll("'", '&#39;');
                }}

                function readCommonClients() {{
                    try {{
                        const raw = localStorage.getItem(COMMON_CLIENTS_KEY);
                        const parsed = raw ? JSON.parse(raw) : [];
                        return Array.isArray(parsed) ? parsed : [];
                    }} catch (e) {{
                        return [];
                    }}
                }}

                function writeCommonClients(list) {{
                    try {{
                        localStorage.setItem(COMMON_CLIENTS_KEY, JSON.stringify(Array.isArray(list) ? list : []));
                    }} catch (e) {{}}
                }}

                function normalizeCommonClient(item) {{
                    if (!item) return null;
                    const normalized = {{
                        id: item.id ?? null,
                        name: (item.name || '').trim(),
                        client_name: item.client_name || '',
                        project_name: item.project_name || '',
                        doc_type: item.doc_type || '報價單',
                        category: item.category || '',
                        notes: item.notes || '',
                        updated_at: item.updated_at || ''
                    }};
                    return normalized.name ? normalized : null;
                }}

                function normalizeCommonClientName(value) {{
                    return String(value ?? '')
                        .normalize('NFKC')
                        .replaceAll('⻘', '青')
                        .replace(/\s+/g, '')
                        .trim()
                        .toLowerCase();
                }}

                function commonClientKey(item) {{
                    const normalized = normalizeCommonClient(item);
                    if (!normalized) return '';
                    return normalizeCommonClientName(normalized.name);
                }}

                function dedupeCommonClientList(list) {{
                    const map = new Map();
                    (Array.isArray(list) ? list : [])
                        .map(normalizeCommonClient)
                        .filter(Boolean)
                        .forEach((item) => {{
                            const key = commonClientKey(item);
                            if (!key) return;
                            const existing = map.get(key);
                            if (!existing) {{
                                map.set(key, item);
                                return;
                            }}
                            const existingScore = [
                                existing.category ? 1 : 0,
                                existing.notes ? 1 : 0,
                                existing.updated_at || '',
                                existing.id ?? 0,
                            ];
                            const itemScore = [
                                item.category ? 1 : 0,
                                item.notes ? 1 : 0,
                                item.updated_at || '',
                                item.id ?? 0,
                            ];
                            if (itemScore > existingScore) {{
                                map.set(key, item);
                            }}
                        }});
                    return Array.from(map.values());
                }}

                function mergeCommonClients(primary, fallback) {{
                    return dedupeCommonClientList([...(Array.isArray(fallback) ? fallback : []), ...(Array.isArray(primary) ? primary : [])]);
                }}

                function getCommonClientStore() {{
                    const server = Array.isArray(SERVER_COMMON_CLIENTS) ? SERVER_COMMON_CLIENTS.map(normalizeCommonClient).filter(Boolean) : [];
                    const local = readCommonClients().map(normalizeCommonClient).filter(Boolean);
                    const serverList = dedupeCommonClientList(server);
                    if (serverList.length) {{
                        writeCommonClients(serverList);
                        return serverList;
                    }}
                    const merged = mergeCommonClients(server, local);
                    if (merged.length) {{
                        writeCommonClients(merged);
                        return merged;
                    }}
                    return [];
                }}

                async function syncCommonClientsToServer() {{
                    const local = readCommonClients().map(normalizeCommonClient).filter(Boolean);
                    const server = dedupeCommonClientList(Array.isArray(SERVER_COMMON_CLIENTS) ? SERVER_COMMON_CLIENTS.map(normalizeCommonClient).filter(Boolean) : []);
                    if (!local.length) return;
                    const serverKeys = new Set(server.map(commonClientKey).filter(Boolean));
                    const missing = local.filter((item) => {{
                        const key = commonClientKey(item);
                        return key && !serverKeys.has(key);
                    }});
                    if (!missing.length) return;
                    await Promise.all(missing.map((item) => fetch('/api/common-clients', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        credentials: 'same-origin',
                        body: JSON.stringify(item)
                    }}).catch(() => null)));
                }}

                function upsertCommonClientLocal(item) {{
                    const normalized = normalizeCommonClient(item);
                    if (!normalized) return readCommonClients();
                    const list = dedupeCommonClientList(readCommonClients().map(normalizeCommonClient).filter(Boolean));
                    const idx = list.findIndex((entry) => commonClientKey(entry) === commonClientKey(normalized));
                    if (idx >= 0) {{
                        list[idx] = {{ ...list[idx], ...normalized }};
                    }} else {{
                        list.unshift(normalized);
                    }}
                    writeCommonClients(list);
                    return list;
                }}

                function removeCommonClientLocal(identifier) {{
                    const key = String(identifier ?? '').trim();
                    const canonical = normalizeCommonClientName(key);
                    const list = dedupeCommonClientList(readCommonClients().map(normalizeCommonClient).filter(Boolean)).filter((entry) => {{
                        return String(entry.id ?? '').trim() !== key && commonClientKey(entry) !== canonical;
                    }});
                    writeCommonClients(list);
                    return list;
                }}

                function renderCommonClientSelect(clients) {{
                    renderCommonClientPicker(clients);
                }}

                function hydrateCommonClients() {{
                    renderCommonClientPicker(getCommonClientStore());
                }}

                function addItem() {{
                    const container = document.getElementById('items-container');
                    const newRow = document.createElement('div');
                    newRow.className = 'item-row grid';
                    newRow.innerHTML = `
                        <div style="grid-column: span 2;"><label>摘要</label><textarea name="descs" rows="2" required></textarea></div>
                        <div><label>單價</label><input type="number" name="prices" value="900" required></div>
                        <div><label>數量</label><input type="number" name="qtys" value="21" required></div>
                        <button type="button" onclick="this.parentElement.remove()" style="grid-column:span 2; color:#da3633; background:none; border:none; cursor:pointer; text-decoration:underline;">移除</button>
                    `;
                    container.appendChild(newRow);
                }}

                function addItemFromData(item = {{}}) {{
                    const container = document.getElementById('items-container');
                    const newRow = document.createElement('div');
                    newRow.className = 'item-row grid';
                    newRow.innerHTML = `
                        <div style="grid-column: span 2;"><label>摘要</label><textarea name="descs" rows="2" required></textarea></div>
                        <div><label>單價</label><input type="number" name="prices" value="" required></div>
                        <div><label>數量</label><input type="number" name="qtys" value="" required></div>
                        <button type="button" onclick="this.parentElement.remove()" style="grid-column:span 2; color:#da3633; background:none; border:none; cursor:pointer; text-decoration:underline;">移除</button>
                    `;
                    newRow.querySelector('textarea[name="descs"]').value = item.desc || '';
                    newRow.querySelector('input[name="prices"]').value = item.price ?? '';
                    newRow.querySelector('input[name="qtys"]').value = item.qty ?? '';
                    container.appendChild(newRow);
                }}

                function collectFormData() {{
                    const items = Array.from(document.querySelectorAll('#items-container .item-row')).map(row => ({{
                        desc: row.querySelector('textarea[name="descs"]').value,
                        price: row.querySelector('input[name="prices"]').value,
                        qty: row.querySelector('input[name="qtys"]').value
                    }}));
                    return {{
                        doc_type: document.querySelector('select[name="doc_type"]').value,
                        date_str: document.querySelector('input[name="date_str"]').value,
                        common_client_name: document.getElementById('common_client_name').value,
                        preset_name: document.getElementById('preset_name').value,
                        client: document.querySelector('[name="client"]').value,
                        project: document.querySelector('[name="project"]').value,
                        doc_no: document.querySelector('[name="doc_no"]').value,
                        custom_remarks: document.querySelector('[name="custom_remarks"]').value,
                        with_sign: document.querySelector('[name="with_sign"]').checked,
                        common_client_selected_id: document.getElementById('common_client_selected_id')?.value || '',
                        items: items
                    }};
                }}

                function saveDraft() {{
                    try {{
                        localStorage.setItem(DRAFT_KEY, JSON.stringify(collectFormData()));
                    }} catch (e) {{}}
                }}

                function clearDraft() {{
                    localStorage.removeItem(DRAFT_KEY);
                    window.location.reload();
                }}

                function fillForm(data) {{
                    if (!data) return;
                    document.querySelector('select[name="doc_type"]').value = data.doc_type || '報價單';
                    document.querySelector('input[name="date_str"]').value = data.date_str || '{today}';
                    document.getElementById('common_client_name').value = data.common_client_name || '';
                    document.getElementById('preset_name').value = data.preset_name || '';
                    const selectedIdField = document.getElementById('common_client_selected_id');
                    if (selectedIdField) selectedIdField.value = data.common_client_selected_id || '';
                    document.querySelector('[name="client"]').value = data.client || '';
                    document.querySelector('[name="project"]').value = data.project || '';
                    document.querySelector('[name="doc_no"]').value = data.doc_no || '';
                    document.querySelector('[name="custom_remarks"]').value = data.custom_remarks || '';
                    document.querySelector('[name="with_sign"]').checked = data.with_sign !== false;
                    const container = document.getElementById('items-container');
                    container.innerHTML = '';
                    const items = Array.isArray(data.items) && data.items.length ? data.items : [{{}}];
                    items.forEach(item => addItemFromData(item));
                }}

                function restoreDraft() {{
                    try {{
                        const raw = localStorage.getItem(DRAFT_KEY);
                        if (!raw) return;
                        fillForm(JSON.parse(raw));
                    }} catch (e) {{}}
                }}

                async function loadPreset() {{
                    const presetId = document.getElementById('preset_select').value;
                    if (!presetId) return;
                    const res = await fetch(`/api/presets/${{presetId}}`, {{
                        credentials: 'same-origin'
                    }});
                    if (!res.ok) {{
                        alert('載入範本失敗');
                        return;
                    }}
                    const data = await res.json();
                    document.getElementById('preset_name').value = data.name || '';
                    fillForm(data.payload);
                    saveDraft();
                }}

                async function savePreset() {{
                    const name = document.getElementById('preset_name').value.trim();
                    if (!name) {{
                        alert('請先輸入範本名稱');
                        return;
                    }}
                    const payload = collectFormData();
                    const res = await fetch('/api/presets', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        credentials: 'same-origin',
                        body: JSON.stringify({{ name, payload }})
                    }});
                    if (!res.ok) {{
                        alert('儲存範本失敗');
                        return;
                    }}
                    saveDraft();
                    window.location.reload();
                }}

                async function deletePreset() {{
                    const presetId = document.getElementById('preset_select').value;
                    if (!presetId) {{
                        alert('請先選擇一個範本');
                        return;
                    }}
                    if (!confirm('確定刪除呢個範本？')) return;
                    const res = await fetch(`/api/presets/${{presetId}}`, {{
                        method: 'DELETE',
                        credentials: 'same-origin'
                    }});
                    if (!res.ok) {{
                        alert('刪除失敗');
                        return;
                    }}
                    localStorage.removeItem(DRAFT_KEY);
                    window.location.reload();
                }}

                function collectCommonClientData() {{
                    const activeCard = document.querySelector('[data-common-client-id].active');
                    return {{
                        name: document.getElementById('common_client_name').value.trim(),
                        client_name: document.querySelector('[name="client"]').value.trim(),
                        project_name: document.querySelector('[name="project"]').value.trim(),
                        doc_type: document.querySelector('select[name="doc_type"]').value,
                        category: activeCard?.dataset.commonClientCategory || '',
                        notes: document.querySelector('[name="custom_remarks"]').value.trim(),
                    }};
                }}

                function getSelectedCommonClientId() {{
                    return (document.getElementById('common_client_selected_id')?.value || '').trim();
                }}

                function setSelectedCommonClientId(clientId) {{
                    const selectedIdField = document.getElementById('common_client_selected_id');
                    const normalizedId = String(clientId || '').trim();
                    if (selectedIdField) selectedIdField.value = normalizedId;
                    document.querySelectorAll('[data-common-client-id]').forEach((button) => {{
                        button.classList.toggle('active', String(button.dataset.commonClientId || '') === normalizedId);
                    }});
                }}

                function inferCommonClientCategory(client) {{
                    const direct = String(client?.category || '').trim();
                    if (direct) return direct;
                    const projectName = String(client?.project_name || '').trim();
                    if (['小學', '中學', '特殊學校/群育學校', '幼稚園', 'NGO'].includes(projectName)) return projectName;
                    const notes = String(client?.notes || '').trim();
                    if (['小學', '中學', '特殊學校/群育學校', '幼稚園', 'NGO'].includes(notes)) return notes;
                    return '';
                }}

                function renderCommonClientPicker(clients) {{
                    const wrap = document.getElementById('common-client-picker');
                    if (!wrap) return;
                    const rows = Array.isArray(clients) ? clients.map(normalizeCommonClient).filter(Boolean) : [];
                    const order = (cat) => {{
                        if (cat === '小學') return 0;
                        if (cat === '中學') return 1;
                        if (cat === '特殊學校/群育學校') return 2;
                        if (cat === '幼稚園') return 3;
                        if (cat === 'NGO') return 4;
                        if (!cat) return 5;
                        return 99;
                    }};
                    const grouped = new Map();
                    const uncategorized = [];
                    [...rows].sort((a, b) => {{
                        const diff = order(inferCommonClientCategory(a)) - order(inferCommonClientCategory(b));
                        return diff || String(a.name || '').localeCompare(String(b.name || ''), 'zh-HK');
                    }}).forEach((client) => {{
                        const category = inferCommonClientCategory(client);
                        if (!category) {{
                            uncategorized.push(client);
                            return;
                        }}
                        if (!grouped.has(category)) grouped.set(category, []);
                        grouped.get(category).push(client);
                    }});
                    const selectedId = getSelectedCommonClientId();
                    const sections = [];
                    const categories = ['小學', '中學', '特殊學校/群育學校', '幼稚園', 'NGO']
                        .filter((category) => grouped.has(category))
                        .concat([...grouped.keys()].filter((category) => !['小學', '中學', '特殊學校/群育學校', '幼稚園', 'NGO'].includes(category)));
                    categories.forEach((category) => {{
                        const clientsInCategory = grouped.get(category) || [];
                        const cards = clientsInCategory.map((client) => {{
                            const id = String(client.id ?? client.name ?? '');
                            const title = client.client_name && client.client_name !== client.name
                                ? `${{escapeHtml(client.name)}}｜${{escapeHtml(client.client_name)}}`
                                : `${{escapeHtml(client.name)}}`;
                            const inferredCategory = inferCommonClientCategory(client) || category;
                            const metaBits = [];
                            if (client.project_name) metaBits.push(escapeHtml(client.project_name));
                            if (client.notes && client.notes !== inferredCategory) metaBits.push(escapeHtml(client.notes));
                            const activeClass = id === selectedId ? ' active' : '';
                            return `
                                <button type="button" class="client-card${{activeClass}}" data-common-client-id="${{escapeHtml(id)}}" data-common-client-name="${{escapeHtml(client.name)}}" data-common-client-category="${{escapeHtml(category)}}">
                                    <div class="client-card-title">${{title}}</div>
                                    <div class="client-card-sub">${{metaBits.length ? metaBits.join(' · ') : escapeHtml(inferredCategory)}}</div>
                                </button>
                            `;
                        }}).join('');
                        sections.push(`
                            <section class="client-group">
                                <div class="client-group-head">
                                    <div>
                                        <div class="client-group-kicker">${{escapeHtml(category)}}</div>
                                        <div class="client-group-title">${{clientsInCategory.length}} 個常用客戶</div>
                                    </div>
                                </div>
                                <div class="client-card-grid">${{cards}}</div>
                            </section>
                        `);
                    }});
                    if (uncategorized.length) {{
                        const cards = uncategorized.map((client) => {{
                            const id = String(client.id ?? client.name ?? '');
                            const title = client.client_name && client.client_name !== client.name
                                ? `${{escapeHtml(client.name)}}｜${{escapeHtml(client.client_name)}}`
                                : `${{escapeHtml(client.name)}}`;
                            const inferredCategory = inferCommonClientCategory(client);
                            const metaBits = [];
                            if (client.project_name) metaBits.push(escapeHtml(client.project_name));
                            if (client.notes) metaBits.push(escapeHtml(client.notes));
                            const activeClass = id === selectedId ? ' active' : '';
                            return `
                                <button type="button" class="client-card${{activeClass}}" data-common-client-id="${{escapeHtml(id)}}" data-common-client-name="${{escapeHtml(client.name)}}" data-common-client-category="">
                                    <div class="client-card-title">${{title}}</div>
                                    <div class="client-card-sub">${{metaBits.length ? metaBits.join(' · ') : (inferredCategory || '未分類 / 其他')}}</div>
                                </button>
                            `;
                        }}).join('');
                        sections.push(`
                            <section class="client-group">
                                <div class="client-group-head">
                                    <div>
                                        <div class="client-group-kicker">未分類 / 其他</div>
                                        <div class="client-group-title">${{uncategorized.length}} 個常用客戶</div>
                                    </div>
                                </div>
                                <div class="client-card-grid">${{cards}}</div>
                            </section>
                        `);
                    }}
                    wrap.innerHTML = sections.join('');
                    wrap.querySelectorAll('[data-common-client-id]').forEach((button) => {{
                        button.addEventListener('click', () => {{
                            setSelectedCommonClientId(button.dataset.commonClientId || '');
                            saveDraft();
                        }});
                    }});
                    setSelectedCommonClientId(selectedId);
                    const status = document.getElementById('common-client-selected-status');
                    if (status) {{
                        status.textContent = selectedId ? '已選擇一個常用客戶' : '未選擇';
                    }}
                }}

                async function loadCommonClient() {{
                    const clientId = getSelectedCommonClientId();
                    if (!clientId) return;
                    const res = await fetch(`/api/common-clients/${{clientId}}`, {{
                        credentials: 'same-origin'
                    }});
                    if (!res.ok) {{
                        alert('載入常用客戶失敗');
                        return;
                    }}
                    const data = await res.json();
                    document.getElementById('common_client_name').value = data.name || '';
                    document.querySelector('[name="client"]').value = data.client_name || '';
                    document.querySelector('[name="project"]').value = data.project_name || '';
                    document.querySelector('select[name="doc_type"]').value = data.doc_type || '報價單';
                    document.querySelector('[name="custom_remarks"]').value = data.notes || '';
                    upsertCommonClientLocal(data);
                    setSelectedCommonClientId(clientId);
                    hydrateCommonClients();
                    saveDraft();
                }}

                async function saveCommonClient() {{
                    const payload = collectCommonClientData();
                    if (!payload.name || !payload.client_name) {{
                        alert('請先輸入常用客戶名稱同客戶資料');
                        return;
                    }}
                    const localPayload = {{
                        ...payload,
                        id: payload.name,
                    }};
                    upsertCommonClientLocal(localPayload);
                    saveDraft();
                    hydrateCommonClients();
                    const res = await fetch('/api/common-clients', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        credentials: 'same-origin',
                        body: JSON.stringify(payload)
                    }});
                    if (!res.ok) {{
                        alert('儲存常用客戶失敗，但已先保存到本機');
                        window.location.reload();
                        return;
                    }}
                    const result = await res.json().catch(() => ({{}}));
                    upsertCommonClientLocal({{
                        ...payload,
                        id: result.id ?? payload.name,
                    }});
                    setSelectedCommonClientId(String(result.id ?? payload.name));
                    saveDraft();
                    hydrateCommonClients();
                    window.location.reload();
                }}

                async function deleteCommonClient() {{
                    const clientId = getSelectedCommonClientId();
                    if (!clientId) {{
                        alert('請先選擇一個常用客戶');
                        return;
                    }}
                    if (!confirm('確定刪除呢個常用客戶？')) return;
                    removeCommonClientLocal(clientId);
                    setSelectedCommonClientId('');
                    hydrateCommonClients();
                    const res = await fetch(`/api/common-clients/${{clientId}}`, {{
                        method: 'DELETE',
                        credentials: 'same-origin'
                    }});
                    if (!res.ok) {{
                        alert('刪除失敗，但已先從本機移除');
                        window.location.reload();
                        return;
                    }}
                    window.location.reload();
                }}

                function bindAutosave() {{
                    const form = document.querySelector('form[action="/generate"]');
                    form.addEventListener('input', saveDraft);
                    form.addEventListener('change', saveDraft);
                    document.getElementById('preset_name').addEventListener('input', saveDraft);
                    document.getElementById('preset_select').addEventListener('change', saveDraft);
                    document.getElementById('common_client_name').addEventListener('input', saveDraft);
                    const selectedIdField = document.getElementById('common_client_selected_id');
                    if (selectedIdField) selectedIdField.addEventListener('change', saveDraft);
                }}

                document.addEventListener('DOMContentLoaded', () => {{
                    restoreDraft();
                    hydrateCommonClients();
                    bindAutosave();
                    syncCommonClientsToServer().catch(() => {{}});
                }});
            </script>
        </head>
        <body>
            <div class="shell">
                <div class="hero">
                    <div class="hero-top">
                        <div>
                            <h1>{APP_NAME}</h1>
                            <p>{APP_TAGLINE}</p>
                        </div>
                        <div class="hero-badges">
                            <span class="badge">報價單 / 發票 / 收據</span>
                            <span class="badge">PDF 生成</span>
                            <span class="badge">常用客戶</span>
                            <span class="badge">薪酬管理</span>
                        </div>
                    </div>
                </div>
                <div class="grid">
                    <div class="card span-8">
                        {logo_html}
                        <div class="client-bar">
                            <div class="preset-block">
                                <label>常用客戶名稱</label>
                                <input id="common_client_name" type="text" placeholder="例如：美孚校區 25-26">
                                <div class="hint">保存常用客戶後，可一鍵帶入客戶、項目同文件類型。</div>
                            </div>
                            <div class="preset-block">
                                <label>已儲存常用客戶</label>
                                <input type="hidden" id="common_client_selected_id" value="">
                                <div id="common-client-selected-status" class="hint">未選擇</div>
                                <div class="client-actions">
                                    <button type="button" class="primary" onclick="saveCommonClient()">儲存常用客戶</button>
                                    <button type="button" onclick="loadCommonClient()">載入</button>
                                    <button type="button" class="danger" onclick="deleteCommonClient()">刪除</button>
                                </div>
                            </div>
                        </div>
                        <div id="common-client-picker" class="client-picker"></div>
                        <div class="preset-bar">
                            <div class="preset-block">
                                <label>範本名稱</label>
                                <input id="preset_name" type="text" placeholder="例如：沙田公立學校 25-26">
                                <div class="hint">用嚟保存常用內容。修改後按「儲存」即可覆蓋同名範本。</div>
                            </div>
                            <div class="preset-block">
                                <label>已儲存範本</label>
                                <select id="preset_select">{preset_options_html}</select>
                                <div class="preset-actions">
                                    <button type="button" class="primary" onclick="savePreset()">儲存範本</button>
                                    <button type="button" onclick="loadPreset()">載入</button>
                                    <button type="button" class="danger" onclick="deletePreset()">刪除</button>
                                    <button type="button" onclick="clearDraft()">清除草稿</button>
                                </div>
                            </div>
                        </div>
                        <form action="/generate" method="post">
                            <div class="grid">
                                <div><label>文件類型</label><select name="doc_type"><option value="報價單">報價單</option><option value="發票">發票</option><option value="收據">收據</option></select></div>
                                <div><label>日期</label><input type="text" name="date_str" value="{today}"></div>
                                <div style="grid-column: span 2;"><label>客戶名稱</label><textarea name="client" rows="2" required></textarea><div class="hint">支援換行，例如學校名稱 + 部門名稱分兩行。</div></div>
                                <div style="grid-column: span 2;"><label>項目名稱</label><textarea name="project" rows="2" required></textarea></div>
                                <div style="grid-column: span 2;"><label>文件編號</label><input type="text" name="doc_no" placeholder="留空自動生成"></div>
                            </div>
                            <div id="items-container" style="margin-top:20px;">
                                <div class="item-row grid">
                                    <div style="grid-column: span 2;"><label>摘要</label><textarea name="descs" rows="2" required></textarea></div>
                                    <div><label>單價</label><input type="number" name="prices" value="900" required></div>
                                    <div><label>數量</label><input type="number" name="qtys" value="21" required></div>
                                </div>
                            </div>
                            <button type="button" class="add-btn" onclick="addItem()">＋ 新增項目</button>
                            <textarea name="custom_remarks" rows="3" placeholder="自定義備註..."></textarea>
                            <div style="margin: 15px 0;"><input type="checkbox" name="with_sign" checked> 附上蓋印及簽署</div>
                            <button type="submit">生成專業 PDF</button>
                        </form>
                        
                        <table style="margin-top:30px;">
                            <thead><tr><th>編號</th><th>類型</th><th>客戶</th><th>總額</th></tr></thead>
                            <tbody>{history_html}</tbody>
                        </table>
                    </div>
                    <div class="card span-4">
                <h3 class="section-title">快速入口</h3>
                        <div class="quick-links">
                            <a href="/invoice/clients"><strong>常用客戶</strong><span>快速套用客戶、項目、文件類型</span></a>
                            <a href="/salary"><strong>薪酬管理</strong><span>導師、班別、薪酬計算</span></a>
                            <a href="/salary/teachers"><strong>導師列表</strong><span>檢視各導師班數與薪酬</span></a>
                            <a href="/salary/classes"><strong>班別列表</strong><span>整理學校、星期與時薪</span></a>
                            <a href="/salary/records"><strong>薪酬記錄</strong><span>已計算與待處理記錄</span></a>
                            <a href="/admin/accounts"><strong>帳戶管理</strong><span>新增、停用、重設密碼</span></a>
                        </div>
                        <div class="hint" style="margin-top:16px;">
                            Root endpoint 已整理成「報價 / 發票 / 收據」主頁，適合直接放上 Vercel。
                        </div>
                    </div>
                </div>
            </div>
        </body>
    </html>
    """


def _render_common_clients_page(request: Request, notice: str = ""):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, client_name, project_name, doc_type, category, notes, updated_at FROM common_clients ORDER BY updated_at DESC, id DESC")
    rows = cursor.fetchall()
    conn.close()
    rows = _unique_common_client_rows(rows)
    common_clients_json = json.dumps(
        [
            {
                "id": r[0],
                "name": r[1],
                "client_name": r[2],
                "project_name": r[3],
                "doc_type": r[4],
                "category": r[5],
                "notes": r[6],
                "updated_at": r[7],
            }
            for r in rows
        ],
        ensure_ascii=False,
    ).replace("</", "<\\/")

    notice_html = f'<div class="notice">{html.escape(notice)}</div>' if notice else ""
    count_html = f'<div class="notice">目前共有 <strong>{len(rows)}</strong> 筆常用客戶。</div>'
    rows_html = ""
    for r in rows:
        rows_html += f"""
        <tr>
            <td><strong>{html.escape(r[1])}</strong></td>
            <td>{html.escape(r[2])}</td>
            <td>{html.escape(r[3] or '')}</td>
            <td>{html.escape(r[4] or '')}</td>
            <td>{html.escape(r[5] or '')}</td>
            <td>{html.escape(r[6] or '')}</td>
            <td>{html.escape(r[7] or '')}</td>
            <td>
                <form class="inline delete-common-client-form" data-client-id="{r[0]}" data-client-name="{html.escape(r[1])}" action="/invoice/clients/{r[0]}/delete" method="post">
                    <button type="submit">刪除</button>
                </form>
            </td>
        </tr>
        """

    return f"""
    <html lang="zh-HK">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{APP_NAME} - 常用客戶</title>
        <style>
            body {{
                margin: 0;
                font-family: -apple-system, BlinkMacSystemFont, "PingFang HK", "Noto Sans TC", sans-serif;
                background: linear-gradient(135deg, #faf7f0 0%, #efe8d8 100%);
                color: #111;
                padding: 22px;
            }}
            .shell {{ max-width: 1180px; margin: 0 auto; }}
            .topbar {{
                display:flex; justify-content:space-between; gap:12px; align-items:center; flex-wrap:wrap;
                padding:20px 22px; background:rgba(255,255,255,.92); border:1px solid rgba(17,24,39,.08); border-radius:22px; margin-bottom:18px;
            }}
            .topbar a {{ text-decoration:none; color:#111; background:#fff; border:1px solid #ddd; border-radius:999px; padding:10px 14px; }}
            .card {{ background:rgba(255,255,255,.94); border:1px solid rgba(17,24,39,.08); border-radius:22px; padding:22px; box-shadow:0 14px 40px rgba(17,24,39,.06); }}
            .notice {{ margin-bottom: 14px; padding: 12px 14px; border-radius: 14px; background: #f4ead2; }}
            .muted {{ color:#6b7280; font-size:13px; line-height:1.6; }}
            .grid {{ display:grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }}
            label {{ display:block; font-size:12px; font-weight:700; margin:4px 0 6px; }}
            input, select, textarea {{ width:100%; padding:12px 13px; border:1px solid #d1d5db; border-radius:12px; }}
            textarea {{ min-height: 88px; resize: vertical; }}
            button {{ padding:10px 12px; border-radius:12px; border:1px solid #d1d5db; background:#111; color:#fff; cursor:pointer; }}
            table {{ width:100%; border-collapse: collapse; margin-top: 18px; }}
            th, td {{ padding: 12px 10px; border-bottom:1px solid #e5e7eb; vertical-align: top; text-align:left; }}
            th {{ font-size:12px; text-transform:uppercase; letter-spacing:.08em; color:#6b7280; }}
            .inline {{ display:inline-flex; gap:8px; align-items:center; margin:0 8px 8px 0; }}
            .inline input {{ width: 170px; }}
            .actions {{ margin-top: 14px; display:flex; gap:10px; flex-wrap:wrap; align-items:center; }}
            .actions > * {{ flex: 1 1 180px; min-width: 180px; }}
            .actions a.chip {{ display:inline-flex; align-items:center; justify-content:center; text-decoration:none; white-space:nowrap; }}
            .actions button {{ width:100%; }}
            @media (max-width: 700px) {{ .actions > * {{ min-width: 0; flex-basis: 100%; }} }}
            .filters {{ margin: 14px 0 6px; display:flex; gap:10px; flex-wrap:wrap; align-items:center; }}
            .chip {{ border:1px solid #d1d5db; background:#fff; color:#111; border-radius:999px; padding:8px 12px; cursor:pointer; }}
            .chip.active {{ background:#111; color:#fff; border-color:#111; }}
            .chip.ghost {{ background:transparent; }}
            .filter-select {{ min-width: 180px; }}
            @media (max-width: 900px) {{ .grid {{ grid-template-columns: 1fr; }} }}
        </style>
        <script>
            const COMMON_CLIENTS_KEY = 'docmagic_common_clients_v1';
            const SERVER_COMMON_CLIENTS = {common_clients_json};
            const CATEGORY_ORDER = ['小學', '中學', '特殊學校/群育學校', '幼稚園', 'NGO'];

            function escapeHtml(value) {{
                return String(value ?? '')
                    .replaceAll('&', '&amp;')
                    .replaceAll('<', '&lt;')
                    .replaceAll('>', '&gt;')
                    .replaceAll('"', '&quot;')
                    .replaceAll("'", '&#39;');
            }}

            function readCommonClients() {{
                try {{
                    const raw = localStorage.getItem(COMMON_CLIENTS_KEY);
                    const parsed = raw ? JSON.parse(raw) : [];
                    return Array.isArray(parsed) ? parsed : [];
                }} catch (e) {{
                    return [];
                }}
            }}

            function writeCommonClients(list) {{
                try {{
                    localStorage.setItem(COMMON_CLIENTS_KEY, JSON.stringify(Array.isArray(list) ? list : []));
                }} catch (e) {{}}
            }}

            function normalizeCommonClient(item) {{
                if (!item) return null;
                const normalized = {{
                    id: item.id ?? null,
                    name: (item.name || '').trim(),
                    client_name: item.client_name || '',
                    project_name: item.project_name || '',
                    doc_type: item.doc_type || '報價單',
                    category: item.category || '',
                    notes: item.notes || '',
                    updated_at: item.updated_at || ''
                }};
                return normalized.name ? normalized : null;
            }}

            function normalizeCommonClientName(value) {{
                return String(value ?? '')
                    .normalize('NFKC')
                    .replaceAll('⻘', '青')
                    .replace(/\s+/g, '')
                    .trim()
                    .toLowerCase();
            }}

            function commonClientKey(item) {{
                const normalized = normalizeCommonClient(item);
                if (!normalized) return '';
                return normalizeCommonClientName(normalized.name);
            }}

            function dedupeCommonClientList(list) {{
                const map = new Map();
                (Array.isArray(list) ? list : [])
                    .map(normalizeCommonClient)
                    .filter(Boolean)
                    .forEach((item) => {{
                        const key = commonClientKey(item);
                        if (!key) return;
                        const existing = map.get(key);
                        if (!existing) {{
                            map.set(key, item);
                            return;
                        }}
                        const existingScore = [
                            existing.category ? 1 : 0,
                            existing.notes ? 1 : 0,
                            existing.updated_at || '',
                            existing.id ?? 0,
                        ];
                        const itemScore = [
                            item.category ? 1 : 0,
                            item.notes ? 1 : 0,
                            item.updated_at || '',
                            item.id ?? 0,
                        ];
                        if (itemScore > existingScore) {{
                            map.set(key, item);
                        }}
                    }});
                return Array.from(map.values());
            }}

            function mergeCommonClients(primary, fallback) {{
                const merged = dedupeCommonClientList([...(Array.isArray(fallback) ? fallback : []), ...(Array.isArray(primary) ? primary : [])]);
                return merged;
            }}

            function getCommonClientStore() {{
                const server = Array.isArray(SERVER_COMMON_CLIENTS) ? SERVER_COMMON_CLIENTS.map(normalizeCommonClient).filter(Boolean) : [];
                const local = readCommonClients().map(normalizeCommonClient).filter(Boolean);
                const serverList = dedupeCommonClientList(server);
                if (serverList.length) {{
                    writeCommonClients(serverList);
                    return serverList;
                }}
                const merged = mergeCommonClients(server, local);
                if (merged.length) {{
                    writeCommonClients(merged);
                    return merged;
                }}
                return [];
            }}

            async function syncCommonClientsToServer() {{
                const local = readCommonClients().map(normalizeCommonClient).filter(Boolean);
                const server = dedupeCommonClientList(Array.isArray(SERVER_COMMON_CLIENTS) ? SERVER_COMMON_CLIENTS.map(normalizeCommonClient).filter(Boolean) : []);
                if (!local.length) return;
                const serverKeys = new Set(server.map(commonClientKey).filter(Boolean));
                const missing = local.filter((item) => {{
                    const key = commonClientKey(item);
                    return key && !serverKeys.has(key);
                }});
                if (!missing.length) return;
                await Promise.all(missing.map((item) => fetch('/api/common-clients', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    credentials: 'same-origin',
                    body: JSON.stringify(item)
                }}).catch(() => null)));
            }}

            function upsertCommonClientLocal(item) {{
                const normalized = normalizeCommonClient(item);
                if (!normalized) return readCommonClients();
                const list = dedupeCommonClientList(readCommonClients().map(normalizeCommonClient).filter(Boolean));
                const idx = list.findIndex((entry) => commonClientKey(entry) === commonClientKey(normalized));
                if (idx >= 0) {{
                    list[idx] = {{ ...list[idx], ...normalized }};
                }} else {{
                    list.unshift(normalized);
                }}
                writeCommonClients(list);
                return list;
            }}

            function removeCommonClientLocal(identifier) {{
                const key = String(identifier ?? '').trim();
                const canonical = normalizeCommonClientName(key);
                const list = dedupeCommonClientList(readCommonClients().map(normalizeCommonClient).filter(Boolean)).filter((entry) => {{
                    return String(entry.id ?? '').trim() !== key && commonClientKey(entry) !== canonical;
                }});
                writeCommonClients(list);
                return list;
            }}

            function renderCommonClientsTable(clients) {{
                const tbody = document.getElementById('common-clients-body');
                if (!tbody) return;
                const categoryFilter = (document.getElementById('category-filter')?.value || '').trim();
                const query = (document.getElementById('client-search')?.value || '').trim().toLowerCase();
                const rows = Array.isArray(clients) ? clients.map(normalizeCommonClient).filter(Boolean) : [];
                const filtered = rows.filter((client) => {{
                    const category = String(client.category || '').trim();
                    const haystack = `${{client.name}} ${{client.client_name}} ${{client.project_name || ''}} ${{client.doc_type || ''}} ${{client.category || ''}} ${{client.notes || ''}}`.toLowerCase();
                    const categoryMatch = !categoryFilter || category === categoryFilter;
                    const queryMatch = !query || haystack.includes(query);
                    return categoryMatch && queryMatch;
                }});
                if (!filtered.length) {{
                    tbody.innerHTML = '<tr><td colspan="8" class="muted">暫時未有符合條件嘅常用客戶。</td></tr>';
                    return;
                }}
                tbody.innerHTML = filtered.map((client) => {{
                    const safeId = escapeHtml(client.id ?? client.name);
                    const categoryLabel = String(client.category || '').trim();
                    return `
                        <tr>
                            <td><strong>${{escapeHtml(client.name)}}</strong></td>
                            <td>${{escapeHtml(client.client_name)}}</td>
                            <td>${{escapeHtml(client.project_name || '')}}</td>
                            <td>${{escapeHtml(client.doc_type || '')}}</td>
                            <td>${{escapeHtml(categoryLabel)}}</td>
                            <td>${{escapeHtml(client.notes || '')}}</td>
                            <td>${{escapeHtml(client.updated_at || '')}}</td>
                            <td>
                                <form class="inline delete-common-client-form" data-client-id="${{safeId}}" action="/invoice/clients/${{safeId}}/delete" method="post">
                                    <button type="submit">刪除</button>
                                </form>
                            </td>
                        </tr>
                    `;
                }}).join('');
            }}

            function hydrateCommonClients() {{
                renderCommonClientsTable(getCommonClientStore());
            }}

            function renderCategoryChips(clients) {{
                const wrap = document.getElementById('category-chips');
                if (!wrap) return;
                const rows = Array.isArray(clients) ? clients.map(normalizeCommonClient).filter(Boolean) : [];
                const categories = [...new Set([...CATEGORY_ORDER, ...rows.map((client) => String(client.category || '').trim()).filter(Boolean)])];
                wrap.innerHTML = ['<button type="button" class="chip active" data-category="">全部</button>', ...categories.map((category) => `<button type="button" class="chip" data-category="${{escapeHtml(category)}}">${{escapeHtml(category)}}</button>`)].join('');
                wrap.querySelectorAll('.chip').forEach((button) => {{
                    button.addEventListener('click', () => {{
                        wrap.querySelectorAll('.chip').forEach((item) => item.classList.remove('active'));
                        button.classList.add('active');
                        const select = document.getElementById('category-filter');
                        if (select) select.value = button.dataset.category || '';
                        renderCommonClientsTable(getCommonClientStore());
                    }});
                }});
            }}

            function updateCategoryActiveState() {{
                const select = document.getElementById('category-filter');
                const value = (select?.value || '').trim();
                const wrap = document.getElementById('category-chips');
                if (!wrap) return;
                wrap.querySelectorAll('.chip').forEach((button) => {{
                    button.classList.toggle('active', (button.dataset.category || '') === value);
                }});
            }}

            document.addEventListener('DOMContentLoaded', () => {{
                const store = getCommonClientStore();
                renderCategoryChips(store);
                hydrateCommonClients();
                syncCommonClientsToServer().catch(() => {{}});
                const form = document.getElementById('common-client-form');
                if (form) {{
                    form.addEventListener('submit', () => {{
                const payload = {{
                    name: form.querySelector('[name="name"]').value.trim(),
                    client_name: form.querySelector('[name="client_name"]').value.trim(),
                    project_name: form.querySelector('[name="project_name"]').value.trim(),
                    doc_type: form.querySelector('[name="doc_type"]').value,
                    category: form.querySelector('[name="category"]').value,
                    notes: form.querySelector('[name="notes"]').value.trim(),
                }};
                        if (payload.name && payload.client_name) {{
                            upsertCommonClientLocal(payload);
                        }}
                    }});
                }}
                document.querySelectorAll('.delete-common-client-form').forEach((deleteForm) => {{
                    deleteForm.addEventListener('submit', async (event) => {{
                        event.preventDefault();
                        const identifier = deleteForm.dataset.clientId || deleteForm.dataset.clientName || '';
                        if (!confirm('確定刪除呢個常用客戶？')) return;
                        removeCommonClientLocal(identifier);
                        try {{
                            const res = await fetch(deleteForm.action, {{
                                method: 'POST',
                                credentials: 'same-origin'
                            }});
                            if (!res.ok) throw new Error('delete failed');
                            window.location.reload();
                        }} catch (e) {{
                            alert('刪除失敗');
                            window.location.reload();
                        }}
                    }});
                }});
                const search = document.getElementById('client-search');
                const category = document.getElementById('category-filter');
                if (search) search.addEventListener('input', () => renderCommonClientsTable(getCommonClientStore()));
                if (category) category.addEventListener('change', () => {{
                    updateCategoryActiveState();
                    renderCommonClientsTable(getCommonClientStore());
                }});
            }});
        </script>
    </head>
    <body>
        <div class="shell">
            <div class="topbar">
                <div>
                    <div class="muted">Quick access</div>
                    <h1 style="margin:0;">常用客戶</h1>
                </div>
                <div>
                    <a href="/dashboard">返回主選單</a>
                    <a href="/invoice">發票系統</a>
                </div>
            </div>
            <div class="card">
                <h2 style="margin-top:0;">儲存常用客戶</h2>
                <p class="muted">用嚟快速帶入客戶名稱、項目名稱同文件類型。常用客戶可同草稿共存，方便重複出單。</p>
                {count_html}
                {notice_html}
                <form id="common-client-form" action="/invoice/clients/save" method="post">
                    <div class="grid">
                        <div><label>常用客戶名稱</label><input name="name" placeholder="例如：沙田校區"></div>
                        <div><label>文件類型</label>
                            <select name="doc_type">
                                <option value="報價單">報價單</option>
                                <option value="發票">發票</option>
                                <option value="收據">收據</option>
                            </select>
                        </div>
                        <div><label>分類</label>
                            <select name="category">
                                <option value="">請選擇分類</option>
                                <option value="小學">小學</option>
                                <option value="中學">中學</option>
                                <option value="特殊學校/群育學校">特殊學校/群育學校</option>
                                <option value="幼稚園">幼稚園</option>
                                <option value="NGO">NGO</option>
                            </select>
                        </div>
                        <div><label>客戶名稱</label><textarea name="client_name" placeholder="客戶 / 學校名稱"></textarea></div>
                        <div><label>項目名稱</label><textarea name="project_name" placeholder="例如：2025-26 舞蹈課程"></textarea></div>
                    </div>
                    <label style="margin-top:12px;">備註</label>
                    <textarea name="notes" placeholder="可留付款提醒、常用備註等。"></textarea>
                    <div class="actions">
                        <button type="submit">儲存常用客戶</button>
                        <a href="/invoice/clients/export" class="chip ghost" style="text-decoration:none; display:inline-flex; align-items:center;">匯出 CSV</a>
                    </div>
                </form>
                <div class="filters">
                    <input id="client-search" type="text" placeholder="搜尋名稱 / 客戶 / 項目 / 備註" style="max-width:320px;">
                    <select id="category-filter" class="filter-select">
                        <option value="">全部分類</option>
                        <option value="小學">小學</option>
                        <option value="中學">中學</option>
                        <option value="特殊學校/群育學校">特殊學校/群育學校</option>
                        <option value="幼稚園">幼稚園</option>
                        <option value="NGO">NGO</option>
                    </select>
                </div>
                <div id="category-chips" class="filters"></div>
                <table>
                    <thead><tr><th>名稱</th><th>客戶</th><th>項目</th><th>文件類型</th><th>分類</th><th>備註</th><th>更新</th><th>操作</th></tr></thead>
                    <tbody id="common-clients-body">{rows_html}</tbody>
                </table>
            </div>
        </div>
    </body>
    </html>
    """


@app.get("/invoice/clients", response_class=HTMLResponse)
async def invoice_clients(request: Request, username: str = Depends(_require_admin_username)):
    return HTMLResponse(
        _render_common_clients_page(request),
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
        },
    )


@app.post("/invoice/clients/save")
async def invoice_clients_save(
    request: Request,
    name: str = Form(...),
    client_name: str = Form(...),
    project_name: str = Form(""),
    doc_type: str = Form("報價單"),
    category: str = Form(""),
    notes: str = Form(""),
    username: str = Depends(_require_admin_username),
):
    name = name.strip()
    client_name = client_name.strip()
    if not name or not client_name:
        return HTMLResponse(_render_common_clients_page(request, "名稱同客戶名稱不可留空"))
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    canonical = _normalize_common_client_name(name)
    cursor.execute("SELECT id, name FROM common_clients")
    matched_id = None
    for existing_id, existing_name in cursor.fetchall():
        if _normalize_common_client_name(existing_name) == canonical:
            matched_id = existing_id
            break
    if matched_id:
        cursor.execute(
            "UPDATE common_clients SET client_name=?, project_name=?, doc_type=?, category=?, notes=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (client_name, project_name.strip(), doc_type.strip(), category.strip(), notes.strip(), matched_id),
        )
    else:
        cursor.execute(
            "INSERT INTO common_clients (name, client_name, project_name, doc_type, category, notes) VALUES (?, ?, ?, ?, ?, ?)",
            (name, client_name, project_name.strip(), doc_type.strip(), category.strip(), notes.strip()),
        )
    conn.commit()
    conn.close()
    return RedirectResponse("/invoice/clients", status_code=303)


@app.post("/invoice/clients/{client_key}/delete")
async def invoice_clients_delete(request: Request, client_key: str, username: str = Depends(_require_admin_username)):
    _delete_common_client_by_key(client_key)
    return RedirectResponse("/invoice/clients", status_code=303)


@app.get("/invoice/clients/export")
async def invoice_clients_export(username: str = Depends(_require_admin_username)):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT name, client_name, project_name, doc_type, category, notes, updated_at
        FROM common_clients
        ORDER BY category, name
    """)
    rows = cursor.fetchall()
    conn.close()

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["名稱", "客戶", "項目", "文件類型", "分類", "備註", "更新時間"])
    for row in rows:
        writer.writerow(row)

    csv_data = buffer.getvalue().encode("utf-8-sig")
    return Response(
        content=csv_data,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=common_clients.csv"},
    )


@app.get("/announcements", response_class=HTMLResponse)
async def announcements(request: Request, user: tuple = Depends(require_roles("admin", "manager", "finance", "tutor"))):
    return HTMLResponse(_render_announcements_page(request))


@app.post("/announcements")
async def announcements_create(
    request: Request,
    title: str = Form(...),
    body: str = Form(...),
    pinned: str = Form("0"),
    image: Optional[UploadFile] = File(None),
    user: tuple = Depends(require_roles("admin")),
):
    title = title.strip()
    body = body.strip()
    if not title or not body:
        return HTMLResponse(_render_announcements_page(request, "標題同內容不可留空"))

    image_filename = None
    image_mime = None
    image_blob = None
    if image and image.filename:
        if image.content_type not in {"image/png", "image/jpeg"}:
            return HTMLResponse(_render_announcements_page(request, "只支援 PNG 或 JPEG 圖片"), status_code=400)
        image_blob = await image.read()
        if not image_blob:
            return HTMLResponse(_render_announcements_page(request, "圖片檔案無內容"), status_code=400)
        if len(image_blob) > 5 * 1024 * 1024:
            return HTMLResponse(_render_announcements_page(request, "圖片不可超過 5MB"), status_code=400)
        image_filename = os.path.basename(image.filename)
        image_mime = image.content_type

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO announcements
            (title, body, pinned, created_by, image_filename, image_mime, image_blob, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """,
        (title, body, 1 if str(pinned) == "1" else 0, user[1], image_filename, image_mime, sqlite3.Binary(image_blob) if image_blob else None),
    )
    conn.commit()
    conn.close()
    return RedirectResponse("/announcements", status_code=303)


@app.post("/announcements/{announcement_id}/delete")
async def announcements_delete(
    request: Request,
    announcement_id: int,
    user: tuple = Depends(require_roles("admin")),
):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM announcements WHERE id=?", (announcement_id,))
    conn.commit()
    conn.close()
    return RedirectResponse("/announcements", status_code=303)


@app.post("/generate")
async def handle_generate(
    doc_type: str = Form(...), client: str = Form(...), project: str = Form(...),
    date_str: str = Form(...), doc_no: str = Form(None),
    descs: List[str] = Form(...), prices: List[int] = Form(...), qtys: List[int] = Form(...),
    custom_remarks: str = Form(None),
    with_sign: bool = Form(False),
    username: str = Depends(_require_admin_username)
):
    try:
        if not doc_no:
            prefix = {"報價單": "QU", "發票": "INV", "收據": "REC"}.get(doc_type, "DOC")
            doc_no = f"DK-{prefix}{datetime.now().strftime('%m%d%H%M')}"
        
        items = list(zip(descs, prices, qtys))
        total_amount = sum([int(p) * int(q) for p, q in zip(prices, qtys)])

        pdf_content = generate_pdf_logic(doc_type, client, project, items, date_str, doc_no, with_sign, custom_remarks)
        
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO records (doc_no, doc_type, client, project, total_amount) VALUES (?, ?, ?, ?, ?)",
                           (doc_no, doc_type, client, project, total_amount))
            conn.commit()
            conn.close()
        except: pass

        return Response(content=pdf_content, media_type="application/pdf", 
                        headers={"Content-Disposition": f"attachment; filename={doc_no}.pdf"})
    except Exception:
        return HTMLResponse(content=f"<pre>{traceback.format_exc()}</pre>", status_code=500)

@app.get("/api/presets")
async def list_form_presets(username: str = Depends(_require_admin_username)):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, name, updated_at FROM form_presets ORDER BY updated_at DESC, id DESC")
    rows = c.fetchall()
    conn.close()
    return {"presets": [{"id": r[0], "name": r[1], "updated_at": r[2]} for r in rows]}

@app.get("/api/presets/{preset_id}")
async def get_form_preset(preset_id: int, username: str = Depends(_require_admin_username)):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, name, payload FROM form_presets WHERE id=?", (preset_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Preset not found")
    try:
        payload = json.loads(row[2])
    except Exception:
        payload = {}
    return {"id": row[0], "name": row[1], "payload": payload}

@app.post("/api/presets")
async def save_form_preset(request: Request, username: str = Depends(_require_admin_username)):
    data = await request.json()
    name = (data.get("name") or "").strip()
    payload = data.get("payload") or {}
    if not name:
        raise HTTPException(status_code=400, detail="Preset name is required")

    payload_json = json.dumps(payload, ensure_ascii=False)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id FROM form_presets WHERE name=?", (name,))
    existing = c.fetchone()
    if existing:
        c.execute(
            "UPDATE form_presets SET payload=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (payload_json, existing[0])
        )
        preset_id = existing[0]
    else:
        c.execute(
            "INSERT INTO form_presets (name, payload) VALUES (?, ?)",
            (name, payload_json)
        )
        preset_id = c.lastrowid
    conn.commit()
    conn.close()
    return {"ok": True, "id": preset_id, "name": name}

@app.delete("/api/presets/{preset_id}")
async def delete_form_preset(preset_id: int, username: str = Depends(_require_admin_username)):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM form_presets WHERE id=?", (preset_id,))
    deleted = c.rowcount
    conn.commit()
    conn.close()
    if not deleted:
        raise HTTPException(status_code=404, detail="Preset not found")
    return {"ok": True}


@app.get("/api/common-clients")
async def list_common_clients(username: str = Depends(_require_admin_username)):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, name, client_name, project_name, doc_type, category, notes, updated_at FROM common_clients ORDER BY updated_at DESC, id DESC")
    rows = c.fetchall()
    conn.close()
    rows = _unique_common_client_rows(rows)
    return {
        "clients": [
            {
                "id": r[0],
                "name": r[1],
                "client_name": r[2],
                "project_name": r[3],
                "doc_type": r[4],
                "category": r[5],
                "notes": r[6],
                "updated_at": r[7],
            }
            for r in rows
        ]
    }


@app.get("/api/common-clients/{client_id}")
async def get_common_client(client_id: int, username: str = Depends(_require_admin_username)):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, name, client_name, project_name, doc_type, category, notes FROM common_clients WHERE id=?", (client_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Common client not found")
    return {
        "id": row[0],
        "name": row[1],
        "client_name": row[2],
        "project_name": row[3],
        "doc_type": row[4],
        "category": row[5],
        "notes": row[6],
    }


@app.post("/api/common-clients")
async def save_common_client(request: Request, username: str = Depends(_require_admin_username)):
    data = await request.json()
    name = (data.get("name") or "").strip()
    client_name = (data.get("client_name") or "").strip()
    project_name = (data.get("project_name") or "").strip()
    doc_type = (data.get("doc_type") or "報價單").strip()
    category = (data.get("category") or "").strip()
    notes = (data.get("notes") or "").strip()
    if not name or not client_name:
        raise HTTPException(status_code=400, detail="Name and client name are required")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    canonical = _normalize_common_client_name(name)
    c.execute("SELECT id, name FROM common_clients")
    existing = None
    for row in c.fetchall():
        if _normalize_common_client_name(row[1]) == canonical:
            existing = row
            break
    if existing:
        c.execute(
            "UPDATE common_clients SET client_name=?, project_name=?, doc_type=?, category=?, notes=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (client_name, project_name, doc_type, category, notes, existing[0]),
        )
        client_id = existing[0]
    else:
        c.execute(
            "INSERT INTO common_clients (name, client_name, project_name, doc_type, category, notes) VALUES (?, ?, ?, ?, ?, ?)",
            (name, client_name, project_name, doc_type, category, notes),
        )
        client_id = c.lastrowid
    conn.commit()
    conn.close()
    return {"ok": True, "id": client_id, "name": name}


@app.delete("/api/common-clients/{client_key}")
async def delete_common_client(client_key: str, username: str = Depends(_require_admin_username)):
    deleted = _delete_common_client_by_key(client_key)
    if not deleted:
        raise HTTPException(status_code=404, detail="Common client not found")
    return {"ok": True}

# =========================================================
# 🧾 導師薪酬計算系統 (Teacher Salary Module)
# =========================================================

# 品牌色系
BRAND_BLUE = "#B89D5D"
BRAND_LIGHT = "#F5F5F3"
BRAND_WHITE = "#FFFFFF"
TEXT_DARK = "#111111"

# ----- 初始化薪酬資料表 -----
def init_salary_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS teachers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            bank_name TEXT DEFAULT '',
            bank_account_number TEXT DEFAULT '',
            fps_id TEXT DEFAULT '',
            is_active INTEGER DEFAULT 1
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS school_classes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teacher_id INTEGER,
            area TEXT DEFAULT '',
            school_name TEXT,
            weekday TEXT,
            lesson_time TEXT DEFAULT '',
            salary_per_hour REAL DEFAULT 0,
            total_lessons INTEGER DEFAULT 0,
            completed_lessons INTEGER DEFAULT 0,
            lessons_this_month INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1,
            FOREIGN KEY(teacher_id) REFERENCES teachers(id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS salary_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teacher_id INTEGER,
            month INTEGER,
            year INTEGER,
            total_classes INTEGER,
            total_amount REAL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(teacher_id) REFERENCES teachers(id)
        )
    """)
    c.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_salary_records_teacher_year_month
        ON salary_records(teacher_id, year, month)
    """)
    c.execute("PRAGMA table_info(teachers)")
    teacher_cols = {row[1] for row in c.fetchall()}
    for col_name, col_def in [
        ("bank_name", "TEXT DEFAULT ''"),
        ("bank_account_number", "TEXT DEFAULT ''"),
        ("fps_id", "TEXT DEFAULT ''"),
    ]:
        if col_name not in teacher_cols:
            c.execute(f"ALTER TABLE teachers ADD COLUMN {col_name} {col_def}")
    c.execute("PRAGMA table_info(school_classes)")
    class_cols = {row[1] for row in c.fetchall()}
    for col_name, col_def in [
        ("area", "TEXT DEFAULT ''"),
        ("lesson_time", "TEXT DEFAULT ''"),
    ]:
        if col_name not in class_cols:
            c.execute(f"ALTER TABLE school_classes ADD COLUMN {col_name} {col_def}")
    conn.commit()
    conn.close()

init_salary_db()

SALARY_HEADER = f"""<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>薪酬系統 - Dance Kingdom</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family: 'PingFang HK', 'Noto Sans HK', -apple-system, sans-serif; background: linear-gradient(135deg, #fafafa 0%, #f1f3f5 100%); color: {TEXT_DARK}; }}
.nav {{ background: {BRAND_WHITE}; border-bottom: 2px solid {BRAND_BLUE}; padding: 12px 24px; display: flex; align-items: center; justify-content: space-between; box-shadow: 0 2px 8px rgba(17,24,39,0.06); }}
.nav h1 {{ font-size: 18px; color: {TEXT_DARK}; font-weight: 800; }}
.nav a {{ color: {TEXT_DARK}; text-decoration: none; font-size: 13px; margin-left: 16px; font-weight: 500; padding: 6px 14px; border-radius: 6px; transition: all .2s; }}
.nav a:hover {{ background: {BRAND_LIGHT}; }}
.nav .sub a {{ background: {BRAND_BLUE}; color: #111111; }}
.nav .sub a:hover {{ opacity: .9; }}
.container {{ max-width: 1100px; margin: 0 auto; padding: 24px 16px; }}
.card {{ background: {BRAND_WHITE}; border-radius: 16px; border: 1px solid #e5e7eb; padding: 24px; margin-bottom: 20px; box-shadow: 0 2px 12px rgba(17,24,39,0.04); }}
h2 {{ font-size: 20px; color: {TEXT_DARK}; margin-bottom: 16px; font-weight: 800; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th {{ background: #fafafa; color: {TEXT_DARK}; padding: 10px 12px; text-align: left; font-weight: 600; border-bottom: 2px solid #d1d5db; font-size: 12px; text-transform: uppercase; letter-spacing: .5px; }}
td {{ padding: 10px 12px; border-bottom: 1px solid #eef2f7; }}
tr:hover td {{ background: #fcfcfd; }}
.badge {{ display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 11px; font-weight: 600; }}
.badge-blue {{ background: {BRAND_LIGHT}; color: {TEXT_DARK}; }}
.badge-green {{ background: #f6f1e3; color: {TEXT_DARK}; }}
.btn {{ display: inline-block; padding: 8px 20px; border-radius: 8px; font-size: 13px; font-weight: 600; cursor: pointer; border: none; text-decoration: none; transition: all .2s; }}
.btn-primary {{ background: {BRAND_BLUE}; color: #111111; }}
.btn-primary:hover {{ opacity: .9; transform: translateY(-1px); }}
.btn-outline {{ background: transparent; color: {TEXT_DARK}; border: 1.5px solid {BRAND_BLUE}; }}
.btn-outline:hover {{ background: {BRAND_LIGHT}; }}
.btn-small {{ padding: 4px 12px; font-size: 11px; }}
.stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 14px; margin-bottom: 20px; }}
.stat-card {{ background: {BRAND_WHITE}; border: 1px solid #e5e7eb; border-radius: 14px; padding: 16px; text-align: center; }}
.stat-card .num {{ font-size: 26px; font-weight: 700; color: {TEXT_DARK}; }}
.stat-card .label {{ font-size: 11px; color: #666; margin-top: 4px; text-transform: uppercase; letter-spacing: .5px; }}
.alert-info {{ background: #fafafa; border-left: 3px solid {BRAND_BLUE}; padding: 12px 16px; border-radius: 8px; font-size: 13px; margin-bottom: 16px; color: #4b5563; }}
.footer {{ text-align: center; padding: 24px; font-size: 11px; color: #999; }}
.mt-2 {{ margin-top: 12px; }}
.flex {{ display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }}
.stack {{ display: grid; gap: 10px; }}
.report-box {{ border: 1px solid #e5e7eb; border-radius: 14px; padding: 16px; margin-top: 14px; background: #fff; }}
.report-title {{ font-size: 15px; font-weight: 800; margin-bottom: 8px; }}
.muted {{ color: #6b7280; }}
.print-bar {{ display: flex; gap: 10px; flex-wrap: wrap; margin: 12px 0 18px; }}
@media print {{
    .nav, .footer, .print-bar, .no-print {{ display: none !important; }}
    body {{ background: #fff; }}
    .card, .report-box {{ box-shadow: none; border-color: #ccc; }}
}}
</style></head><body>
<div class="nav">
<div><h1>💃 導師薪酬系統</h1></div>
<div class="flex">
<a href="/salary">📊 Dashboard</a>
<a href="/salary/teachers">👨‍🏫 導師</a>
<a href="/salary/classes">🏫 班別</a>
<a href="/salary/records">📋 薪酬記錄</a>
<a href="/salary/import">📥 匯入數據</a>
<a href="/" class="sub">← 返回 DocMagic</a>
</div></div>"""

SALARY_FOOTER = """<div class="footer">Di2da Dance School &copy; 2026 &middot; 導師薪酬管理系統</div>
</body></html>"""

def _salary_amount_for_teacher(cursor, teacher_id: int):
    cursor.execute("""
        SELECT COALESCE(SUM(COALESCE(completed_lessons, 0) * COALESCE(salary_per_hour, 0)), 0)
        FROM school_classes
        WHERE teacher_id=? AND is_active=1
    """, (teacher_id,))
    return cursor.fetchone()[0] or 0

def render_salary_page(title, body):
    return HTMLResponse(f"{SALARY_HEADER}<div class='container'><h2>{title}</h2><div class='card'>{body}</div></div>{SALARY_FOOTER}")


def _csv_text_from_upload(upload: UploadFile):
    raw = upload.file.read()
    if isinstance(raw, bytes):
        for encoding in ("utf-8-sig", "utf-8", "cp950"):
            try:
                return raw.decode(encoding)
            except Exception:
                pass
        return raw.decode("utf-8", errors="ignore")
    return raw or ""


def _csv_row_value(row, *names, default=""):
    lower_map = {str(k).strip().lower(): v for k, v in row.items()}
    for name in names:
        key = str(name).strip().lower()
        if key in lower_map and str(lower_map[key]).strip() != "":
            return str(lower_map[key]).strip()
    return default


def _truthy(value):
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on", "是", "啟用"}


def _clear_salary_data(clear_teachers: bool = False):
    conn = _REAL_SQLITE_CONNECT(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM salary_records")
    cursor.execute("DELETE FROM school_classes")
    if clear_teachers:
        cursor.execute("DELETE FROM teachers")
    cursor.execute("DELETE FROM sqlite_sequence WHERE name IN ('salary_records','school_classes','teachers')")
    conn.commit()
    conn.close()


def _import_teachers_csv_text(csv_text: str, replace: bool = False):
    rows = list(csv.DictReader(io.StringIO(csv_text)))
    conn = _REAL_SQLITE_CONNECT(DB_PATH)
    cursor = conn.cursor()
    imported = 0
    if replace:
        cursor.execute("DELETE FROM teachers")
        cursor.execute("DELETE FROM sqlite_sequence WHERE name='teachers'")
    for row in rows:
        name = _csv_row_value(row, "name", "teacher", "導師")
        if not name:
            continue
        bank_name = _csv_row_value(row, "bank_name", "銀行名稱")
        bank_account_number = _csv_row_value(row, "bank_account_number", "戶口號碼")
        fps_id = _csv_row_value(row, "fps_id", "FPS ID", "fps")
        is_active = 1 if _truthy(_csv_row_value(row, "is_active", "啟用", default="1")) else 0
        cursor.execute("SELECT id FROM teachers WHERE name=?", (name,))
        existing = cursor.fetchone()
        if existing:
            cursor.execute(
                "UPDATE teachers SET bank_name=?, bank_account_number=?, fps_id=?, is_active=? WHERE id=?",
                (bank_name, bank_account_number, fps_id, is_active, existing[0]),
            )
        else:
            cursor.execute(
                "INSERT INTO teachers (name, bank_name, bank_account_number, fps_id, is_active) VALUES (?, ?, ?, ?, ?)",
                (name, bank_name, bank_account_number, fps_id, is_active),
            )
        imported += 1
    conn.commit()
    conn.close()
    return imported


def _import_classes_csv_text(csv_text: str, replace: bool = False):
    rows = list(csv.DictReader(io.StringIO(csv_text)))
    conn = _REAL_SQLITE_CONNECT(DB_PATH)
    cursor = conn.cursor()
    imported = 0
    if replace:
        cursor.execute("DELETE FROM school_classes")
        cursor.execute("DELETE FROM sqlite_sequence WHERE name='school_classes'")
    for row in rows:
        teacher_name = _csv_row_value(row, "teacher_name", "teacher", "導師")
        school_name = _csv_row_value(row, "school_name", "school", "學校名稱")
        if not teacher_name or not school_name:
            continue
        area = _csv_row_value(row, "area", "地區")
        weekday = _csv_row_value(row, "weekday", "星期")
        lesson_time = _csv_row_value(row, "lesson_time", "時間")
        salary_per_hour = float(_csv_row_value(row, "salary_per_hour", "rate", "時薪", default="0") or 0)
        total_lessons = int(float(_csv_row_value(row, "total_lessons", "total", "總堂數", default="0") or 0))
        completed_lessons = int(float(_csv_row_value(row, "completed_lessons", "completed", "已上", default="0") or 0))
        lessons_this_month = int(float(_csv_row_value(row, "lessons_this_month", "monthly", "本月堂數", default="0") or 0))
        is_active = 1 if _truthy(_csv_row_value(row, "is_active", "啟用", default="1")) else 0
        cursor.execute("INSERT OR IGNORE INTO teachers (name) VALUES (?)", (teacher_name,))
        cursor.execute("SELECT id FROM teachers WHERE name=?", (teacher_name,))
        teacher_id = cursor.fetchone()[0]
        cursor.execute("""
            SELECT id FROM school_classes
            WHERE teacher_id=? AND school_name=? AND weekday=? AND lesson_time=?
        """, (teacher_id, school_name, weekday, lesson_time))
        existing = cursor.fetchone()
        if existing:
            cursor.execute("""
                UPDATE school_classes
                SET area=?, salary_per_hour=?, total_lessons=?, completed_lessons=?, lessons_this_month=?, is_active=?
                WHERE id=?
            """, (area, salary_per_hour, total_lessons, completed_lessons, lessons_this_month, is_active, existing[0]))
        else:
            cursor.execute("""
                INSERT INTO school_classes
                    (teacher_id, area, school_name, weekday, lesson_time, salary_per_hour, total_lessons, completed_lessons, lessons_this_month, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (teacher_id, area, school_name, weekday, lesson_time, salary_per_hour, total_lessons, completed_lessons, lessons_this_month, is_active))
        imported += 1
    conn.commit()
    conn.close()
    return imported

@app.get("/salary")
async def salary_dashboard(user: tuple = Depends(require_roles("admin", "finance"))):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute("SELECT COUNT(*) FROM teachers WHERE is_active=1")
    teacher_count = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM school_classes WHERE is_active=1")
    class_count = c.fetchone()[0]
    
    c.execute("""
        SELECT COALESCE(SUM(sc.total_lessons * sc.salary_per_hour), 0)
        FROM school_classes sc WHERE sc.is_active=1
    """)
    total_contract = c.fetchone()[0]
    
    # 本月薪酬估算
    c.execute("""
        SELECT COALESCE(SUM(sc.completed_lessons * sc.salary_per_hour), 0)
        FROM school_classes sc WHERE sc.is_active=1
    """)
    this_month_total = c.fetchone()[0]
    
    # 各導師本月統計
    c.execute("""
        SELECT t.name, COUNT(sc.id) as classes,
               COALESCE(SUM(sc.completed_lessons * sc.salary_per_hour), 0) as amount
        FROM teachers t
        LEFT JOIN school_classes sc ON sc.teacher_id = t.id AND sc.is_active=1
        WHERE t.is_active=1
        GROUP BY t.id ORDER BY amount DESC
    """)
    teachers_data = c.fetchall()
    conn.close()
    
    stats_html = f"""
    <div class="stats">
        <div class="stat-card"><div class="num">{teacher_count}</div><div class="label">導師</div></div>
        <div class="stat-card"><div class="num">{class_count}</div><div class="label">班別</div></div>
        <div class="stat-card"><div class="num">${this_month_total:,.0f}</div><div class="label">本月薪酬預算</div></div>
        <div class="stat-card"><div class="num">${total_contract:,.0f}</div><div class="label">全年合約總值</div></div>
    </div>"""
    
    rows_html = ""
    for t_name, classes, amount in teachers_data:
        rows_html += f"<tr><td><strong>{t_name}</strong></td><td>{classes} 班</td><td><strong>${amount:,.0f}</strong></td></tr>"
    
    body = f"""
    {stats_html}
    <div class="alert-info">💡 點選上方「匯入數據」可從 Excel 匯入現有教務資料，系統會自動計算薪酬。</div>
    <div class="print-bar no-print">
        <a href="/salary/report" class="btn btn-primary btn-small">📄 一鍵出報表</a>
    </div>
    <h3>👨‍🏫 導師本月薪酬一覽</h3>
    <table><thead><tr><th>導師</th><th>班數</th><th>本月薪酬 (HKD)</th></tr></thead><tbody>{rows_html}</tbody></table>
    """
    return render_salary_page("📊 薪酬概覽", body)

@app.get("/salary/import")
async def salary_import_page(user: tuple = Depends(require_roles("admin", "finance"))):
    body = """
    <div class="alert-info">📥 支援 CSV 匯入導師同班別。建議先匯入導師，再匯入班別。匯入前可先用重置按鈕清空舊資料。</div>
    <div class="stack" style="margin-bottom:18px;">
        <form action="/salary/import/teachers-csv" method="post" enctype="multipart/form-data">
            <div class="stack">
                <strong>導師 CSV 匯入</strong>
                <div class="muted">欄位建議：name, bank_name, bank_account_number, fps_id, is_active</div>
                <input type="file" name="file" accept=".csv,text/csv" required>
                <label><input type="checkbox" name="replace" value="1"> 覆蓋現有導師資料</label>
                <button type="submit" class="btn btn-primary">匯入導師 CSV</button>
            </div>
        </form>
        <form action="/salary/import/classes-csv" method="post" enctype="multipart/form-data">
            <div class="stack">
                <strong>班別 CSV 匯入</strong>
                <div class="muted">欄位建議：teacher_name, area, school_name, weekday, lesson_time, salary_per_hour, total_lessons, completed_lessons, lessons_this_month, is_active</div>
                <input type="file" name="file" accept=".csv,text/csv" required>
                <label><input type="checkbox" name="replace" value="1"> 覆蓋現有班別資料</label>
                <button type="submit" class="btn btn-primary">匯入班別 CSV</button>
            </div>
        </form>
        <form action="/salary/reset-data" method="post" onsubmit="return confirm('確定清空導師、班別同薪酬記錄？');">
            <button type="submit" class="btn btn-outline">清空導師 / 班別 / 薪酬</button>
        </form>
    </div>
    <div class="alert-info">手動匯入仍然保留，適合少量臨時補資料。</div>
    <form action="/salary/import" method="post">
    <table><thead><tr><th>地區</th><th>學校名稱</th><th>星期</th><th>時間</th><th>導師</th><th>銀行名稱</th><th>戶口號碼</th><th>FPS ID</th><th>時薪</th><th>已上</th><th>本月</th><th>總堂數</th></tr></thead><tbody id="rows">
    """
    # Default example row
    body += """<tr><td><input name="area[]" style="width:90px;padding:6px;border:1px solid #ccc;border-radius:4px;"></td>
    <td><input name="school[]" style="width:190px;padding:6px;border:1px solid #ccc;border-radius:4px;"></td>
    <td><input name="weekday[]" style="width:70px;padding:6px;border:1px solid #ccc;border-radius:4px;"></td>
    <td><input name="lesson_time[]" style="width:100px;padding:6px;border:1px solid #ccc;border-radius:4px;"></td>
    <td><input name="teacher[]" style="width:80px;padding:6px;border:1px solid #ccc;border-radius:4px;"></td>
    <td><input name="bank_name[]" style="width:120px;padding:6px;border:1px solid #ccc;border-radius:4px;"></td>
    <td><input name="bank_account_number[]" style="width:120px;padding:6px;border:1px solid #ccc;border-radius:4px;"></td>
    <td><input name="fps_id[]" style="width:110px;padding:6px;border:1px solid #ccc;border-radius:4px;"></td>
    <td><input name="rate[]" type="number" style="width:70px;padding:6px;border:1px solid #ccc;border-radius:4px;"></td>
    <td><input name="completed[]" type="number" style="width:60px;padding:6px;border:1px solid #ccc;border-radius:4px;"></td>
    <td><input name="monthly[]" type="number" style="width:60px;padding:6px;border:1px solid #ccc;border-radius:4px;"></td>
    <td><input name="total[]" type="number" style="width:60px;padding:6px;border:1px solid #ccc;border-radius:4px;"></td></tr>"""
    body += """
    </tbody></table>
    <div class="flex mt-2">
    <button type="button" class="btn btn-outline btn-small" onclick="addRow()">+ 加一行</button>
    <button type="submit" class="btn btn-primary">📥 批量匯入</button>
    </div></form>
    <script>
    function addRow() {
        const t = document.getElementById('rows');
        const tr = document.createElement('tr');
        tr.innerHTML = `<td><input name="area[]" style="width:90px;padding:6px;border:1px solid #ccc;border-radius:4px;"></td>
    <td><input name="school[]" style="width:190px;padding:6px;border:1px solid #ccc;border-radius:4px;"></td>
    <td><input name="weekday[]" style="width:70px;padding:6px;border:1px solid #ccc;border-radius:4px;"></td>
    <td><input name="lesson_time[]" style="width:100px;padding:6px;border:1px solid #ccc;border-radius:4px;"></td>
    <td><input name="teacher[]" style="width:80px;padding:6px;border:1px solid #ccc;border-radius:4px;"></td>
    <td><input name="bank_name[]" style="width:120px;padding:6px;border:1px solid #ccc;border-radius:4px;"></td>
    <td><input name="bank_account_number[]" style="width:120px;padding:6px;border:1px solid #ccc;border-radius:4px;"></td>
    <td><input name="fps_id[]" style="width:110px;padding:6px;border:1px solid #ccc;border-radius:4px;"></td>
    <td><input name="rate[]" type="number" style="width:70px;padding:6px;border:1px solid #ccc;border-radius:4px;"></td>
    <td><input name="completed[]" type="number" style="width:60px;padding:6px;border:1px solid #ccc;border-radius:4px;"></td>
    <td><input name="monthly[]" type="number" style="width:60px;padding:6px;border:1px solid #ccc;border-radius:4px;"></td>
    <td><input name="total[]" type="number" style="width:60px;padding:6px;border:1px solid #ccc;border-radius:4px;"></td>`;
        t.appendChild(tr);
    }
    </script>"""
    return render_salary_page("📥 匯入教務數據", body)


@app.post("/salary/import/teachers-csv")
async def salary_import_teachers_csv(
    file: UploadFile = File(...),
    replace: str = Form("0"),
    user: tuple = Depends(require_roles("admin", "finance")),
):
    imported = _import_teachers_csv_text(_csv_text_from_upload(file), replace=str(replace) == "1")
    return HTMLResponse(
        f"{SALARY_HEADER}<div class='container'><div class='card'><h3>✅ 導師 CSV 匯入完成</h3><p>成功匯入 {imported} 筆導師記錄。</p><br><a href='/salary/import' class='btn btn-primary'>返回</a></div></div>{SALARY_FOOTER}"
    )


@app.post("/salary/import/classes-csv")
async def salary_import_classes_csv(
    file: UploadFile = File(...),
    replace: str = Form("0"),
    user: tuple = Depends(require_roles("admin", "finance")),
):
    imported = _import_classes_csv_text(_csv_text_from_upload(file), replace=str(replace) == "1")
    return HTMLResponse(
        f"{SALARY_HEADER}<div class='container'><div class='card'><h3>✅ 班別 CSV 匯入完成</h3><p>成功匯入 {imported} 筆班別記錄。</p><br><a href='/salary/import' class='btn btn-primary'>返回</a></div></div>{SALARY_FOOTER}"
    )


@app.post("/salary/reset-data")
async def salary_reset_data(user: tuple = Depends(require_roles("admin", "finance"))):
    _clear_salary_data(clear_teachers=True)
    return HTMLResponse(
        f"{SALARY_HEADER}<div class='container'><div class='card'><h3>✅ 已清空導師 / 班別 / 薪酬記錄</h3><p>你可以重新上載新學年資料。</p><br><a href='/salary/import' class='btn btn-primary'>返回</a></div></div>{SALARY_FOOTER}"
    )

@app.post("/salary/import")
async def salary_import_post(
    area: List[str] = Form(...),
    school: List[str] = Form(...),
    weekday: List[str] = Form(...),
    lesson_time: List[str] = Form(...),
    teacher: List[str] = Form(...),
    bank_name: List[str] = Form(...),
    bank_account_number: List[str] = Form(...),
    fps_id: List[str] = Form(...),
    rate: List[str] = Form(...),
    completed: List[str] = Form(...),
    monthly: List[str] = Form(...),
    total: List[str] = Form(...),
    user: tuple = Depends(require_roles("admin", "finance"))
):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    imported = 0
    for i in range(len(school)):
        if not school[i].strip() or not teacher[i].strip():
            continue
        try:
            # Get or create teacher
            c.execute("INSERT OR IGNORE INTO teachers (name) VALUES (?)", (teacher[i].strip(),))
            conn.commit()
            c.execute("SELECT id FROM teachers WHERE name=?", (teacher[i].strip(),))
            tid = c.fetchone()[0]

            c.execute("""
                UPDATE teachers
                SET bank_name = CASE WHEN ? <> '' THEN ? ELSE bank_name END,
                    bank_account_number = CASE WHEN ? <> '' THEN ? ELSE bank_account_number END,
                    fps_id = CASE WHEN ? <> '' THEN ? ELSE fps_id END
                WHERE id=?
            """, (
                bank_name[i].strip(), bank_name[i].strip(),
                bank_account_number[i].strip(), bank_account_number[i].strip(),
                fps_id[i].strip(), fps_id[i].strip(),
                tid,
            ))
            
            c.execute("""
                INSERT INTO school_classes (teacher_id, area, school_name, weekday, lesson_time, salary_per_hour, total_lessons, completed_lessons, lessons_this_month)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                tid, area[i].strip(), school[i].strip(), weekday[i].strip(), lesson_time[i].strip(),
                float(rate[i] or 0), int(total[i] or 0),
                int(completed[i] or 0), int(monthly[i] or 0)
            ))
            imported += 1
        except Exception as e:
            print(f"Import error row {i}: {e}")
    conn.commit()
    conn.close()
    return HTMLResponse(f"{SALARY_HEADER}<div class='container'><div class='card'><h3>✅ 匯入完成</h3><p>成功匯入 {imported} 筆記錄。</p><br><a href='/salary' class='btn btn-primary'>返回 Dashboard</a></div></div>{SALARY_FOOTER}")

@app.get("/salary/teachers")
async def salary_teachers(user: tuple = Depends(require_roles("admin", "finance"))):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT t.id, t.name, t.bank_name, t.bank_account_number, t.fps_id, COUNT(sc.id),
               COALESCE(SUM(sc.completed_lessons * sc.salary_per_hour), 0)
        FROM teachers t
        LEFT JOIN school_classes sc ON sc.teacher_id = t.id AND sc.is_active=1
        WHERE t.is_active=1
        GROUP BY t.id ORDER BY t.name
    """)
    rows = c.fetchall()
    conn.close()
    
    html = "<table><thead><tr><th>導師</th><th>銀行名稱</th><th>戶口號碼</th><th>FPS / 轉數快</th><th>班數</th><th>本月薪酬</th><th></th></tr></thead><tbody>"
    for tid, name, bank_name, bank_account_number, fps_value, count, amt in rows:
        html += f"<tr><td><strong>{name}</strong></td><td>{bank_name or '-'}</td><td>{bank_account_number or '-'}</td><td>{fps_value or '-'}</td><td>{count} 班</td><td><strong>${amt:,.0f}</strong></td><td><a href='/salary/teacher/{tid}' class='btn btn-outline btn-small'>詳情</a></td></tr>"
    html += "</tbody></table>"
    return render_salary_page("👨‍🏫 導師列表", html)

@app.get("/salary/teacher/{tid}")
async def salary_teacher_detail(tid: int, user: tuple = Depends(require_roles("admin", "finance"))):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT name FROM teachers WHERE id=?", (tid,))
    t = c.fetchone()
    if not t:
        return HTMLResponse("導師不存在", status_code=404)
    name = t[0]
    
    c.execute("""
        SELECT area, school_name, weekday, lesson_time, salary_per_hour, total_lessons, completed_lessons, lessons_this_month, id
        FROM school_classes WHERE teacher_id=? AND is_active=1 ORDER BY weekday
    """, (tid,))
    classes = c.fetchall()
    
    c.execute("SELECT bank_name, bank_account_number, fps_id FROM teachers WHERE id=?", (tid,))
    bank_info = c.fetchone() or ("", "", "")

    c.execute("SELECT COALESCE(SUM(completed_lessons * salary_per_hour), 0) FROM school_classes WHERE teacher_id=? AND is_active=1", (tid,))
    monthly = c.fetchone()[0]
    conn.close()
    
    html = f"""
    <div class="stats">
        <div class="stat-card"><div class="num">{len(classes)}</div><div class="label">班別</div></div>
        <div class="stat-card"><div class="num">${monthly:,.0f}</div><div class="label">本月薪酬</div></div>
    </div>
    <div class="alert-info">銀行名稱：{bank_info[0] or '-'} ｜ 戶口號碼：{bank_info[1] or '-'} ｜ FPS / 轉數快：{bank_info[2] or '-'}</div>
    <table><thead><tr><th>地區</th><th>學校</th><th>星期 + 時間</th><th>時薪</th><th>總堂數</th><th>已上</th><th>本月</th></tr></thead><tbody>"""
    for sc in classes:
        html += f"<tr><td>{sc[0] or '-'}</td><td>{sc[1]}</td><td><span class='badge badge-blue'>{sc[2]} {sc[3] or ''}</span></td><td>${sc[4]:,.0f}</td><td>{sc[5]}</td><td>{sc[6]}</td><td><strong>{sc[7]}</strong></td></tr>"
    html += "</tbody></table>"
    current_month = datetime.now().month
    current_year = datetime.now().year
    month_options = "".join([
        f"<option value='{m}'{' selected' if m == current_month else ''}>{m:02d}</option>"
        for m in range(1, 13)
    ])
    year_options = "".join([
        f"<option value='{y}'{' selected' if y == current_year else ''}>{y}</option>"
        for y in range(current_year - 2, current_year + 2)
    ])
    html += f"""
    <form action='/salary/calculate/{tid}' method='get' class='flex mt-2'>
        <div>
            <label style='display:block;margin-bottom:4px;'>月份</label>
            <select name='month' style='padding:8px 10px;border:1px solid #d1d5db;border-radius:8px;'>{month_options}</select>
        </div>
        <div>
            <label style='display:block;margin-bottom:4px;'>年份</label>
            <select name='year' style='padding:8px 10px;border:1px solid #d1d5db;border-radius:8px;'>{year_options}</select>
        </div>
        <div style='align-self:end;'>
            <button type='submit' class='btn btn-primary btn-small'>📊 計算 / 儲存月份薪酬</button>
        </div>
    </form>"""
    return render_salary_page(f"👤 {name} 詳細", html)

@app.get("/salary/records")
async def salary_records(user: tuple = Depends(require_roles("admin", "finance"))):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT sr.id, t.name, sr.month, sr.year, sr.total_classes, sr.total_amount, sr.status
        FROM salary_records sr
        JOIN teachers t ON t.id = sr.teacher_id
        ORDER BY sr.year DESC, sr.month DESC, t.name
    """)
    rows = c.fetchall()
    conn.close()
    html = ""
    if rows:
        html = "<table><thead><tr><th>導師</th><th>月份</th><th>堂數</th><th>金額</th><th>狀態</th></tr></thead><tbody>"
        for r in rows:
            badge = "badge-green" if r[6] == "paid" else "badge-blue"
            s = "✅ 已支付" if r[6] == "paid" else "⏳ 待處理"
            html += f"<tr><td>{r[1]}</td><td>{r[3]}/{r[2]:02d}</td><td>{r[4]}</td><td><strong>${r[5]:,.0f}</strong></td><td><span class='badge {badge}'>{s}</span></td></tr>"
        html += "</tbody></table>"
    else:
        html = "<p style='color:#666;padding:20px;text-align:center;'>尚未有薪酬記錄，請先從 Dashboard 點選導師計算。</p>"
    return render_salary_page("📋 薪酬記錄", html)

@app.get("/salary/calculate/{tid}")
async def salary_calculate(
    tid: int,
    month: int = Query(default=None, ge=1, le=12),
    year: int = Query(default=None, ge=2000, le=2100),
    user: tuple = Depends(require_roles("admin", "finance")),
):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, name FROM teachers WHERE id=?", (tid,))
    t = c.fetchone()
    if not t:
        return HTMLResponse("導師不存在", status_code=404)
    
    c.execute("""
        SELECT area, school_name, weekday, lesson_time, salary_per_hour, total_lessons, completed_lessons, lessons_this_month
        FROM school_classes WHERE teacher_id=? AND is_active=1
    """, (tid,))
    classes = c.fetchall()
    
    month = month or datetime.now().month
    year = year or datetime.now().year
    total_classes = sum(x[6] for x in classes)
    total_amount = sum(x[4] * x[6] for x in classes)
    
    # Save or update this teacher's monthly record
    c.execute("""
        INSERT INTO salary_records (teacher_id, month, year, total_classes, total_amount, status, created_at)
        VALUES (?, ?, ?, ?, ?, 'pending', CURRENT_TIMESTAMP)
        ON CONFLICT(teacher_id, year, month) DO UPDATE SET
            total_classes=excluded.total_classes,
            total_amount=excluded.total_amount,
            status='pending',
            created_at=CURRENT_TIMESTAMP
    """, (tid, month, year, total_classes, total_amount))
    conn.commit()
    conn.close()
    
    html = f"""
    <div class="alert-info">✅ {t[1]} 的 {year}年{month:02d}月 薪酬已計算並儲存。</div>
    <div class="stats">
        <div class="stat-card"><div class="num">{total_classes}</div><div class="label">本月堂數</div></div>
        <div class="stat-card"><div class="num">${total_amount:,.0f}</div><div class="label">應付薪酬</div></div>
    </div>
    <table><thead><tr><th>地區</th><th>學校</th><th>星期 + 時間</th><th>時薪</th><th>已上堂數</th><th>小計</th></tr></thead><tbody>"""
    for c in classes:
        sub = c[4] * c[6]
        html += f"<tr><td>{c[0] or '-'}</td><td>{c[1]}</td><td><span class='badge badge-blue'>{c[2]} {c[3] or ''}</span></td><td>${c[4]:,.0f}</td><td>{c[6]}</td><td><strong>${sub:,.0f}</strong></td></tr>"
    html += f"""</tbody>
    <tfoot><tr style="font-weight:700;background:{BRAND_LIGHT};"><td colspan="5">總計</td><td>${total_amount:,.0f}</td></tr></tfoot></table>
    <br><a href="/salary/teacher/{tid}" class="btn btn-outline btn-small">← 返回</a>
    """
    return render_salary_page(f"📊 {t[1]} 薪酬計算", html)

@app.get("/salary/report")
async def salary_report(user: tuple = Depends(require_roles("admin", "finance"))):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT t.id, t.name, t.bank_name, t.bank_account_number, t.fps_id,
               COALESCE(SUM(sc.completed_lessons * sc.salary_per_hour), 0) AS amount
        FROM teachers t
        LEFT JOIN school_classes sc ON sc.teacher_id = t.id AND sc.is_active=1
        WHERE t.is_active=1
        GROUP BY t.id
        ORDER BY amount DESC, t.name
    """)
    teachers = c.fetchall()

    c.execute("""
        SELECT COUNT(*), COALESCE(SUM(completed_lessons * salary_per_hour), 0)
        FROM school_classes
        WHERE is_active=1
    """)
    class_stats = c.fetchone() or (0, 0)
    total_classes = class_stats[0] or 0
    total_amount = class_stats[1] or 0

    report_html = f"""
    <div class="print-bar no-print">
        <button class="btn btn-primary btn-small" onclick="window.print()">🖨️ 列印報表</button>
        <a href="/salary" class="btn btn-outline btn-small">← 返回 Dashboard</a>
    </div>
    <div class="stats">
        <div class="stat-card"><div class="num">{len(teachers)}</div><div class="label">導師</div></div>
        <div class="stat-card"><div class="num">{total_classes}</div><div class="label">班別</div></div>
        <div class="stat-card"><div class="num">${total_amount:,.0f}</div><div class="label">總支出</div></div>
    </div>
    <div class="report-box">
        <div class="report-title">支票備忘</div>
        <div class="muted">銀行名稱 + 戶口號碼 + 銀碼，方便即時出糧。</div>
        <table style="margin-top:10px;">
            <thead><tr><th>導師</th><th>銀行名稱</th><th>戶口號碼</th><th>FPS</th><th>銀碼</th></tr></thead>
            <tbody>"""
    for tid, name, bank_name, account_no, fps_value, amount in teachers:
        report_html += f"<tr><td><a href='/salary/teacher/{tid}'>{name}</a></td><td>{bank_name or '-'}</td><td>{account_no or '-'}</td><td>{fps_value or '-'}</td><td><strong>${amount:,.0f}</strong></td></tr>"
    report_html += """
            </tbody>
        </table>
    </div>"""

    for tid, name, bank_name, account_no, fps_value, amount in teachers:
        c.execute("""
            SELECT area, school_name, weekday, lesson_time, salary_per_hour, total_lessons, completed_lessons, lessons_this_month
            FROM school_classes
            WHERE teacher_id=? AND is_active=1
            ORDER BY weekday, school_name
        """, (tid,))
        classes = c.fetchall()
        report_html += f"""
        <div class="report-box">
            <div class="report-title">{name}</div>
            <div class="muted">銀行：{bank_name or '-'} ｜ 戶口：{account_no or '-'} ｜ FPS：{fps_value or '-'}</div>
            <div class="muted">導師時薪 × 已上堂數 = 本月薪酬</div>
            <table style="margin-top:10px;">
                <thead><tr><th>地區</th><th>學校</th><th>星期 + 時間</th><th>時薪</th><th>已上堂數</th><th>小計</th></tr></thead>
                <tbody>"""
        for sc in classes:
            sub = float(sc[4] or 0) * float(sc[6] or 0)
            report_html += f"<tr><td>{sc[0] or '-'}</td><td>{sc[1]}</td><td><span class='badge badge-blue'>{sc[2]} {sc[3] or ''}</span></td><td>${sc[4]:,.0f}</td><td>{sc[6]}</td><td><strong>${sub:,.0f}</strong></td></tr>"
        report_html += f"""
                </tbody>
                <tfoot><tr style="font-weight:700;background:{BRAND_LIGHT};"><td colspan="5">導師小計</td><td>${amount:,.0f}</td></tr></tfoot>
            </table>
        </div>"""

    conn.close()
    return render_salary_page("📄 薪酬總報表", report_html)

@app.get("/salary/classes")
async def salary_classes(user: tuple = Depends(require_roles("admin", "finance"))):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT sc.area, sc.school_name, sc.weekday, sc.lesson_time, t.id, t.name, sc.salary_per_hour, sc.total_lessons, sc.completed_lessons, sc.lessons_this_month
        FROM school_classes sc
        JOIN teachers t ON t.id = sc.teacher_id
        WHERE sc.is_active=1
        ORDER BY sc.weekday, sc.school_name
    """)
    rows = c.fetchall()
    conn.close()
    if not rows:
        html = "<p style='color:#666;padding:20px;text-align:center;'>尚未匯入班別數據。</p>"
    else:
        days = ["星期一", "星期二", "星期三", "星期四", "星期五", "星期六", "星期日"]
        html = "<table><thead><tr><th>地區</th><th>學校名稱</th><th>星期 + 時間</th><th>導師 Link</th><th>時薪</th><th>總堂數</th><th>已上</th><th>本月</th></tr></thead><tbody>"
        for r in sorted(rows, key=lambda x: (days.index(x[2]) if x[2] in days else 99, x[1])):
            html += f"<tr><td>{r[0] or '-'}</td><td>{r[1]}</td><td><span class='badge badge-blue'>{r[2]} {r[3] or ''}</span></td><td><a href='/salary/teacher/{r[4]}' class='btn btn-outline btn-small'>{r[5]}</a></td><td>${r[6]:,.0f}</td><td>{r[7]}</td><td>{r[8]}</td><td><strong>{r[9]}</strong></td></tr>"
        html += "</tbody></table>"
    return render_salary_page("🏫 班別列表", html)


@app.post("/api/db/query")
async def db_query(request: Request, user: tuple = Depends(require_roles("admin", allow_basic_auth=True))):
    payload = await request.json()
    sql = (payload.get("sql") or "").strip()
    params = payload.get("params") or []
    fetch = bool(payload.get("fetch", True))
    if not sql:
        raise HTTPException(status_code=400, detail="SQL is required")

    conn = _REAL_SQLITE_CONNECT(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute(sql, params)
        rows = []
        columns = []
        if fetch and cursor.description:
            columns = [col[0] for col in cursor.description]
            rows = cursor.fetchall()
        else:
            conn.commit()
        response = {
            "ok": True,
            "rows": rows,
            "columns": columns,
            "rowcount": cursor.rowcount,
            "lastrowid": cursor.lastrowid,
        }
        if fetch and not cursor.description:
            conn.commit()
        return response
    finally:
        conn.close()

# =========================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    if uvicorn is None:
        raise RuntimeError("uvicorn is not installed in this environment")
    uvicorn.run(app, host="0.0.0.0", port=port)


@app.get("/healthz")
async def healthz():
    return {"ok": True, "app": APP_NAME}
