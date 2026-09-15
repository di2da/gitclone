import os
import sqlite3
import json
import csv
import html
import re
import base64
import urllib.request
from urllib.parse import quote, urlencode
import subprocess
import tempfile
import shutil
import secrets
import hashlib
import hmac
import unicodedata
import zipfile
import time
from xml.sax.saxutils import escape as xml_escape
from fastapi import FastAPI, Form, File, UploadFile, Response, Request, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from PIL import Image, ImageDraw, ImageFont
import io
import traceback
import ssl
from datetime import datetime, timedelta, timezone
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
    from reportlab.pdfgen import canvas
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import HRFlowable, Image as RLImage, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False

try:
    from pypdf import PdfReader, PdfWriter
    PYPDF_AVAILABLE = True
except Exception:
    PYPDF_AVAILABLE = False

app = FastAPI()
@app.exception_handler(Exception)
async def debug_exception_handler(request: Request, exc: Exception):
    import traceback
    return HTMLResponse(
        content=f"<html><body style='font-family:sans-serif;padding:20px;'><h1>Internal Server Error (Debug)</h1><p><b>Error:</b> {html.escape(str(exc))}</p><pre style='background:#eee;padding:10px;border-radius:5px;'>{html.escape(traceback.format_exc())}</pre></body></html>",
        status_code=500
    )
security = HTTPBasic(auto_error=False)
BASE_DIR = Path(__file__).resolve().parent
PANTENE_FOODIE_DIR = BASE_DIR / "projects" / "pantene-foodie-journey"
FONT_DIR = BASE_DIR / "assets" / "fonts"
CACHE_FONT_DIR = Path(os.environ.get("DOCMAGIC_FONT_CACHE", "/tmp/docmagic-fonts"))
APP_NAME = "DK Admin V10"
APP_TAGLINE = "軍團報價、發票、收據與薪酬管理系統"
SCRC_BASE_PDF_PATH = BASE_DIR / "api" / "SCRC_Template.pdf"
SCRC_COORDINATE_MAP_PATH = BASE_DIR / "scrc_overlay_coordinates.json"
SCRC_ORG_NAME = "狄易達軍團跳舞學校"
SCRC_ORG_ADDRESS_LINES = [
    "香港九龍紅磡鶴園街2G號",
    "恒豐工業大廈1期",
    "3樓C室",
]
SCRC_SIGNATORY_DEFAULT = "廖成達校長"
SCRC_SIGNATURE_PNG = BASE_DIR / "signature.png"
SCRC_STAMP_PNG = BASE_DIR / "stamp.png"


@app.exception_handler(Exception)
async def debug_exception_handler(request: Request, exc: Exception):
    import traceback
    return HTMLResponse(
        content=f"<html><body><h1>Internal Server Error (Debug)</h1><pre>{html.escape(traceback.format_exc())}</pre></body></html>",
        status_code=500
    )

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


@app.middleware("http")
async def _security_gate_middleware(request: Request, call_next):
    request.state.request_id = _request_id()
    method = request.method.upper()
    unsafe_method = method in {"POST", "PUT", "PATCH", "DELETE"}

    if unsafe_method:
        if request.url.path == "/api/db/query":
            service_actor = _service_auth_from_request(request)
            if not service_actor:
                _audit_action_request(request, "raw_sql_bridge", target_type="bridge", target_id="", result="denied", metadata={"reason": "service_auth_missing"})
                return Response("Unauthorized", status_code=401)
            content_type = (request.headers.get("content-type") or "").lower()
            if "application/json" not in content_type:
                _audit_action_request(request, "raw_sql_bridge", target_type="bridge", target_id="", result="denied", metadata={"reason": "content_type"})
                return Response("Unsupported Media Type", status_code=415)
            try:
                body = await request.body()
            except Exception:
                _audit_action_request(request, "raw_sql_bridge", target_type="bridge", target_id="", result="denied", metadata={"reason": "body_read_failed"})
                return Response("Bad Request", status_code=400)
            if len(body) > 64 * 1024:
                _audit_action_request(request, "raw_sql_bridge", target_type="bridge", target_id="", result="denied", metadata={"reason": "body_too_large"})
                return Response("Payload Too Large", status_code=413)
        elif request.url.path == "/login":
            if not _origin_allowed(request):
                _audit_action_request(request, "login_origin_denied", target_type="route", target_id="/login", result="denied", metadata={"origin": _extract_request_origin(request)})
                return Response("Forbidden", status_code=403)
        else:
            if not _origin_allowed(request):
                actor = _current_user_record(request)
                _audit_action_request(request, "origin_denied", result="denied", metadata={"origin": _extract_request_origin(request)}, actor=actor)
                return Response("Forbidden", status_code=403)
            token = _current_session_token(request)
            if token:
                session_row = _session_lookup_by_token(token)
                if not session_row:
                    return Response("Unauthorized", status_code=401)
                provided = await _request_csrf_token(request)
                expected = str(session_row[6] or "").strip()
                if not provided or not expected or not secrets.compare_digest(provided, expected):
                    actor = session_row if session_row else None
                    _audit_action_request(request, "csrf_denied", result="denied", metadata={"path": request.url.path}, actor=actor)
                    return Response("Forbidden", status_code=403)

    response = await call_next(request)
    return response

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
LOCAL_ALLOWED_ORIGINS = {
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "http://127.0.0.1:8010",
    "http://localhost:8010",
}
PRODUCTION_ALLOWED_ORIGINS = {
    "https://invoice.dancekingdom.com.hk",
    "https://dk-admin-v10.vercel.app",
}
SERVICE_AUTH_USER = os.environ.get("DOCMAGIC_DB_SERVICE_USER", "").strip()
SERVICE_AUTH_PASSWORD = os.environ.get("DOCMAGIC_DB_SERVICE_PASSWORD", "").strip()
ALLOWED_ORIGINS_ENV = os.environ.get("DOCMAGIC_ALLOWED_ORIGINS", "").strip()
DOCMAGIC_ENV = os.environ.get("DOCMAGIC_ENV", "").strip().lower()
DOCMAGIC_SECURE_COOKIE = os.environ.get("DOCMAGIC_SECURE_COOKIE", "").strip().lower()


def _is_production():
    if DOCMAGIC_ENV in {"production", "prod"}:
        return True
    return bool(os.environ.get("VERCEL") or os.environ.get("VERCEL_ENV") == "production")


def _should_secure_cookie():
    if DOCMAGIC_SECURE_COOKIE in {"1", "true", "yes", "on"}:
        return True
    if DOCMAGIC_SECURE_COOKIE in {"0", "false", "no", "off"}:
        return False
    return _is_production()


def _allowed_origins():
    origins = set(LOCAL_ALLOWED_ORIGINS) | set(PRODUCTION_ALLOWED_ORIGINS)
    if ALLOWED_ORIGINS_ENV:
        origins.update({item.strip().rstrip("/") for item in ALLOWED_ORIGINS_ENV.split(",") if item.strip()})
    return origins


def _utc_now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _request_id():
    return secrets.token_urlsafe(18)


def _mask_bank_account(value):
    text = str(value or "").strip()
    if not text:
        return ""
    digits = re.sub(r"\D", "", text)
    if len(digits) <= 4:
        return "****"
    return f"****{digits[-4:]}"


def _session_cookie_options():
    expires = datetime.now(timezone.utc) + timedelta(hours=SESSION_TTL_HOURS)
    return {
        "httponly": True,
        "secure": _should_secure_cookie(),
        "samesite": "lax",
        "path": "/",
        "max_age": SESSION_TTL_HOURS * 3600,
        "expires": expires,
    }


def _extract_request_origin(request: Request):
    origin = (request.headers.get("origin") or "").strip()
    if origin:
        return origin.rstrip("/")
    referer = (request.headers.get("referer") or "").strip()
    if referer:
        try:
            from urllib.parse import urlsplit

            parts = urlsplit(referer)
            if parts.scheme and parts.netloc:
                return f"{parts.scheme}://{parts.netloc}".rstrip("/")
        except Exception:
            return None
    return None


def _request_base_origin(request: Request):
    host = (request.headers.get("x-forwarded-host") or request.headers.get("host") or "").strip()
    if not host:
        return None
    host = host.split(",")[0].strip()
    proto = (request.headers.get("x-forwarded-proto") or request.url.scheme or "").strip().lower()
    if proto not in {"http", "https"}:
        proto = "https" if request.url.scheme == "https" else "http"
    return f"{proto}://{host}".rstrip("/")


def _origin_hostname(origin: str):
    try:
        from urllib.parse import urlsplit

        return (urlsplit(origin).hostname or "").strip().lower()
    except Exception:
        return ""


def _origin_hosts_match(request: Request, origin: str):
    try:
        from urllib.parse import urlsplit

        request_host = (request.headers.get("x-forwarded-host") or request.headers.get("host") or "").strip()
        if not request_host:
            return False
        request_host = request_host.split(",")[0].strip().lower()
        origin_host = (urlsplit(origin).netloc or "").strip().lower()
        if not origin_host:
            return False
        return origin_host == request_host
    except Exception:
        return False


def _origin_allowed(request: Request):
    origin = _extract_request_origin(request)
    if not origin:
        return True
    if origin.rstrip("/") in _allowed_origins():
        return True
    base_origin = _request_base_origin(request)
    if base_origin and origin.rstrip("/") == base_origin.rstrip("/"):
        return True
    origin_host = _origin_hostname(origin)
    request_host = _origin_hostname(base_origin or "")
    if origin_host in {"localhost", "127.0.0.1"} and request_host in {"localhost", "127.0.0.1"}:
        return True
    return _origin_hosts_match(request, origin)


def _service_auth_from_request(request: Request):
    header = (request.headers.get("authorization") or "").strip()
    if not header.lower().startswith("basic "):
        return None
    try:
        token = header.split(" ", 1)[1].strip()
        raw = base64.b64decode(token).decode("utf-8")
        username, password = raw.split(":", 1)
    except Exception:
        return None
    if not SERVICE_AUTH_USER or not SERVICE_AUTH_PASSWORD:
        return None
    if hmac.compare_digest(username, SERVICE_AUTH_USER) and hmac.compare_digest(password, SERVICE_AUTH_PASSWORD):
        return {"username": username}
    return None


def require_service_auth(request: Request):
    actor = _service_auth_from_request(request)
    if not actor:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return actor


def _current_session_token(request: Request):
    return request.cookies.get("docmagic_session")


def _csrf_header_token(request: Request):
    return (request.headers.get("x-csrf-token") or "").strip()


async def _request_csrf_token(request: Request):
    header_token = _csrf_header_token(request)
    if header_token:
        return header_token
    try:
        body = await request.body()
    except Exception:
        return ""
    if not body:
        return ""
    content_type = (request.headers.get("content-type") or "").lower()
    if "application/json" in content_type:
        try:
            payload = json.loads(body.decode("utf-8"))
            if isinstance(payload, dict):
                token = (payload.get("csrf_token") or "").strip()
                if token:
                    return token
        except Exception:
            return ""
    if "application/x-www-form-urlencoded" in content_type:
        try:
            from urllib.parse import parse_qs

            parsed = parse_qs(body.decode("utf-8", errors="ignore"), keep_blank_values=True)
            token = (parsed.get("csrf_token") or [""])[0].strip()
            if token:
                return token
        except Exception:
            return ""
    if "multipart/form-data" in content_type:
        try:
            match = re.search(rb'name="csrf_token"\r?\n\r?\n([^\r\n]+)', body, re.IGNORECASE)
            if match:
                return match.group(1).decode("utf-8", errors="ignore").strip()
        except Exception:
            return ""
    return ""


def _audit_safe_payload(value):
    if value is None:
        return None
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if any(secret in lowered for secret in ("password", "token", "session", "authorization", "api_key", "apikey", "csrf")):
                continue
            if "bank" in lowered:
                if "account" in lowered:
                    result[key] = _mask_bank_account(item)
                else:
                    result[key] = item
                continue
            result[key] = _audit_safe_payload(item)
        return result
    if isinstance(value, list):
        return [_audit_safe_payload(item) for item in value]
    text = str(value)
    if len(text) > 200:
        return text[:200]
    return value


def _audit_action_request(request: Request, action: str, target_type: str = "", target_id: str = "", result: str = "ok", before=None, after=None, metadata=None, actor=None):
    return _write_audit_log(
        request=request,
        action=action,
        target_type=target_type,
        target_id=target_id,
        result=result,
        before_json=before,
        after_json=after,
        metadata_json=metadata,
        actor=actor,
    )


def _session_lookup_by_token(token: str):
    conn = sqlite3.connect(DB_PATH, timeout=30)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT u.id, u.username, u.display_name, u.role, u.is_active, s.expires_at, s.csrf_token
        FROM app_sessions s
        JOIN app_users u ON u.username = s.username
        WHERE s.token=? AND u.is_active=1
        """,
        (token,),
    )
    row = cursor.fetchone()
    conn.close()
    return row


def _now():
    return datetime.now().replace(microsecond=0)


def _fmt_dt(value: datetime):
    return value.strftime("%Y-%m-%d %H:%M:%S")


def _cn_date_text(value: Optional[datetime] = None):
    value = value or datetime.now()
    digits = {
        "0": "零",
        "1": "一",
        "2": "二",
        "3": "三",
        "4": "四",
        "5": "五",
        "6": "六",
        "7": "七",
        "8": "八",
        "9": "九",
    }

    def convert_number(number: int):
        if number == 10:
            return "十"
        if number < 10:
            return digits[str(number)]
        if number < 20:
            return "十" + (digits[str(number % 10)] if number % 10 else "")
        tens, ones = divmod(number, 10)
        return digits[str(tens)] + "十" + (digits[str(ones)] if ones else "")

    year_text = "".join(digits[ch] for ch in str(value.year))
    return f"{year_text}年{convert_number(value.month)}月{convert_number(value.day)}日"


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

    conn = sqlite3.connect(DB_PATH, timeout=30)
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

def _retry_sqlite_locked(operation):
    def wrapped(*args, **kwargs):
        retries = 6
        delay = 0.25
        last_error = None
        for attempt in range(retries):
            try:
                return operation(*args, **kwargs)
            except sqlite3.OperationalError as exc:
                last_error = exc
                if "locked" not in str(exc).lower() or attempt >= retries - 1:
                    raise
                time.sleep(delay * (attempt + 1))
        if last_error is not None:
            raise last_error

    return wrapped


def _is_sqlite_locked_error(exc: Exception) -> bool:
    return "locked" in str(exc).lower()


def _html_error_page(title: str, message: str, back_href: str):
    return HTMLResponse(
        f"""
        <html lang="zh-HK">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>{html.escape(title)}</title>
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, "PingFang HK", "Noto Sans TC", sans-serif; margin: 0; padding: 24px; background: #faf7f0; color: #111; }}
                .wrap {{ max-width: 860px; margin: 0 auto; }}
                .card {{ background: #fff; border: 1px solid #e5e7eb; border-radius: 18px; padding: 20px; box-shadow: 0 14px 40px rgba(17,24,39,.06); }}
                .msg {{ background: #f4ead2; border-radius: 14px; padding: 14px 16px; line-height: 1.6; }}
                a {{ display: inline-block; margin-top: 16px; text-decoration: none; color: #111; background: #fff; border: 1px solid #d1d5db; padding: 10px 14px; border-radius: 999px; }}
            </style>
        </head>
        <body>
            <div class="wrap">
                <div class="card">
                    <h2>{html.escape(title)}</h2>
                    <div class="msg">{html.escape(message)}</div>
                    <a href="{html.escape(back_href, quote=True)}">返回</a>
                </div>
            </div>
        </body>
        </html>
        """,
        status_code=500,
    )

@_retry_sqlite_locked
def _ensure_user_table():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    cursor = conn.cursor()
    try:
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.execute("PRAGMA journal_mode=WAL")
    except Exception:
        pass
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


@_retry_sqlite_locked
def _ensure_session_table():
    conn = _bootstrap_sqlite_connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS app_sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            display_name TEXT,
            csrf_token TEXT,
            expires_at TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("PRAGMA table_info(app_sessions)")
    cols = {row[1] for row in cursor.fetchall()}
    if "csrf_token" not in cols:
        cursor.execute("ALTER TABLE app_sessions ADD COLUMN csrf_token TEXT")
    if "expires_at" not in cols:
        cursor.execute("ALTER TABLE app_sessions ADD COLUMN expires_at TEXT")
    conn.commit()
    conn.close()


@_retry_sqlite_locked
def _ensure_audit_table():
    conn = _bootstrap_sqlite_connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            created_at_utc TEXT NOT NULL,
            request_id TEXT NOT NULL,
            actor_user_id INTEGER,
            actor_username TEXT,
            normalized_role TEXT,
            action TEXT NOT NULL,
            target_type TEXT,
            target_id TEXT,
            route TEXT,
            http_method TEXT,
            result TEXT NOT NULL,
            source_ip TEXT,
            user_agent TEXT,
            before_json TEXT,
            after_json TEXT,
            metadata_json TEXT
        )
    """)
    conn.commit()
    conn.close()


@_retry_sqlite_locked
def _ensure_common_clients_table():
    conn = _bootstrap_sqlite_connect(DB_PATH)
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


@_retry_sqlite_locked
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
    conn = _bootstrap_sqlite_connect(DB_PATH)
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


@_retry_sqlite_locked
def _dedupe_common_clients():
    conn = _bootstrap_sqlite_connect(DB_PATH)
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
    conn = _bootstrap_sqlite_connect(DB_PATH)
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


@_retry_sqlite_locked
def _ensure_announcements_table():
    conn = _bootstrap_sqlite_connect(DB_PATH)
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


@_retry_sqlite_locked
def _ensure_pantene_meeting_tables():
    conn = _bootstrap_sqlite_connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
    except Exception:
        pass
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pantene_meetings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL,
            meeting_date TEXT NOT NULL,
            district TEXT DEFAULT '',
            budget TEXT DEFAULT '',
            share_permission TEXT NOT NULL DEFAULT 'vote',
            expires_at TEXT,
            is_active INTEGER DEFAULT 1,
            created_by TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pantene_meeting_candidates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT NOT NULL UNIQUE,
            meeting_id INTEGER NOT NULL,
            restaurant_name TEXT NOT NULL,
            district TEXT DEFAULT '',
            cuisine TEXT DEFAULT '',
            note TEXT DEFAULT '',
            sort_order INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(meeting_id) REFERENCES pantene_meetings(id) ON DELETE CASCADE
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pantene_meeting_votes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            meeting_id INTEGER NOT NULL,
            candidate_id INTEGER NOT NULL,
            visitor_token TEXT NOT NULL,
            nickname TEXT NOT NULL,
            vote_value TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(meeting_id, candidate_id, visitor_token),
            FOREIGN KEY(meeting_id) REFERENCES pantene_meetings(id) ON DELETE CASCADE,
            FOREIGN KEY(candidate_id) REFERENCES pantene_meeting_candidates(id) ON DELETE CASCADE
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pantene_meeting_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            meeting_id INTEGER NOT NULL,
            visitor_token TEXT NOT NULL,
            nickname TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(meeting_id) REFERENCES pantene_meetings(id) ON DELETE CASCADE
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pantene_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_type TEXT NOT NULL DEFAULT 'meeting',
            target_token TEXT NOT NULL,
            parent_comment_id INTEGER,
            visitor_token TEXT NOT NULL,
            nickname TEXT NOT NULL,
            body TEXT NOT NULL,
            moderation_status TEXT NOT NULL DEFAULT 'visible',
            hidden_at TEXT,
            hidden_by TEXT,
            hidden_reason TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(parent_comment_id) REFERENCES pantene_comments(id) ON DELETE SET NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pantene_comment_reactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            comment_id INTEGER NOT NULL,
            visitor_token TEXT NOT NULL,
            emoji TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(comment_id, visitor_token),
            FOREIGN KEY(comment_id) REFERENCES pantene_comments(id) ON DELETE CASCADE
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_pantene_meetings_token ON pantene_meetings(token)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_pantene_candidates_meeting ON pantene_meeting_candidates(meeting_id, sort_order)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_pantene_votes_meeting_candidate ON pantene_meeting_votes(meeting_id, candidate_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_pantene_comments_meeting ON pantene_meeting_comments(meeting_id, id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_pantene_comments_target ON pantene_comments(target_type, target_token, id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_pantene_comment_reactions_comment ON pantene_comment_reactions(comment_id, emoji)")
    cursor.execute("SELECT COUNT(1) FROM pantene_comments")
    if (cursor.fetchone() or [0])[0] == 0:
        cursor.execute(
            """
            INSERT INTO pantene_comments (target_type, target_token, parent_comment_id, visitor_token, nickname, body, moderation_status, created_at, updated_at)
            SELECT 'meeting', m.token, NULL, c.visitor_token, c.nickname, c.body, 'visible', c.created_at, c.updated_at
            FROM pantene_meeting_comments c
            JOIN pantene_meetings m ON m.id = c.meeting_id
            ORDER BY c.id ASC
            """
        )
    conn.commit()
    conn.close()


def _pantene_normalize_permission(value: str):
    text = str(value or "").strip().lower()
    if text in {"read_only", "readonly", "read-only", "view", "view_only"}:
        return "read_only"
    if text in {"vote", "voting", "can_vote"}:
        return "vote"
    if text in {"comment", "comments", "can_comment"}:
        return "comment"
    return "vote"


def _pantene_permission_level(permission: str):
    order = {"read_only": 0, "vote": 1, "comment": 2}
    return order.get(_pantene_normalize_permission(permission), 1)


def _pantene_parse_date(value: str):
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).date().isoformat()
    except Exception:
        return text[:10]


def _pantene_parse_datetime(value: str):
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is not None:
            return parsed.astimezone().replace(tzinfo=None, microsecond=0)
        return parsed.replace(microsecond=0)
    except Exception:
        return None


def _pantene_meeting_is_expired(row):
    if not row:
        return True
    expires_at = _pantene_parse_datetime(row[7] if len(row) > 7 else "")
    if expires_at is None:
        return False
    return expires_at <= _now()


def _pantene_bundle_is_expired(bundle):
    meeting = (bundle or {}).get("meeting") or {}
    expires_at = _pantene_parse_datetime(meeting.get("expiresAt"))
    if expires_at is None:
        return False
    return expires_at <= _now()


def _pantene_visitor_token():
    return secrets.token_urlsafe(24)


def _pantene_public_meeting_payload(meeting_row):
    if not meeting_row:
        return None
    return {
        "token": meeting_row[1],
        "title": meeting_row[2],
        "meetingDate": _pantene_parse_date(meeting_row[3]),
        "district": meeting_row[4] or "",
        "budget": meeting_row[5] or "",
        "sharePermission": _pantene_normalize_permission(meeting_row[6]),
        "expiresAt": meeting_row[7] or "",
        "isActive": bool(meeting_row[8]),
        "notes": meeting_row[10] or "",
        "createdAt": meeting_row[11] or "",
        "updatedAt": meeting_row[12] or "",
    }


def _pantene_public_candidate_payload(candidate_row):
    return {
        "token": candidate_row[1],
        "restaurantName": candidate_row[3],
        "district": candidate_row[4] or "",
        "cuisine": candidate_row[5] or "",
        "note": candidate_row[6] or "",
        "sortOrder": candidate_row[7] or 0,
    }


def _pantene_vote_row_to_payload(row):
    return {
        "candidateToken": row[0],
        "voteValue": row[1],
        "nickname": row[2],
        "updatedAt": row[3] or "",
    }


def _pantene_comment_row_to_payload(row):
    return {
        "id": row[0],
        "targetType": row[1],
        "targetToken": row[2],
        "parentCommentId": row[3],
        "nickname": row[4],
        "body": row[5],
        "moderationStatus": row[6],
        "hiddenAt": row[7] or "",
        "hiddenBy": row[8] or "",
        "hiddenReason": row[9] or "",
        "createdAt": row[10] or "",
        "updatedAt": row[11] or "",
        "replies": [],
        "reactions": {},
    }


def _pantene_meeting_bundle(token: str, visitor_token: str = ""):
    conn = sqlite3.connect(DB_PATH, timeout=30)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, token, title, meeting_date, district, budget, share_permission, expires_at, is_active, created_by, notes, created_at, updated_at
        FROM pantene_meetings
        WHERE token=?
        """,
        (str(token).strip(),),
    )
    meeting_row = cursor.fetchone()
    if not meeting_row:
        conn.close()
        return None
    meeting_id = meeting_row[0]
    cursor.execute(
        """
        SELECT id, token, meeting_id, restaurant_name, district, cuisine, note, sort_order, created_at, updated_at
        FROM pantene_meeting_candidates
        WHERE meeting_id=?
        ORDER BY sort_order ASC, id ASC
        """,
        (meeting_id,),
    )
    candidate_rows = cursor.fetchall()
    cursor.execute(
        """
        SELECT v.visitor_token, v.vote_value, v.nickname, v.updated_at, v.candidate_id
        FROM pantene_meeting_votes v
        JOIN pantene_meeting_candidates c ON c.id = v.candidate_id
        WHERE v.meeting_id=?
        ORDER BY v.updated_at DESC, v.id DESC
        """,
        (meeting_id,),
    )
    vote_rows = cursor.fetchall()
    conn.close()

    votes_by_candidate = {}
    for candidate_row in candidate_rows:
        votes_by_candidate[candidate_row[0]] = {
            "want": 0,
            "okay": 0,
            "no": 0,
            "total": 0,
            "supportScore": 0,
            "controversial": False,
            "myVote": "",
            "myNickname": "",
        }

    my_votes = {}
    for token_value, vote_value, nickname, updated_at, candidate_id in vote_rows:
        current = votes_by_candidate.get(candidate_id)
        if not current:
            continue
        value = str(vote_value or "").strip()
        if value not in {"want", "okay", "no"}:
            continue
        current[value] += 1
        current["total"] += 1
        current["supportScore"] = current["want"] * 2 + current["okay"]
        current["controversial"] = current["want"] > 0 and current["no"] > 0
        if visitor_token and token_value == visitor_token:
            my_votes[candidate_id] = {"vote": value, "nickname": nickname or ""}

    candidate_payloads = []
    for candidate_row in candidate_rows:
        payload = _pantene_public_candidate_payload(candidate_row)
        summary = votes_by_candidate.get(candidate_row[0]) or {
            "want": 0,
            "okay": 0,
            "no": 0,
            "total": 0,
            "supportScore": 0,
            "controversial": False,
        }
        my_vote = my_votes.get(candidate_row[0], {})
        payload["votes"] = {
            **summary,
            "myVote": my_vote.get("vote", ""),
            "myNickname": my_vote.get("nickname", ""),
        }
        candidate_payloads.append(payload)

    top_score = max([item["votes"]["supportScore"] for item in candidate_payloads], default=0)
    top_candidates = [item["token"] for item in candidate_payloads if item["votes"]["supportScore"] == top_score and top_score > 0]
    tied_candidates = []
    if top_score > 0 and len(top_candidates) > 1:
        tied_candidates = top_candidates[:]
    controversial_candidates = [item["token"] for item in candidate_payloads if item["votes"]["controversial"]]
    comment_bundle = _pantene_comment_bundle("meeting", meeting_row[1], visitor_token=visitor_token)

    return {
        "meeting": _pantene_public_meeting_payload(meeting_row),
        "candidates": candidate_payloads,
        "comments": comment_bundle["comments"],
        "commentStats": comment_bundle["stats"],
        "summary": {
            "topScore": top_score,
            "topCandidates": top_candidates,
            "tiedCandidates": tied_candidates,
            "controversialCandidates": controversial_candidates,
            "totalVotes": sum(item["votes"]["total"] for item in candidate_payloads),
        },
    }


async def _pantene_request_json(request: Request):
    try:
        return await request.json()
    except Exception:
        return {}


def _pantene_request_visitor_token(request: Request, payload: dict):
    header = (request.headers.get("x-pantene-visitor-token") or "").strip()
    if header:
        return header
    body_token = str((payload or {}).get("visitorToken") or "").strip()
    if body_token:
        return body_token
    return ""


def _pantene_comment_target_type(value):
    text = str(value or "").strip().lower()
    if text in {"restaurant", "place", "candidate"}:
        return "restaurant"
    return "meeting"


def _pantene_comment_limit_ok(body: str):
    text = str(body or "").strip()
    if not text:
        return False, "留言不可留空"
    if len(text) > 240:
        return False, "留言不可超過 240 字"
    return True, ""


def _pantene_comment_flag(body: str):
    text = str(body or "").strip()
    lowered = text.lower()
    if any(token in lowered for token in ("http://", "https://", "www.", "mailto:", "tel:")):
        return "pending", "含連結"
    if re.search(r"[\w.-]+@[\w.-]+\.[a-zA-Z]{2,}", text):
        return "pending", "含電郵"
    if re.search(r"(?:\+?\d[\d\-\s]{6,}\d)", text):
        return "pending", "含電話"
    if re.search(r"(.)\1{9,}", text):
        return "pending", "重複字元過多"
    return "visible", ""


def _pantene_comment_rate_limited(conn, target_type: str, target_token: str, visitor_token: str):
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT COUNT(1)
        FROM pantene_comments
        WHERE target_type=? AND target_token=? AND visitor_token=? AND datetime(created_at) >= datetime('now', '-20 seconds')
        """,
        (target_type, target_token, visitor_token),
    )
    row = cursor.fetchone()
    recent_same_target = row[0] if row else 0
    cursor.execute(
        """
        SELECT COUNT(1)
        FROM pantene_comments
        WHERE visitor_token=? AND datetime(created_at) >= datetime('now', '-10 minutes')
        """,
        (visitor_token,),
    )
    row = cursor.fetchone()
    recent_total = row[0] if row else 0
    return recent_same_target > 0 or recent_total >= 6


def _pantene_comment_thread(conn, target_type: str, target_token: str, visitor_token: str = ""):
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT
            c.id, c.target_type, c.target_token, c.parent_comment_id, c.nickname, c.body,
            c.moderation_status, c.hidden_at, c.hidden_by, c.hidden_reason, c.created_at, c.updated_at
        FROM pantene_comments c
        WHERE c.target_type=? AND c.target_token=?
        ORDER BY c.id ASC
        """,
        (target_type, target_token),
    )
    rows = cursor.fetchall()
    comments = {}
    for row in rows:
        payload = _pantene_comment_row_to_payload(row)
        if payload.get("moderationStatus") == "hidden":
            continue
        comments[row[0]] = payload
    cursor.execute(
        """
        SELECT comment_id, visitor_token, emoji, COUNT(1)
        FROM pantene_comment_reactions
        WHERE comment_id IN (
            SELECT id FROM pantene_comments WHERE target_type=? AND target_token=?
        )
        GROUP BY comment_id, visitor_token, emoji
        """,
        (target_type, target_token),
    )
    reaction_rows = cursor.fetchall()
    for comment_id, token_value, emoji, count in reaction_rows:
        item = comments.get(comment_id)
        if not item:
            continue
        item.setdefault("reactions", {})
        item["reactions"][emoji] = item["reactions"].get(emoji, 0) + int(count or 0)
        if visitor_token and token_value == visitor_token:
            item["myReaction"] = emoji
    roots = []
    for comment in comments.values():
        parent_id = comment.get("parentCommentId")
        if parent_id and parent_id in comments:
            comments[parent_id].setdefault("replies", []).append(comment)
        else:
            roots.append(comment)
    roots.sort(key=lambda item: item.get("id", 0))
    for item in comments.values():
        item.setdefault("replies", []).sort(key=lambda reply: reply.get("id", 0))
    return roots


def _pantene_comment_bundle(target_type: str, target_token: str, visitor_token: str = ""):
    conn = sqlite3.connect(DB_PATH, timeout=30)
    try:
        thread = _pantene_comment_thread(conn, target_type, target_token, visitor_token=visitor_token)
        return {
            "comments": thread,
            "stats": _pantene_comment_stats(thread),
        }
    finally:
        conn.close()


def _pantene_comment_stats(thread):
    visible = 0
    pending = 0
    hidden = 0
    for comment in thread:
        status = comment.get("moderationStatus", "visible")
        if status == "hidden":
            hidden += 1
        elif status == "pending":
            pending += 1
        else:
            visible += 1
        for reply in comment.get("replies", []) or []:
            rstatus = reply.get("moderationStatus", "visible")
            if rstatus == "hidden":
                hidden += 1
            elif rstatus == "pending":
                pending += 1
            else:
                visible += 1
    return {"visible": visible, "pending": pending, "hidden": hidden}


def _pantene_comment_target_allowed(target_type: str, target_token: str):
    ttype = _pantene_comment_target_type(target_type)
    token = str(target_token or "").strip()
    if not token:
        return False
    if ttype == "meeting":
        bundle = _pantene_meeting_bundle(token)
        if not bundle:
            return False
        meeting = bundle["meeting"] or {}
        return bool(meeting.get("isActive")) and not _pantene_bundle_is_expired(bundle)
    if ttype == "restaurant":
        return True
    return False

def _pantene_payload_candidates(payload):
    candidates = payload.get("candidates") if isinstance(payload, dict) else []
    if not isinstance(candidates, list):
        return []
    normalized = []
    for index, item in enumerate(candidates):
        if not isinstance(item, dict):
            continue
        name = str(item.get("restaurantName") or item.get("name") or "").strip()
        if not name:
            continue
        normalized.append({
            "token": secrets.token_urlsafe(10),
            "restaurantName": name,
            "district": str(item.get("district") or "").strip(),
            "cuisine": str(item.get("cuisine") or "").strip(),
            "note": str(item.get("note") or "").strip(),
            "sortOrder": int(item.get("sortOrder") or index),
        })
    return normalized


def _lock_until(minutes: int):
    return _fmt_dt(_now() + timedelta(minutes=minutes))


def _session_expires_at():
    return _fmt_dt(_now() + timedelta(hours=SESSION_TTL_HOURS))


def _cleanup_expired_sessions(conn=None):
    own_conn = False
    if conn is None:
        conn = _bootstrap_sqlite_connect(DB_PATH)
        own_conn = True
    cursor = conn.cursor()
    cursor.execute("DELETE FROM app_sessions WHERE expires_at IS NOT NULL AND expires_at < ?", (_fmt_dt(_now()),))
    if own_conn:
        conn.commit()
        conn.close()


def _get_user_by_username(username: str):
    conn = _bootstrap_sqlite_connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
    except Exception:
        pass
    cursor.execute(
        "SELECT id, username, password, display_name, role, is_active, failed_attempts, locked_until FROM app_users WHERE username=?",
        (username,),
    )
    row = cursor.fetchone()
    conn.close()
    return row


def _get_user_by_token(token: str):
    conn = _bootstrap_sqlite_connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT u.id, u.username, u.display_name, u.role, u.is_active, s.expires_at, s.csrf_token
        FROM app_sessions s
        JOIN app_users u ON u.username = s.username
        WHERE s.token=? AND u.is_active=1
        """,
        (token,),
    )
    row = cursor.fetchone()
    conn.close()
    return row


def _write_audit_log(
    request: Request,
    action: str,
    target_type: str = "",
    target_id: str = "",
    result: str = "ok",
    before_json=None,
    after_json=None,
    metadata_json=None,
    actor=None,
):
    request_id = getattr(request.state, "request_id", None) or _request_id()
    event_id = _request_id()
    if actor is None:
        actor = _current_user_record(request)
    if isinstance(actor, dict):
        actor_user_id = actor.get("id")
        actor_username = actor.get("username")
        normalized_role = _normalize_role(actor.get("role"))
    else:
        actor_user_id = actor[0] if actor else None
        actor_username = actor[1] if actor else None
        normalized_role = _normalize_role(actor[3]) if actor else ""
    row_before = json.dumps(_audit_safe_payload(before_json), ensure_ascii=False) if before_json is not None else None
    row_after = json.dumps(_audit_safe_payload(after_json), ensure_ascii=False) if after_json is not None else None
    row_metadata = json.dumps(_audit_safe_payload(metadata_json), ensure_ascii=False) if metadata_json is not None else None
    conn = _bootstrap_sqlite_connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO audit_logs (
            event_id, created_at_utc, request_id, actor_user_id, actor_username, normalized_role,
            action, target_type, target_id, route, http_method, result, source_ip, user_agent,
            before_json, after_json, metadata_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_id,
            _utc_now_iso(),
            request_id,
            actor_user_id,
            actor_username,
            normalized_role,
            action,
            target_type,
            str(target_id or ""),
            request.url.path,
            request.method,
            result,
            request.client.host if request.client else "",
            request.headers.get("user-agent", ""),
            row_before,
            row_after,
            row_metadata,
        ),
    )
    conn.commit()
    conn.close()
    return event_id


def _current_session_csrf_token(request: Request):
    token = _current_session_token(request)
    if not token:
        return ""
    row = _session_lookup_by_token(token)
    if not row:
        return ""
    return str(row[6] or "").strip()


def _csrf_input_html(request: Request):
    token = _current_session_csrf_token(request)
    if not token:
        return ""
    return f'<input type="hidden" name="csrf_token" value="{html.escape(token)}">'


def _csrf_fetch_script(request: Request):
    token = _current_session_csrf_token(request)
    if not token:
        return ""
    token_json = json.dumps(token)
    return f"""
    <script>
    window.DOCMAGIC_CSRF_TOKEN = {token_json};
    (function() {{
        const originalFetch = window.fetch.bind(window);
        window.fetch = function(input, init) {{
            const options = init ? {{ ...init }} : {{}};
            try {{
                const method = String(options.method || (input && typeof input === 'object' && input.method) || 'GET').toUpperCase();
                const target = typeof input === 'string' ? input : '';
                const sameOrigin = !target || target.startsWith('/') || target.startsWith(window.location.origin);
                if (sameOrigin && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {{
                    const headers = new Headers(options.headers || (input && typeof input === 'object' && input.headers) || {{}});
                    if (!headers.has('X-CSRF-Token')) {{
                        headers.set('X-CSRF-Token', window.DOCMAGIC_CSRF_TOKEN || '');
                    }}
                    options.headers = headers;
                }}
            }} catch (error) {{}}
            return originalFetch(input, options);
        }};
    }})();
    </script>
    """


@_retry_sqlite_locked
def _seed_admin_user():
    conn = _bootstrap_sqlite_connect(DB_PATH)
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


@_retry_sqlite_locked
def _clear_admin_lock():
    conn = _bootstrap_sqlite_connect(DB_PATH)
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
                conn = _bootstrap_sqlite_connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute("DELETE FROM app_sessions WHERE token=?", (token,))
                conn.commit()
                conn.close()
            else:
                conn = _bootstrap_sqlite_connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute("UPDATE app_sessions SET last_seen=CURRENT_TIMESTAMP WHERE token=?", (token,))
                conn.commit()
                conn.close()
                return row[1]

    if credentials and credentials.username and credentials.password:
        conn = _bootstrap_sqlite_connect(DB_PATH)
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
        target_tmp = Path("/tmp/docmagic.db")
        # Try multiple potential source locations on Vercel
        possible_sources = [
            Path(__file__).resolve().parent / "docmagic.db",
            Path("/var/task/docmagic.db"),
            Path("/var/task/api/../docmagic.db"),
            Path("docmagic.db").resolve()
        ]
        
        source_bundled = None
        for ps in possible_sources:
            if ps.exists():
                source_bundled = ps
                break

        if not target_tmp.exists() or not os.access(target_tmp, os.W_OK):
            try:
                target_tmp.parent.mkdir(parents=True, exist_ok=True)
                if source_bundled and source_bundled.exists():
                    import shutil
                    # Ensure the target is writable and fresh
                    if target_tmp.exists():
                        target_tmp.unlink(missing_ok=True)
                    shutil.copy(str(source_bundled), str(target_tmp))
                    os.chmod(str(target_tmp), 0o666)
            except Exception:
                pass
        return str(target_tmp)
    return "docmagic.db"


DB_PATH = _resolve_db_path()
DB_IS_EPHEMERAL = str(DB_PATH).startswith("/tmp/")
DB_PROXY_BASE_URL = os.environ.get("DOCMAGIC_DB_BASE_URL", "").strip().rstrip("/")
DB_PROXY_ENABLED = bool(DB_PROXY_BASE_URL) and os.environ.get("DOCMAGIC_DB_PROXY", "1") != "0"
DB_RUNTIME_PROXY_ENABLED = False
DB_SERVER_MODE = ContextVar("docmagic_db_server_mode", default=False)
_REAL_SQLITE_CONNECT = sqlite3.connect
_BOOTSTRAP_DB_TOKEN = DB_SERVER_MODE.set(True)


def _bootstrap_sqlite_connect(path=DB_PATH, timeout=3, retries=3, delay=0.1):
    last_error = None
    retries = max(1, int(retries))
    for attempt in range(retries):
        try:
            conn = _REAL_SQLITE_CONNECT(path, timeout=timeout)
            try:
                conn.execute("PRAGMA busy_timeout=30000")
                if os.environ.get("VERCEL"):
                    conn.execute("PRAGMA journal_mode=DELETE")
                else:
                    conn.execute("PRAGMA journal_mode=WAL")
            except Exception:
                pass
            return conn
        except sqlite3.OperationalError as exc:
            last_error = exc
            if "locked" not in str(exc).lower() or attempt >= retries - 1:
                raise
            time.sleep(delay * (attempt + 1))
    if last_error is not None:
        raise last_error


def _retry_sqlite_locked(operation):
    def wrapped(*args, **kwargs):
        retries = 6
        delay = 0.25
        last_error = None
        for attempt in range(retries):
            try:
                return operation(*args, **kwargs)
            except sqlite3.OperationalError as exc:
                last_error = exc
                if "locked" not in str(exc).lower() or attempt >= retries - 1:
                    raise
                time.sleep(delay * (attempt + 1))
        if last_error is not None:
            raise last_error

    return wrapped


def _auth_headers():
    if not SERVICE_AUTH_USER or not SERVICE_AUTH_PASSWORD:
        return {}
    token = base64.b64encode(f"{SERVICE_AUTH_USER}:{SERVICE_AUTH_PASSWORD}".encode("utf-8")).decode("ascii")
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
        kwargs.setdefault("timeout", 3)
        return _bootstrap_sqlite_connect(path, **kwargs)
    if DB_PROXY_ENABLED and DB_RUNTIME_PROXY_ENABLED and DB_PROXY_BASE_URL:
        return _RemoteConnection(path)
    kwargs.setdefault("timeout", 3)
    return _bootstrap_sqlite_connect(path, **kwargs)


sqlite3.connect = _connect_proxy_or_sqlite


def _ensure_db_parent_dir():
    try:
        Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


@_retry_sqlite_locked
def _ensure_announcements_teacher_quote_column():
    conn = _bootstrap_sqlite_connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(announcements)")
    columns = {row[1] for row in cursor.fetchall()}
    if "teacher_quote" not in columns:
        cursor.execute("ALTER TABLE announcements ADD COLUMN teacher_quote TEXT DEFAULT ''")
        conn.commit()
    conn.close()


_ensure_db_parent_dir()

@_retry_sqlite_locked
def init_db():
    conn = _bootstrap_sqlite_connect(DB_PATH)
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

@_retry_sqlite_locked
def init_preset_db():
    conn = _bootstrap_sqlite_connect(DB_PATH)
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
_ensure_audit_table()
_ensure_common_clients_table()
_seed_common_clients()
_dedupe_common_clients()
_ensure_announcements_table()
_ensure_announcements_teacher_quote_column()
_ensure_pantene_meeting_tables()
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


@app.get("/pantene-foodie-journey/assets/{filename}")
async def pantene_foodie_journey_asset(filename: str):
    asset_path = PANTENE_FOODIE_DIR / "assets" / filename
    if asset_path.is_file():
        return FileResponse(str(asset_path))
    return Response(status_code=404)


@app.get("/pantene-foodie-journey", response_class=HTMLResponse)
async def pantene_foodie_journey_share():
    share_path = PANTENE_FOODIE_DIR / "share.html"
    if share_path.exists():
        return HTMLResponse(share_path.read_text(encoding="utf-8"))
    fallback_path = PANTENE_FOODIE_DIR / "prototype.html"
    if fallback_path.exists():
        return HTMLResponse(fallback_path.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Pantene's Foodie Journey</h1><p>Share page not found.</p>", status_code=404)


@app.get("/pantene-foodie-journey/friends-dinner", response_class=HTMLResponse)
@app.get("/pantene-foodie-journey/friends-dinner/{share_token}", response_class=HTMLResponse)
async def pantene_friends_dinner_page(share_token: str = ""):
    page_path = PANTENE_FOODIE_DIR / "friends-dinner.html"
    if page_path.exists():
        return HTMLResponse(page_path.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Pantene Friends Dinner</h1><p>Page not found.</p>", status_code=404)

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


def _parse_money_number(value):
    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip().replace(",", "")
    match = re.search(r"-?\d+(?:\.\d+)?", text)
    if not match:
        return 0.0
    try:
        return float(match.group(0))
    except Exception:
        return 0.0


def _format_calc_qty(value):
    if value is None:
        return "0"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return str(int(value)) if value.is_integer() else f"{value:g}"
    text = str(value).strip()
    if text == "":
        return "0"
    return text


def _format_money(value):
    return f"${float(value):,.2f}"


def _format_doc_no_display(doc_no):
    return "" if doc_no is None else str(doc_no).replace("-", "‑")


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
        no_label = "報價單號碼"
    elif doc_type == "收據":
        no_label = "收據號碼"
    else:
        no_label = "發票號碼"
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
            "1. 「客戶名稱」簽回報價文件以確認服務提供。",
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
            "1. 將全數款項支票交給項目負責人或直接存入” 狄易達軍團跳舞學校 ” 戶口。",
            "2. 支票抬頭： “ Di2da Dance School ”",
            "3. 中國銀行：012 882 000 82760",
            "4. 本校只接受支票付款。/ 查詢電話：67004444",
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
        teacher_quote = html.escape(r[9] or "").replace("\n", "<br>")
        teacher_quote_html = ""
        if teacher_quote:
            teacher_quote_html = f'''
                <div style="margin-top:12px;padding:12px 14px;border-left:4px solid #b89d5d;background:#fff8e8;border-radius:14px;">
                    <div style="font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:#8b6a20;font-weight:800;margin-bottom:6px;">導師的話</div>
                    <div style="font-size:13px;line-height:1.7;color:#374151;">{teacher_quote}</div>
                </div>
            '''
        cards.append(f"""
            <article class="announce-card">
                <div class="announce-meta">
                    <span class="announce-tag">{'置頂' if r[3] else '公告'}</span>
                    <span>{html.escape(r[4] or 'system')}</span>
                    <span>{html.escape(r[8] or '')}</span>
                </div>
                <h3>{html.escape(r[1])}</h3>
                <p>{body}</p>
                {teacher_quote_html}
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
        f'<div class="line"><b>{esc(meta["no_label"])}：</b>{esc(_format_doc_no_display(doc_no))}</div>',
        f'<div class="line"><b>日期：</b>{esc(date_str)}</div>',
    ]

    item_rows = []
    total_val = 0
    for idx, item in enumerate(items_list, start=1):
        desc, price, qty = item
        price_val = _parse_money_number(price)
        qty_val = _parse_money_number(qty)
        amount = price_val * qty_val
        total_val += amount
        desc_html = esc(desc).replace("\n", "<br>")
        calc_text = f"${price_val:,.0f} x {_format_calc_qty(qty)}"
        amount_text = _format_money(amount)
        item_rows.append(
            f"""
            <tr>
              <td>
                <b>{desc_html}</b>
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
              <td><b>-</b></td>
              <td>$0 x 0</td>
              <td>$0.00</td>
            </tr>
            """
        )

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
      <th>摘要 Description</th>
      <th>數量/計算</th>
      <th>費用 (HKD)</th>
    </tr>
    {''.join(item_rows)}
    <tr class="total-row">
      <td colspan="2" class="total-label-cell">總計 Total:</td>
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
    right_top = Paragraph(f"<b>{_para(doc_type)}號碼：</b>{_para(_format_doc_no_display(doc_no))}", body_right) if doc_no else Spacer(1, 1)
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
        price_val = _parse_money_number(price)
        qty_val = _parse_money_number(qty)
        amount = price_val * qty_val
        total_val += amount
        table_data.append([
            Paragraph(_para(desc), body),
            Paragraph(f"${price_val:,.0f} x {_format_calc_qty(qty)}", body_center),
            Paragraph(_format_money(amount), body_right),
        ])

    total_row_idx = len(table_data)
    table_data.append([
        Paragraph("總計 Total", body_bold),
        "",
        Paragraph(_format_money(total_val), total_amount_style),
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
            remarks = ["「客戶名稱」簽回報價文件以確認服務提供。"]
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
    # Give the remarks/signature block more breathing room so it stays clear of the table border.
    story.append(Spacer(1, 18 * mm))
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
    if doc_no:
        draw.text((width - margin, y), f"{doc_type}號碼：{_format_doc_no_display(doc_no)}", font=f_info, fill="black", anchor="ra")
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
        price_val = _parse_money_number(price)
        qty_val = _parse_money_number(qty)
        amt = price_val * qty_val
        total_val += amt
        desc_max_width = col1_w - 60
        desc_height = wrapped_text_height(desc, f_item, desc_max_width)
        calc_height = line_height(f_calc)
        amt_height = line_height(f_total)
        row_h = max(desc_height, calc_height, amt_height) + 44
        draw.rectangle([table_x, y, table_x + table_w, y + row_h], outline="black", width=2)
        draw_wrapped_text(table_x + 30, y + 16, desc, f_item, "black", desc_max_width)
        draw.text((table_x + col1_w + col2_w // 2, y + row_h // 2), f"${price_val:,.0f} x {_format_calc_qty(qty)}", font=f_calc, fill="black", anchor="mm")
        draw.text((table_x + table_w - 28, y + row_h // 2), _format_money(amt), font=f_total, fill="black", anchor="rm")
        y += row_h

    draw.rectangle([table_x, y, table_x + table_w, y + 108], outline="black", width=3, fill="#F9F9F9")
    draw.text((table_x + col1_w + col2_w - 28, y + 54), "總計 Total:", font=f_total, fill="black", anchor="rm")
    draw.text((table_x + table_w - 28, y + 54), _format_money(total_val), font=f_total, fill="black", anchor="rm")
    y += 140

    if custom_remarks and custom_remarks.strip():
        remarks = [r.strip() for r in custom_remarks.split("\n") if r.strip()]
    else:
        if doc_type == "報價單":
            remarks = ["「客戶名稱」簽回報價文件以確認服務提供。"]
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

    # Keep the signature block lower so it does not intrude into the table area.
    sig_line_y = height - 390
    line_x_start = width - 620
    line_x_end = width - margin
    if with_sign:
        try:
            if sig_path.exists():
                s = Image.open(sig_path).convert("RGBA")
                fit_w, fit_h = _fit_box(s.width, s.height, 240, 120)
                s = s.resize((max(1, int(fit_w)), max(1, int(fit_h))), Image.Resampling.LANCZOS)
                image.paste(s, (line_x_start + 18, sig_line_y - 12), s)
            if stamp_path.exists():
                st = Image.open(stamp_path).convert("RGBA")
                fit_w, fit_h = _fit_box(st.width, st.height, 160, 160)
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
            remarks = ["「客戶名稱」簽回報價文件以確認服務提供。"]
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
        _audit_action_request(request, "permission_denied", target_type="page", target_id="/admin", result="denied", metadata={"required_role": "admin"})
        raise HTTPException(status_code=303, detail="Redirect", headers={"Location": "/"})
    if (user[3] or "").lower() != "admin":
        _audit_action_request(request, "permission_denied", target_type="page", target_id="/admin", result="denied", actor=user, metadata={"required_role": "admin"})
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
            _audit_action_request(request, "permission_denied", target_type="route", target_id=request.url.path, result="denied")
            raise HTTPException(
                status_code=401,
                detail="Unauthorized",
                headers={"WWW-Authenticate": "Basic"},
            )
        if not _role_allowed(user[3], allowed_roles):
            _audit_action_request(request, "permission_denied", target_type="route", target_id=request.url.path, result="denied", actor=user, metadata={"required_roles": sorted(allowed_roles)})
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
            .quote {{
                margin-top: 12px;
                padding: 12px 14px;
                border-left: 4px solid #d6b46d;
                border-radius: 14px;
                background: rgba(255,255,255,.08);
            }}
            .quote .label {{
                font-size: 11px;
                letter-spacing: .16em;
                text-transform: uppercase;
                color: #d6b46d;
                font-weight: 800;
                margin-bottom: 6px;
            }}
            .quote .text {{
                font-size: 13px;
                line-height: 1.7;
                color: #f8fafc;
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
                    <div class="eyebrow">Di2da Admin · 我是最新版本v20260915</div>
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
    now = datetime.now()
    today = now.strftime("%Y年%m月%d日")
    display_name = _current_display_name(request)
    user = _current_user_record(request)
    csrf_html = _csrf_input_html(request)
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
        cursor.execute("SELECT COUNT(*) FROM attendance_lesson_groups WHERE is_active=1")
        attendance_group_count = cursor.fetchone()[0]
    except Exception:
        attendance_group_count = 0
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
        cursor.execute("SELECT COUNT(*) FROM attendance_records")
        attendance_count = cursor.fetchone()[0]
    except Exception:
        attendance_count = 0
    try:
        cursor.execute(
            """
            SELECT COALESCE(SUM(duplicate_count - 1), 0)
            FROM (
                SELECT COUNT(*) AS duplicate_count
                FROM attendance_records
                WHERE lesson_group_id > 0 AND class_date <> '' AND student_name <> ''
                GROUP BY lesson_group_id, class_date, student_name
                HAVING COUNT(*) > 1
            )
            """
        )
        duplicate_count = cursor.fetchone()[0] or 0
    except Exception:
        duplicate_count = 0
    try:
        cursor.execute(
            "SELECT title, body, pinned, created_at FROM announcements ORDER BY pinned DESC, created_at DESC, id DESC LIMIT 3"
        )
        announcement_rows = cursor.fetchall()
    except Exception:
        announcement_rows = []
    try:
        cursor.execute(
            """
            SELECT id, area, class_title, weekday, lesson_time, class_category, teacher_name, school_name, notes, sort_order, is_demo, is_active
            FROM attendance_lesson_groups
            WHERE is_active=1
            ORDER BY COALESCE(sort_order, 0), weekday, lesson_time, id
            """
        )
        lesson_rows = cursor.fetchall()
    except Exception:
        lesson_rows = []
    conn.close()

    weekday_aliases = {
        0: {"星期一", "週一", "周一", "一", "1", "mon", "monday"},
        1: {"星期二", "週二", "周二", "二", "2", "tue", "tues", "tuesday"},
        2: {"星期三", "週三", "周三", "三", "3", "wed", "wednesday"},
        3: {"星期四", "週四", "周四", "四", "4", "thu", "thur", "thurs", "thursday"},
        4: {"星期五", "週五", "周五", "五", "5", "fri", "friday"},
        5: {"星期六", "週六", "周六", "六", "6", "sat", "saturday"},
        6: {"星期日", "星期天", "週日", "周日", "日", "天", "7", "0", "sun", "sunday"},
    }

    def _lesson_is_today(weekday_value: str) -> bool:
        text = re.sub(r"\s+", "", str(weekday_value or "")).strip().lower()
        if not text:
            return False
        compact = text.replace("星期", "").replace("週", "").replace("周", "")
        # Fix: Use datetime.now() instead of the 'today' string
        aliases = weekday_aliases.get(datetime.now().weekday(), set())
        return text in aliases or compact in aliases

    today_lesson_rows = [row for row in lesson_rows if _lesson_is_today(row[3])]
    if today_lesson_rows:
        today_class_body = "\n".join(
            " · ".join(
                bit
                for bit in [
                    (row[4] or "").strip(),
                    (row[1] or "").strip(),
                    (row[2] or row[5] or f"課堂 #{row[0]}").strip(),
                    (row[6] or "").strip(),
                    (row[7] or "").strip(),
                    (row[8] or "").strip(),
                ]
                if bit
            )
            for row in today_lesson_rows
        )
    else:
        today_class_body = "今日暫時未有已登記課堂。"

    announcement_rows = [("今日課堂資訊", today_class_body, 1, now.strftime("%Y-%m-%d %H:%M"))] + list(announcement_rows)

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
                    <form action="/logout" method="post" style="display:inline;">
                        {csrf_html}
                        <button type="submit" style="display:inline-block;border:1px solid var(--line);border-radius:999px;padding:10px 14px;background:#fff;color:var(--ink);font-size:13px;cursor:pointer;">登出</button>
                    </form>
                    {"<a href='/admin/accounts'>帳戶管理</a>" if user and (user[3] or "").lower() == "admin" else ""}
                    <a href="/announcements">軍團公告</a>
                    {"<a href='/invoice/clients'>常用客戶</a>" if user and (user[3] or "").lower() == "admin" else ""}
                    {"<a href='/invoice'>發票系統</a>" if user and (user[3] or "").lower() == "admin" else ""}
                    {"<a href='/invoice/scrc'>性罪行查核信</a>" if user and (user[3] or "").lower() == "admin" else ""}
                </div>
            </div>
            <div class="grid">
                <div class="card">
                    <h3>工作入口</h3>
                    <p>先揀你要處理嘅模組，再進入對應頁面。</p>
                    <div class="links">
                        <a class="link" href="/salary/teachers"><strong>導師列表</strong><span>查看各導師班數、狀態與薪酬詳情。</span></a>
                        <a class="link" href="/salary/classes"><strong>班別列表</strong><span>整理學校、星期、導師同時薪資料。</span></a>
                        <a class="link" href="/attendance"><strong>學生點名系統</strong><span>記錄各地區課堂出席、缺席同原因。</span></a>
                        <a class="link" href="/salary"><strong>薪酬管理</strong><span>查看薪酬總覽、匯入資料與計算記錄。</span></a>
                        <a class="link" href="/announcements"><strong>軍團公告</strong><span>查看最新通知、時間表同內部消息。</span></a>
                        {f'<a class="link" href="/invoice"><strong>發票系統</strong><span>生成報價單、發票、收據同常用範本。</span></a>' if user and (user[3] or "").lower() == "admin" else '<div class="link" style="opacity:.55; pointer-events:none;"><strong>發票系統</strong><span>只限 admin 使用。</span></div>'}
                        {f'<a class="link" href="/invoice/scrc"><strong>性罪行查核信</strong><span>按範本快速生成查核證明信件。</span></a>' if user and (user[3] or "").lower() == "admin" else '<div class="link" style="opacity:.55; pointer-events:none;"><strong>性罪行查核信</strong><span>只限 admin 使用。</span></div>'}
                    </div>
                </div>
                <div class="card">
                    <h3>系統概覽</h3>
                    <p>現有架構已預留多帳戶登入能力，並已將發票系統限制為 admin 使用。</p>
                    <div class="stats">
                        <div class="stat"><div class="num">{account_count}</div><div class="label">登入帳戶</div></div>
                        <div class="stat"><div class="num">{teacher_count}</div><div class="label">導師</div></div>
                        <div class="stat"><div class="num">{class_count + attendance_group_count}</div><div class="label">班別</div></div>
                        <div class="stat"><div class="num">{client_count}</div><div class="label">常用客戶</div></div>
                        <div class="stat"><div class="num">{preset_count}</div><div class="label">文件範本</div></div>
                        <div class="stat"><div class="num">{announcement_count}</div><div class="label">公告</div></div>
                        <div class="stat"><div class="num">{attendance_count}</div><div class="label">點名記錄</div></div>
                    </div>
                    {f'<div class="muted" style="margin-top:12px;color:#b42318;font-weight:700;">偵測到 {duplicate_count} 筆重複點名記錄，建議檢查同班同日是否重複提交。</div>' if duplicate_count else ''}
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


def _render_announcements_page(request: Request):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT title, body, pinned, created_at FROM announcements ORDER BY pinned DESC, created_at DESC, id DESC LIMIT 12")
        announcement_rows = cursor.fetchall()
    except Exception:
        announcement_rows = []
    try:
        cursor.execute(
            """
            SELECT id, area, class_title, weekday, lesson_time, class_category, teacher_name, school_name, notes, sort_order, is_demo, is_active
            FROM attendance_lesson_groups
            WHERE is_active=1
            ORDER BY COALESCE(sort_order, 0), weekday, lesson_time, id
            """
        )
        lesson_rows = cursor.fetchall()
    except Exception:
        lesson_rows = []
    conn.close()

    weekday_aliases = {
        0: {"星期一", "週一", "周一", "一", "1", "mon", "monday"},
        1: {"星期二", "週二", "周二", "二", "2", "tue", "tues", "tuesday"},
        2: {"星期三", "週三", "周三", "三", "3", "wed", "wednesday"},
        3: {"星期四", "週四", "周四", "四", "4", "thu", "thur", "thurs", "thursday"},
        4: {"星期五", "週五", "周五", "五", "5", "fri", "friday"},
        5: {"星期六", "週六", "周六", "六", "6", "sat", "saturday"},
        6: {"星期日", "星期天", "週日", "周日", "日", "天", "7", "0", "sun", "sunday"},
    }

    def _lesson_is_today(weekday_value: str) -> bool:
        text = re.sub(r"\s+", "", str(weekday_value or "")).strip().lower()
        if not text:
            return False
        compact = text.replace("星期", "").replace("週", "").replace("周", "")
        aliases = weekday_aliases.get(datetime.now().weekday(), set())
        return text in aliases or compact in aliases

    today_lesson_rows = [row for row in lesson_rows if _lesson_is_today(row[3])]
    if today_lesson_rows:
        today_class_body = "\n".join(
            " · ".join(
                bit
                for bit in [
                    (row[4] or "").strip(),
                    (row[1] or "").strip(),
                    (row[2] or row[5] or f"課堂 #{row[0]}").strip(),
                    (row[6] or "").strip(),
                    (row[7] or "").strip(),
                    (row[8] or "").strip(),
                ]
                if bit
            )
            for row in today_lesson_rows
        )
    else:
        today_class_body = "今日暫時未有已登記課堂。"

    today_card_html = f"""
        <section class="announce-panel">
            <div class="announce-panel-head">
                <div>
                    <div class="announce-kicker">今日課堂資訊</div>
                    <h2>今日班別安排</h2>
                </div>
                <span class="announce-pill">{len(today_lesson_rows)} 堂</span>
            </div>
            <div class="announce-today">PLACEHOLDER_TODAY_CLASS_BODY</div>
        </section>
    """
    today_card_html = today_card_html.replace('PLACEHOLDER_TODAY_CLASS_BODY', html.escape(today_class_body).replace('\n', '<br>'))


    announcement_cards = []
    for row in announcement_rows:
        title = row[0] if len(row) > 0 else ""
        body = row[1] if len(row) > 1 else ""
        pinned = row[2] if len(row) > 2 else 0
        created_at = row[3] if len(row) > 3 else ""
        teacher_quote = row[9] if len(row) > 9 else ""
        teacher_quote_html = ""
        if teacher_quote:
            teacher_quote_html = f'''
                <div class="quote">
                    <div class="label">導師的話</div>
                    <div class="text">{html.escape(str(teacher_quote)).replace(chr(10), '<br>')}</div>
                </div>
            '''
        announcement_cards.append(f"""
            <article class="announce-card">
                <div class="announce-meta">
                    <span class="announce-tag">{'置頂' if pinned else '公告'}</span>
                    <span>{html.escape(created_at or '')}</span>
                </div>
                <h3>{html.escape(title or '')}</h3>
                <p>PLACEHOLDER_ANNOUNCE_BODY</p>
                {teacher_quote_html}
            </article>
        """.replace('PLACEHOLDER_ANNOUNCE_BODY', html.escape(body or '').replace('\n', '<br>')))
    announcements_html = "".join(announcement_cards) or '<div class="announce-empty">暫時未有公告。</div>'

    return f"""
    <html lang="zh-HK">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{APP_NAME} - 軍團公告</title>
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
            .shell {{ max-width: 1160px; margin: 0 auto; }}
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
            .panel {{
                background: rgba(255,255,255,.92);
                border: 1px solid var(--line);
                border-radius: 24px;
                padding: 22px;
                box-shadow: 0 16px 40px rgba(16,17,20,.06);
            }}
            .announce-panel {{
                border: 1px solid var(--line);
                border-radius: 22px;
                padding: 18px;
                background: linear-gradient(180deg, #fff, #fbf7ef);
                margin-bottom: 18px;
            }}
            .announce-panel-head {{ display:flex; justify-content:space-between; gap:12px; align-items:flex-start; flex-wrap:wrap; }}
            .announce-kicker {{ color: var(--accent); letter-spacing: .18em; text-transform: uppercase; font-size: 11px; font-weight: 800; }}
            .announce-panel h2 {{ margin: 6px 0 0; font-size: 22px; }}
            .announce-pill {{ display:inline-flex; align-items:center; padding:8px 12px; border-radius:999px; background: var(--accent-soft); color:#5b4a18; font-size:12px; font-weight:700; }}
            .announce-today {{ margin-top: 14px; line-height: 1.75; color: var(--ink); white-space: normal; }}
            .announce-list {{ display: grid; gap: 12px; margin-top: 14px; }}
            .announce-card {{
                border: 1px solid var(--line);
                border-radius: 20px;
                padding: 16px;
                background: #fff;
            }}
            .announce-meta {{
                display: flex;
                flex-wrap: wrap;
                gap: 8px;
                color: #6b7280;
                font-size: 11px;
                margin-bottom: 8px;
            }}
            .announce-tag {{
                display: inline-block;
                padding: 2px 8px;
                border-radius: 999px;
                background: rgba(214,180,109,.16);
                color: #8b6a20;
                font-weight: 700;
            }}
            .announce-card h3 {{ margin: 0 0 6px; font-size: 16px; line-height: 1.4; }}
            .announce-card p {{ margin: 0; color: #374151; line-height: 1.7; }}
            .announce-empty {{ padding: 14px; border-radius: 16px; border: 1px dashed rgba(16,17,20,.14); color: var(--muted); background: rgba(255,255,255,.4); }}
            @media (max-width: 760px) {{
                body {{ padding: 14px; }}
                .hero, .panel {{ padding: 18px; border-radius: 20px; }}
                .hero h1 {{ font-size: 28px; }}
                .toolbar a {{ margin: 0 8px 8px 0; }}
            }}
        </style>
    </head>
    <body>
        <div class="shell">
            <div class="hero">
                <div>
                    <div style="color: var(--accent); font-weight: 800; letter-spacing: .18em; text-transform: uppercase; font-size: 12px;">Announcements</div>
                    <h1>軍團公告</h1>
                    <p>今日課堂資訊會放喺最前，下面再接最新內部公告。</p>
                </div>
                <div class="toolbar">
                    <a href="/dashboard">返回主目錄</a>
                </div>
            </div>
            <div class="panel">
                {today_card_html}
                <div class="announce-list">{announcements_html}</div>
            </div>
        </div>
    </body>
    </html>
    """


@app.get("/announcements", response_class=HTMLResponse)
async def announcements(request: Request):
    return HTMLResponse(_render_announcements_page(request))


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
    try:
        conn = _bootstrap_sqlite_connect(DB_PATH, timeout=2, retries=2)
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password, display_name, role, is_active, failed_attempts, locked_until FROM app_users WHERE username=?", (username.strip(),))
        row = cursor.fetchone()
        if not row or row[5] != 1:
            conn.close()
            _audit_action_request(request, "login_failure", target_type="account", target_id=username.strip(), result="denied", metadata={"reason": "not_found_or_disabled"})
            return HTMLResponse(_render_login_page("帳戶名稱或密碼唔正確"), status_code=401)
        locked_until = _parse_dt(row[7])
        if locked_until and locked_until > _now():
            conn.close()
            _audit_action_request(request, "account_lockout", target_type="account", target_id=row[1], result="denied", metadata={"locked_until": row[7]})
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
            _audit_action_request(
                request,
                "login_failure",
                target_type="account",
                target_id=row[1],
                result="denied",
                metadata={"failed_attempts": failed_attempts, "locked": bool(lock_until)},
            )
            if lock_until:
                _audit_action_request(request, "account_lockout", target_type="account", target_id=row[1], result="denied", metadata={"locked_until": lock_until})
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
        token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(48)
        cursor.execute(
            "INSERT OR REPLACE INTO app_sessions (token, username, display_name, csrf_token, expires_at, last_seen) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
            (token, row[1], row[3] or row[1], csrf_token, _session_expires_at()),
        )
        conn.commit()
        conn.close()
        response = RedirectResponse("/dashboard", status_code=303)
        response.set_cookie("docmagic_session", token, **_session_cookie_options())
        _audit_action_request(request, "login_success", target_type="account", target_id=row[1], result="ok", metadata={"role": _normalize_role(row[4])})
        return response
    except sqlite3.OperationalError as exc:
        if _is_sqlite_locked_error(exc):
            return HTMLResponse(_render_login_page("系統忙緊中，請稍後再試登入"), status_code=503)
        raise


@app.get("/logout", response_class=HTMLResponse)
async def logout(request: Request):
    user = _current_user_record(request)
    csrf_html = _csrf_input_html(request)
    return HTMLResponse(
        f"""
        <html lang="zh-HK">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>{APP_NAME} - 登出</title>
            <style>
                body {{ margin:0; font-family: -apple-system, BlinkMacSystemFont, "PingFang HK", "Noto Sans TC", sans-serif; background:#f4f0e6; color:#111; }}
                .wrap {{ max-width:560px; margin:10vh auto; background:#fff; border:1px solid #e5e7eb; border-radius:20px; padding:28px; }}
                button {{ padding:12px 16px; border:0; border-radius:12px; background:#111; color:#fff; font-weight:700; cursor:pointer; }}
                a {{ color:#111; text-decoration:none; display:inline-block; margin-left:12px; }}
            </style>
        </head>
        <body>
            <div class="wrap">
                <h2>確認登出</h2>
                <p>{html.escape(user[2] if user else '你') if user else '你'}，按下面按鈕會即時清除目前 session。</p>
                <form action="/logout" method="post">
                    {csrf_html}
                    <button type="submit">確認登出</button>
                    <a href="/dashboard">返回</a>
                </form>
                <script>document.querySelector('form')?.addEventListener('submit', () => document.querySelector('button')?.setAttribute('disabled', 'disabled'));</script>
            </div>
        </body>
        </html>
        """
    )


@app.post("/logout")
async def logout_submit(request: Request):
    token = request.cookies.get("docmagic_session")
    user = _current_user_record(request)
    if token:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM app_sessions WHERE token=?", (token,))
        conn.commit()
        conn.close()
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie("docmagic_session", path="/")
    _audit_action_request(request, "logout", target_type="session", target_id=user[1] if user else "", result="ok", actor=user)
    return response


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    if not _current_user_record(request):
        return RedirectResponse("/", status_code=303)
    return HTMLResponse(_render_dashboard_page(request))


def _attendance_status_badge(status: str):
    value = (status or "present").strip().lower()
    if value == "absent":
        return "<span class='badge att-badge att-absent'>✗ 缺席</span>"
    if value == "dropped":
        return "<span class='badge att-badge att-dropped'>⛔ 已退學</span>"
    return "<span class='badge att-badge att-present'>✓ 出席</span>"


def _attendance_area_options_html(selected_value: str = ""):
    pieces = ['<option value="">請選擇地區</option>']
    for area in ATTENDANCE_AREA_OPTIONS:
        selected = " selected" if area == selected_value else ""
        pieces.append(f'<option value="{html.escape(area, quote=True)}"{selected}>{html.escape(area)}</option>')
    return "".join(pieces)


def _attendance_weekday_options_html(selected_value: str = ""):
    weekdays = ["星期一", "星期二", "星期三", "星期四", "星期五", "星期六", "星期日"]
    pieces = ['<option value="">請選擇星期</option>']
    for weekday in weekdays:
        selected = " selected" if weekday == selected_value else ""
        pieces.append(f'<option value="{html.escape(weekday, quote=True)}"{selected}>{html.escape(weekday)}</option>')
    return "".join(pieces)


def _attendance_category_options_html(selected_value: str = ""):
    pieces = ['<option value="">請選擇課堂類別</option>']
    for category in ATTENDANCE_CATEGORY_OPTIONS:
        selected = " selected" if category == selected_value else ""
        pieces.append(f'<option value="{html.escape(category, quote=True)}"{selected}>{html.escape(category)}</option>')
    return "".join(pieces)


def _attendance_teacher_options_html(teacher_values, selected_value: str = ""):
    pieces = ['<option value="">全部導師</option>']
    seen = set()
    for teacher in teacher_values:
        value = (teacher or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        selected = " selected" if value == selected_value else ""
        pieces.append(f'<option value="{html.escape(value, quote=True)}"{selected}>{html.escape(value)}</option>')
    return "".join(pieces)


def _attendance_status_option_html(value: str, label: str, selected_value: str):
    checked = " checked" if value == selected_value else ""
    return f"""
    <label class="status-chip">
        <input type="radio" name="status" value="{html.escape(value, quote=True)}"{checked}>
        <span>{html.escape(label)}</span>
    </label>
    """


def _attendance_batch_row_html():
    return """
    <div class="batch-row" data-batch-row>
        <div class="field">
            <label>學生名稱</label>
            <input name="batch_student_name" placeholder="例如：陳小明">
        </div>
        <div class="field">
            <label>出席 / 缺席</label>
            <select name="batch_status">
                <option value="present">✓ 出席</option>
                <option value="absent">✗ 缺席</option>
                <option value="dropped">⛔ 已退學</option>
            </select>
        </div>
        <div class="field">
            <label>缺席原因</label>
            <input name="batch_absence_reason" placeholder="如有才填">
        </div>
        <button class="batch-remove" type="button" data-batch-remove>移除</button>
    </div>
    """


def _attendance_lesson_title(row):
    lesson_id, area, class_title, weekday, lesson_time, class_category, teacher_name, school_name, notes, sort_order, is_demo, is_active = row
    subtitle_bits = [weekday, lesson_time, teacher_name, class_category]
    subtitle = " · ".join(bit for bit in subtitle_bits if bit)
    label = class_title or subtitle or f"課堂 #{lesson_id}"
    return lesson_id, area or "", label, subtitle, school_name or "", notes or "", bool(is_demo), bool(is_active)


def _attendance_lesson_group_cards_html(groups, selected_id: int = 0):
    cards = []
    for row in groups:
        lesson_id, area, label, subtitle, school_name, notes, is_demo, is_active = _attendance_lesson_title(row)
        active_class = "lesson-card active" if int(selected_id or 0) == int(lesson_id) else "lesson-card"
        demo_badge = "<span class='badge att-badge att-present'>示範</span>" if is_demo else ""
        cards.append(f"""
            <a class="{active_class}" href="/attendance?area={html.escape(area, quote=True)}&lesson_group_id={lesson_id}">
                <div class="lesson-card-top">
                    <div>
                        <div class="lesson-card-title">{html.escape(label)}</div>
                        <div class="mini-meta">{html.escape(area)} · {html.escape(subtitle or school_name or '未有描述')}</div>
                    </div>
                    {demo_badge}
                </div>
                {f"<div class='lesson-card-note'>{html.escape(notes)}</div>" if notes else ""}
            </a>
        """)
    return "".join(cards)


def _attendance_roster_row_html(student_row, selected_status: str = "present"):
    student_id, student_name, display_order, note = student_row
    raw_status = str(selected_status or "").strip().lower()
    status_value = raw_status if raw_status in {"present", "absent", "dropped"} else "present"
    present_selected = " selected" if status_value == "present" else ""
    absent_selected = " selected" if status_value == "absent" else ""
    dropped_selected = " selected" if status_value == "dropped" else ""
    return f"""
        <tr data-roster-row>
            <td>
                <input type="hidden" name="student_ids" value="{student_id}">
                <strong>{html.escape(student_name or '-')}</strong>
                <div class="mini-meta">#{student_id}</div>
            </td>
            <td>
                <select class="roster-status" name="student_status_{student_id}">
                    <option value="present"{present_selected}>出席</option>
                    <option value="absent"{absent_selected}>缺席</option>
                    <option value="dropped"{dropped_selected}>已退學</option>
                </select>
            </td>
            <td>
                <input class="roster-reason" name="absence_reason_{student_id}" placeholder="缺席先填">
            </td>
        </tr>
    """


def _attendance_row_html(row):
    record_id, area, student_name, class_date, class_time, class_category, status, absence_reason, recorded_by_username, recorded_by_display_name, created_at, updated_at = row
    timestamp = f"{class_date or '-'} {class_time or ''}".strip()
    return f"""
        <tr>
            <td><strong>{html.escape(timestamp or '-')}</strong><div class="mini-meta">#{record_id}</div></td>
            <td>{html.escape(area or '-')}</td>
            <td><strong>{html.escape(student_name or '-')}</strong></td>
            <td>{html.escape(class_category or '-')}</td>
            <td>{_attendance_status_badge(status)}</td>
            <td>{html.escape(absence_reason or '-')}</td>
            <td>{html.escape(recorded_by_display_name or recorded_by_username or '-')}</td>
        </tr>
    """


def _attendance_card_html(row):
    record_id, area, student_name, class_date, class_time, class_category, status, absence_reason, recorded_by_username, recorded_by_display_name, created_at, updated_at = row
    timestamp = f"{class_date or '-'} {class_time or ''}".strip()
    return f"""
        <article class="att-card">
            <div class="att-card-top">
                <div>
                    <div class="att-card-title">{html.escape(student_name or '-')}</div>
                    <div class="mini-meta">{html.escape(timestamp or '-')} · {html.escape(area or '-')}</div>
                </div>
                {_attendance_status_badge(status)}
            </div>
            <div class="att-card-grid">
                <div><span>課堂類別</span><strong>{html.escape(class_category or '-')}</strong></div>
                <div><span>缺席原因</span><strong>{html.escape(absence_reason or '-')}</strong></div>
                <div><span>記錄者</span><strong>{html.escape(recorded_by_display_name or recorded_by_username or '-')}</strong></div>
                <div><span>記錄編號</span><strong>#{record_id}</strong></div>
            </div>
        </article>
    """


def _attendance_records_where_clause(
    selected_area: str = "",
    search_text: str = "",
    teacher_filter: str = "",
    category_filter: str = "",
    status_filter: str = "",
    date_from: str = "",
    date_to: str = "",
):
    where = []
    params: list = []
    if selected_area and selected_area != "all":
        where.append("area=?")
        params.append(selected_area)
    if search_text:
        like = f"%{search_text}%"
        where.append("(student_name LIKE ? OR class_category LIKE ? OR absence_reason LIKE ? OR recorded_by_display_name LIKE ? OR recorded_by_username LIKE ?)")
        params.extend([like, like, like, like, like])
    if teacher_filter and teacher_filter != "all":
        where.append("(recorded_by_display_name=? OR recorded_by_username=?)")
        params.extend([teacher_filter, teacher_filter])
    if category_filter and category_filter != "all":
        where.append("class_category=?")
        params.append(category_filter)
    if status_filter and status_filter != "all":
        where.append("status=?")
        params.append(status_filter)
    if date_from:
        where.append("class_date>=?")
        params.append(date_from)
    if date_to:
        where.append("class_date<=?")
        params.append(date_to)
    where_sql = f" WHERE {' AND '.join(where)}" if where else ""
    return where_sql, params


def _attendance_lesson_groups_fetch(selected_area: str = ""):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    params: list = []
    where = ["is_active=1"]
    if selected_area and selected_area != "all":
        where.append("area=?")
        params.append(selected_area)
    where_sql = " WHERE " + " AND ".join(where) if where else ""
    cursor.execute(
        f"""
        SELECT id, area, class_title, weekday, lesson_time, class_category, teacher_name, school_name, notes, sort_order, is_demo, is_active
        FROM attendance_lesson_groups
        {where_sql}
        ORDER BY COALESCE(sort_order, 0), weekday, lesson_time, id
        """,
        params,
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


def _attendance_lesson_group_fetch(lesson_group_id: int):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, area, class_title, weekday, lesson_time, class_category, teacher_name, school_name, notes, sort_order, is_demo, is_active
        FROM attendance_lesson_groups
        WHERE id=? AND is_active=1
        """,
        (lesson_group_id,),
    )
    row = cursor.fetchone()
    conn.close()
    return row


def _attendance_lesson_students_fetch(lesson_group_id: int):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, student_name, display_order, note
        FROM attendance_lesson_students
        WHERE lesson_group_id=? AND is_active=1
        ORDER BY COALESCE(display_order, 0), id
        """,
        (lesson_group_id,),
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


def _attendance_review_records_fetch(lesson_group_id: int, class_date: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, area, student_name, class_date, class_time, class_category, status, absence_reason, recorded_by_username, recorded_by_display_name, created_at, updated_at
        FROM attendance_records
        WHERE lesson_group_id=? AND class_date=?
        ORDER BY COALESCE(student_order, 0), student_name COLLATE NOCASE, id
        """,
        (int(lesson_group_id or 0), class_date.strip()),
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


def _render_attendance_page(
    request: Request,
    notice: str = "",
    added_count: int = 0,
    selected_area: str = "",
    lesson_group_id: int = 0,
    search_text: str = "",
    teacher_filter: str = "",
    category_filter: str = "",
    status_filter: str = "",
    date_from: str = "",
    date_to: str = "",
):
    user = _current_user_record(request)
    display_name = _current_display_name(request)
    today = datetime.now()
    today_date = today.strftime("%Y-%m-%d")
    today_time = today.strftime("%H:%M")
    selected_area = (selected_area or "").strip()
    search_text = (search_text or "").strip()
    teacher_filter = (teacher_filter or "").strip()
    category_filter = (category_filter or "").strip()
    status_filter = (status_filter or "").strip()
    date_from = (date_from or "").strip()
    date_to = (date_to or "").strip()
    try:
        lesson_group_id = int(lesson_group_id or 0)
    except (TypeError, ValueError):
        lesson_group_id = 0

    where = []
    params: list = []
    if selected_area and selected_area != "all":
        where.append("area=?")
        params.append(selected_area)
    if search_text:
        like = f"%{search_text}%"
        where.append("(student_name LIKE ? OR class_category LIKE ? OR absence_reason LIKE ? OR recorded_by_display_name LIKE ? OR recorded_by_username LIKE ?)")
        params.extend([like, like, like, like, like])
    if teacher_filter and teacher_filter != "all":
        where.append("(recorded_by_display_name=? OR recorded_by_username=?)")
        params.extend([teacher_filter, teacher_filter])
    if category_filter and category_filter != "all":
        where.append("class_category=?")
        params.append(category_filter)
    if status_filter and status_filter != "all":
        where.append("status=?")
        params.append(status_filter)
    if date_from:
        where.append("class_date>=?")
        params.append(date_from)
    if date_to:
        where.append("class_date<=?")
        params.append(date_to)
    where_sql = f" WHERE {' AND '.join(where)}" if where else ""
    today_where_sql = f"{where_sql} AND class_date=?" if where_sql else " WHERE class_date=?"
    absent_where_sql = f"{where_sql} AND status='absent'" if where_sql else " WHERE status='absent'"

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(f"SELECT COUNT(*) FROM attendance_records{where_sql}", params)
    total_records = cursor.fetchone()[0] or 0
    cursor.execute(f"SELECT COUNT(*) FROM attendance_records{today_where_sql}", [*params, today_date])
    today_records = cursor.fetchone()[0] or 0
    cursor.execute(f"SELECT COUNT(*) FROM attendance_records{absent_where_sql}", params)
    absent_records = cursor.fetchone()[0] or 0
    cursor.execute(f"SELECT COUNT(DISTINCT student_name) FROM attendance_records{where_sql}", params)
    unique_students = cursor.fetchone()[0] or 0
    cursor.execute(
        f"""
        SELECT id, area, student_name, class_date, class_time, class_category, status, absence_reason, recorded_by_username, recorded_by_display_name, created_at, updated_at
        FROM attendance_records
        {where_sql}
        ORDER BY class_date DESC, class_time DESC, id DESC
        LIMIT 40
        """,
        params,
    )
    rows = cursor.fetchall()
    cursor.execute(
        """
        SELECT DISTINCT COALESCE(NULLIF(recorded_by_display_name, ''), recorded_by_username, '')
        FROM attendance_records
        WHERE COALESCE(NULLIF(recorded_by_display_name, ''), recorded_by_username, '') <> ''
        ORDER BY 1 COLLATE NOCASE
        """
    )
    teacher_values = [row[0] for row in cursor.fetchall()]
    conn.close()

    lesson_groups = _attendance_lesson_groups_fetch(selected_area)
    selected_lesson = _attendance_lesson_group_fetch(lesson_group_id) if lesson_group_id else None
    if selected_lesson and selected_area and selected_area != "all" and selected_lesson[1] != selected_area:
        selected_lesson = None
    lesson_students = _attendance_lesson_students_fetch(lesson_group_id) if selected_lesson else []

    notice_html = ""
    if notice == "added":
        if added_count > 1:
            notice_html = f'<div class="notice success">已新增 {added_count} 筆點名記錄。</div>'
        else:
            notice_html = '<div class="notice success">已新增點名記錄。</div>'
    elif notice == "student_added":
        notice_html = '<div class="notice success">已臨時新增學生到課堂名單。</div>'
    elif notice == "group_saved":
        notice_html = '<div class="notice success">已更新課堂資料。</div>'
    elif notice == "saved":
        notice_html = '<div class="notice success">已更新點名記錄。</div>'
    elif notice == "empty":
        notice_html = '<div class="notice">未有可儲存的學生資料，請至少輸入一位學生名稱。</div>'

    area_chips = ''.join(
        f'<a class="chip {"active" if selected_area == area else ""}" href="/attendance?area={html.escape(area, quote=True)}">{html.escape(area)}</a>'
        for area in ATTENDANCE_AREA_OPTIONS
    )
    all_chip = f'<a class="chip {"active" if not selected_area or selected_area == "all" else ""}" href="/attendance">全部地區</a>'
    export_params = {
        "area": selected_area,
        "q": search_text,
        "teacher": teacher_filter,
        "category": category_filter,
        "status": status_filter,
        "date_from": date_from,
        "date_to": date_to,
    }
    export_query = urlencode({key: value for key, value in export_params.items() if value})
    export_href = f"/attendance/export.csv?{export_query}" if export_query else "/attendance/export.csv"

    rows_html = ''.join(_attendance_row_html(row) for row in rows) or '<tr><td colspan="7" class="empty-state">暫時未有點名記錄。</td></tr>'
    cards_html = ''.join(_attendance_card_html(row) for row in rows) or '<div class="empty-state">暫時未有點名記錄。</div>'
    batch_rows_html = ''.join(_attendance_batch_row_html() for _ in range(4))
    selected_area_label = selected_area if selected_area and selected_area != "all" else "全部地區"
    role_label = _normalize_role(user[3]) if user else "guest"
    admin_manage_button = '<a href="/attendance/manage" class="btn secondary">管理課堂資料</a>' if role_label == "admin" else ""
    selected_teacher_label = teacher_filter if teacher_filter and teacher_filter != "all" else "全部導師"
    selected_category_label = category_filter if category_filter and category_filter != "all" else "全部類別"
    selected_status_label = "全部狀態" if not status_filter or status_filter == "all" else ("出席" if status_filter == "present" else ("缺席" if status_filter == "absent" else ("已退學" if status_filter == "dropped" else status_filter)))
    date_range_bits = []
    if date_from:
        date_range_bits.append(f"由 {date_from}")
    if date_to:
        date_range_bits.append(f"至 {date_to}")
    date_range_label = " / ".join(date_range_bits) if date_range_bits else "全部日期"

    lesson_summary_html = ""
    roster_form_html = ""
    add_student_form_html = ""
    if selected_lesson:
        lesson_rows_html = "".join(_attendance_roster_row_html(row, "present") for row in lesson_students) or '<tr><td colspan="3" class="empty-state">這堂課暫時未有學生名單。</td></tr>'
        lesson_summary_html = f"""
            <div class="lesson-summary">
                <div class="row"><span>地區</span><strong>{html.escape(selected_lesson[1] or selected_area_label)}</strong></div>
                <div class="row"><span>課堂</span><strong>{html.escape(selected_lesson[2] or '未有名稱')}</strong></div>
                <div class="row"><span>摘要</span><strong>{html.escape(selected_lesson[3] or selected_lesson[4] or '未有資料')}</strong></div>
            </div>
        """
        add_student_form_html = f"""
            <div class="btn-row" style="margin-top:12px;">
                <form method="post" action="/attendance/students/add" class="stack" style="display:flex;gap:10px;flex-wrap:wrap;align-items:end;width:100%;">
                    {_csrf_input_html(request)}
                    <input type="hidden" name="lesson_group_id" value="{lesson_group_id}">
                    <div class="field" style="min-width:220px;flex:1 1 220px;">
                        <label>臨時新增學生</label>
                        <input name="student_name" placeholder="輸入學生姓名">
                    </div>
                    <div class="field" style="min-width:160px;">
                        <label>排序</label>
                        <input name="display_order" type="number" min="1" placeholder="自動">
                    </div>
                    <button type="submit" class="btn secondary">加入名單</button>
                </form>
            </div>
        """
        roster_form_html = f"""
            <form method="post" action="/attendance/submit" class="stack" style="margin-top:18px;">
                {_csrf_input_html(request)}
                <input type="hidden" name="lesson_group_id" value="{lesson_group_id}">
                <div class="lesson-form-head">
                    <div>
                        <h2 style="margin:0;">學生名單</h2>
                        <div class="mini-meta">導師只需確認日期，然後剔選出席位置。</div>
                    </div>
                    <div class="field" style="min-width:220px;">
                        <label>課堂日期</label>
                        <input type="date" name="class_date" value="{today_date}" required>
                    </div>
                </div>
                {lesson_summary_html}
                <div class="table-wrap" style="margin-top:12px;">
                    <table class="roster-table">
                        <thead>
                            <tr>
                                <th>學生名稱</th>
                                <th>出席 / 缺席</th>
                                <th>缺席原因</th>
                            </tr>
                        </thead>
                        <tbody>
                            {lesson_rows_html}
                        </tbody>
                    </table>
                </div>
                <div class="btn-row" style="margin-top:14px;">
                    <button type="submit" class="btn">提交點名</button>
                    <a href="/attendance" class="btn secondary">清空 / 重設</a>
                    <a href="/dashboard" class="btn secondary">返回主目錄</a>
                </div>
            </form>
            {add_student_form_html}
        """
    else:
        roster_form_html = """
            <div class="lesson-empty" style="margin-top:18px;">
                未揀課堂。請先從上面課堂名單揀一堂，之後先會顯示學生表格。
            </div>
        """

    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html lang="zh-HK">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{APP_NAME} - 學生點名系統</title>
        <style>
            :root {{
                --bg1: #f7f1e6;
                --bg2: #fffdf8;
                --ink: #111111;
                --muted: #66615b;
                --line: rgba(17,17,17,.10);
                --accent: #b89d5d;
                --accent-soft: #f5ead2;
                --good: #137a63;
                --bad: #b42318;
            }}
            * {{ box-sizing: border-box; }}
            body {{
                margin: 0;
                font-family: -apple-system, BlinkMacSystemFont, "PingFang HK", "Noto Sans TC", sans-serif;
                color: var(--ink);
                background:
                    radial-gradient(circle at top left, rgba(184,157,93,.16), transparent 24%),
                    radial-gradient(circle at bottom right, rgba(19,122,99,.10), transparent 22%),
                    linear-gradient(135deg, var(--bg2), var(--bg1));
                padding: 22px;
            }}
            .shell {{ max-width: 1260px; margin: 0 auto; }}
            .hero {{
                display: flex;
                justify-content: space-between;
                gap: 16px;
                align-items: flex-end;
                flex-wrap: wrap;
                background: rgba(255,255,255,.9);
                border: 1px solid var(--line);
                border-radius: 28px;
                padding: 24px 26px;
                box-shadow: 0 18px 50px rgba(17,17,17,.08);
                margin-bottom: 18px;
            }}
            .eyebrow {{
                color: var(--accent);
                font-size: 12px;
                font-weight: 800;
                letter-spacing: .22em;
                text-transform: uppercase;
            }}
            h1 {{ margin: 8px 0 0; font-size: clamp(30px, 4vw, 48px); line-height: 1.03; letter-spacing: -0.04em; }}
            .lead {{ margin: 12px 0 0; color: var(--muted); line-height: 1.7; max-width: 56ch; }}
            .hero-side {{
                display: grid;
                gap: 8px;
                min-width: 240px;
                padding: 14px 16px;
                border-radius: 18px;
                background: linear-gradient(180deg, #fff, #faf8f2);
                border: 1px solid var(--line);
            }}
            .hero-side .label {{ color: var(--muted); font-size: 12px; }}
            .hero-side .value {{ font-size: 18px; font-weight: 800; }}
            .chips {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 16px; }}
            .chip {{
                display: inline-flex;
                align-items: center;
                justify-content: center;
                padding: 9px 14px;
                border-radius: 999px;
                border: 1px solid #d8cab2;
                background: rgba(255,255,255,.88);
                color: var(--ink);
                text-decoration: none;
                font-size: 12px;
                font-weight: 800;
            }}
            .chip.active {{ background: var(--accent); border-color: var(--accent); color: #111; }}
            .grid {{ display: grid; grid-template-columns: 1.05fr .95fr; gap: 18px; }}
            .panel {{
                background: rgba(255,255,255,.92);
                border: 1px solid var(--line);
                border-radius: 24px;
                padding: 20px;
                box-shadow: 0 14px 36px rgba(17,17,17,.06);
            }}
            .panel h2 {{ margin: 0 0 12px; font-size: 20px; }}
            .panel h3 {{ margin: 0 0 10px; font-size: 16px; }}
            .muted {{ color: var(--muted); font-size: 13px; line-height: 1.6; }}
            .notice {{
                margin: 0 0 14px;
                border-radius: 16px;
                padding: 12px 14px;
                border: 1px solid var(--line);
                background: #fff;
            }}
            .notice.success {{ background: #edf9f3; border-color: rgba(19,122,99,.18); color: var(--good); }}
            .stats {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-top: 14px; }}
            .stat {{
                padding: 14px 12px;
                border-radius: 18px;
                background: linear-gradient(180deg, #fff, #faf8f2);
                border: 1px solid var(--line);
            }}
            .stat .num {{ font-size: 24px; font-weight: 900; }}
            .stat .label {{ margin-top: 4px; font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .06em; }}
            .form-grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }}
            .field {{ display: grid; gap: 6px; }}
            .field label {{ font-size: 12px; font-weight: 800; color: var(--ink); }}
            .field input, .field select, .field textarea {{
                width: 100%;
                padding: 11px 12px;
                border: 1px solid #d7d2c6;
                border-radius: 14px;
                font-size: 14px;
                background: #fff;
                color: var(--ink);
            }}
            .field textarea {{ min-height: 94px; resize: vertical; line-height: 1.5; }}
            .span-2 {{ grid-column: 1 / -1; }}
            .status-row {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }}
            .status-chip {{
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 8px;
                padding: 12px 14px;
                border-radius: 16px;
                border: 1px solid #d7d2c6;
                background: #fff;
                font-weight: 800;
                cursor: pointer;
            }}
            .status-chip input {{ accent-color: var(--accent); }}
            .batch-toolbar {{ display: flex; justify-content: space-between; gap: 10px; align-items: center; flex-wrap: wrap; margin: 10px 0 12px; }}
            .batch-toolbar .mini {{ color: var(--muted); font-size: 12px; }}
            .batch-rows {{ display: grid; gap: 10px; }}
            .batch-row {{
                display: grid;
                grid-template-columns: 1.2fr .7fr 1fr auto;
                gap: 10px;
                align-items: end;
                padding: 12px;
                border: 1px solid var(--line);
                border-radius: 18px;
                background: #fff;
            }}
            .batch-remove {{
                border: 1px solid #e5c7c7;
                background: #fff5f5;
                color: var(--bad);
                border-radius: 12px;
                padding: 10px 12px;
                font-size: 12px;
                font-weight: 800;
                cursor: pointer;
                height: 44px;
            }}
            .btn-row {{ display: flex; gap: 10px; flex-wrap: wrap; margin-top: 4px; }}
            .btn {{
                display: inline-flex;
                align-items: center;
                justify-content: center;
                border: 0;
                border-radius: 14px;
                padding: 11px 16px;
                background: var(--accent);
                color: #111;
                font-size: 14px;
                font-weight: 900;
                text-decoration: none;
                cursor: pointer;
            }}
            .btn.secondary {{ background: #111; color: #fff; }}
            .summary-list {{ display: grid; gap: 10px; }}
            .summary-item {{
                border: 1px solid var(--line);
                border-radius: 18px;
                padding: 14px;
                background: linear-gradient(180deg, #fff, #fbfaf7);
            }}
            .summary-item .top {{ display: flex; justify-content: space-between; gap: 10px; align-items: center; }}
            .summary-item .name {{ font-weight: 900; font-size: 15px; }}
            .summary-item .meta {{ margin-top: 6px; color: var(--muted); font-size: 12px; line-height: 1.5; }}
            .lesson-board {{ display: grid; gap: 10px; }}
            .lesson-board-head {{ display: flex; justify-content: space-between; gap: 10px; align-items: flex-end; flex-wrap: wrap; margin-bottom: 6px; }}
            .lesson-card {{
                display: block;
                text-decoration: none;
                color: inherit;
                border: 1px solid var(--line);
                border-radius: 18px;
                padding: 14px 15px;
                background: linear-gradient(180deg, #fff, #faf8f2);
                box-shadow: 0 8px 20px rgba(17,17,17,.04);
            }}
            .lesson-card.active {{ border-color: rgba(184,157,93,.55); box-shadow: 0 10px 24px rgba(184,157,93,.12); }}
            .lesson-card-top {{ display: flex; justify-content: space-between; gap: 10px; align-items: flex-start; }}
            .lesson-card-title {{ font-weight: 900; font-size: 15px; line-height: 1.35; }}
            .lesson-card-note {{ margin-top: 8px; color: var(--muted); font-size: 12px; line-height: 1.5; }}
            .lesson-empty {{ padding: 16px; border: 1px dashed #d8cab2; border-radius: 16px; background: rgba(255,255,255,.72); color: var(--muted); font-size: 13px; }}
            .lesson-form-head {{ display: flex; justify-content: space-between; gap: 10px; align-items: flex-end; flex-wrap: wrap; }}
            .lesson-summary {{ margin-top: 10px; display: grid; gap: 8px; }}
            .lesson-summary .row {{ display: flex; justify-content: space-between; gap: 12px; align-items: center; padding: 11px 12px; border: 1px solid var(--line); border-radius: 14px; background: #fff; }}
            .lesson-summary .row span {{ color: var(--muted); font-size: 12px; }}
            .lesson-summary .row strong {{ font-size: 13px; }}
            .roster-table td {{ vertical-align: middle; }}
            .roster-check {{ min-width: 120px; }}
            .roster-status {{
                width: 100%;
                border: 1px solid #d7d2c6;
                border-radius: 12px;
                padding: 10px 12px;
                font-size: 13px;
                background: #fff;
            }}
            .roster-reason {{
                width: 100%;
                border: 1px solid #d7d2c6;
                border-radius: 12px;
                padding: 10px 12px;
                font-size: 13px;
                background: #fff;
            }}
            .records-head {{ display: flex; justify-content: space-between; gap: 10px; align-items: flex-end; margin-bottom: 10px; flex-wrap: wrap; }}
            .records-actions {{ display: flex; gap: 8px; flex-wrap: wrap; }}
            .filter-input {{
                min-width: 220px;
                border: 1px solid #d7d2c6;
                border-radius: 999px;
                padding: 10px 14px;
                font-size: 13px;
                background: #fff;
            }}
            .filter-card {{
                border: 1px solid var(--line);
                border-radius: 18px;
                background: linear-gradient(180deg, #fff, #fbfaf7);
                padding: 14px;
                margin-bottom: 14px;
            }}
            .filter-grid {{
                display: grid;
                grid-template-columns: 1.2fr .9fr .9fr .9fr .8fr .8fr;
                gap: 10px;
            }}
            .filter-grid .field label {{ font-size: 11px; }}
            .table-wrap {{ overflow-x: auto; }}
            table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
            th {{ text-align: left; padding: 11px 10px; border-bottom: 2px solid #ddd3c2; color: var(--muted); font-size: 11px; letter-spacing: .08em; text-transform: uppercase; }}
            td {{ padding: 12px 10px; border-bottom: 1px solid #eee6d8; vertical-align: top; }}
            .mini-meta {{ color: var(--muted); font-size: 11px; margin-top: 4px; }}
            .badge {{
                display: inline-flex;
                align-items: center;
                gap: 6px;
                padding: 4px 10px;
                border-radius: 999px;
                font-size: 11px;
                font-weight: 800;
            }}
            .att-badge.att-present {{ background: #e7f8f1; color: var(--good); }}
            .att-badge.att-absent {{ background: #fdecec; color: var(--bad); }}
            .att-badge.att-dropped {{ background: #eef0f4; color: #515766; }}
            .empty-state {{
                padding: 18px;
                text-align: center;
                color: var(--muted);
                background: #fcfbf8;
            }}
            .att-cards {{ display: none; gap: 12px; }}
            .att-card {{
                border: 1px solid var(--line);
                border-radius: 18px;
                background: #fff;
                padding: 14px;
            }}
            .att-card-top {{ display: flex; justify-content: space-between; gap: 10px; align-items: flex-start; }}
            .att-card-title {{ font-weight: 900; font-size: 16px; }}
            .att-card-grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px 12px; margin-top: 12px; }}
            .att-card-grid span {{ display: block; color: var(--muted); font-size: 11px; margin-bottom: 3px; }}
            .att-card-grid strong {{ font-size: 13px; line-height: 1.45; }}
            .page-footer {{ margin-top: 16px; color: var(--muted); font-size: 12px; text-align: center; }}
            @media (max-width: 960px) {{
                .grid {{ grid-template-columns: 1fr; }}
            }}
            @media (max-width: 760px) {{
                body {{ padding: 14px; }}
                .hero {{ padding: 18px; border-radius: 22px; }}
                .panel {{ padding: 16px; border-radius: 20px; }}
                .stats {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
                .form-grid {{ grid-template-columns: 1fr; }}
                .span-2 {{ grid-column: auto; }}
                .status-row {{ grid-template-columns: 1fr; }}
                .batch-row {{ grid-template-columns: 1fr; }}
                .lesson-form-head,
                .lesson-board-head,
                .summary-item .top,
                .records-head {{
                    flex-direction: column;
                    align-items: stretch;
                }}
                .btn-row .btn,
                .btn-row a {{
                    width: 100%;
                }}
                .summary-list {{ gap: 8px; }}
                .summary-item {{ padding: 12px; }}
                .lesson-board {{ gap: 8px; }}
                .lesson-card {{ padding: 12px 13px; }}
                .lesson-summary .row {{ flex-direction: column; align-items: flex-start; gap: 4px; }}
                .roster-table th, .roster-table td {{ padding: 10px 8px; }}
                .roster-status, .roster-reason {{ font-size: 15px; }}
                .att-cards {{ display: grid; }}
                .att-card-grid {{ grid-template-columns: 1fr; }}
                .records-head {{ align-items: stretch; }}
                .filter-input {{ width: 100%; min-width: 0; }}
                .records-actions {{ width: 100%; }}
                .records-actions .btn, .records-actions .filter-input {{ flex: 1 1 100%; }}
                .filter-grid {{ grid-template-columns: 1fr 1fr; }}
                .filter-grid .field:last-child {{ grid-column: 1 / -1; }}
            }}
        </style>
    </head>
    <body>
        <div class="shell">
            <section class="hero">
                <div>
                    <div class="eyebrow">Di2da Admin · Student Attendance</div>
                    <h1>學生點名系統</h1>
                    <p class="lead">導師登入後可以即時記錄學生出席、缺席同原因。系統已預設九個地區，方便你按校區 / 堂別快速管理課堂出席。</p>
                    <div class="chips">
                        {all_chip}
                        {area_chips}
                    </div>
                </div>
                <div class="hero-side">
                    <div class="label">登入帳戶</div>
                    <div class="value">{html.escape(display_name)}</div>
                    <div class="label">角色</div>
                    <div class="value">{html.escape(role_label)}</div>
                    <div class="label">今日預設時間</div>
                    <div class="value">{today_date} {today_time}</div>
                </div>
            </section>

            {notice_html}

            <section class="grid">
                <div class="panel">
                    <div class="lesson-form-head">
                    <div>
                        <h2>點名流程示範</h2>
                        <p class="muted">先揀地區，再揀課堂，最後只需要揀日期同剔選出席位置，完成後提交。</p>
                    </div>
                        <div class="btn-row">
                            <a class="btn secondary" href="/attendance">重設</a>
                            <a class="btn secondary" href="/dashboard">返回主目錄</a>
                            {admin_manage_button}
                        </div>
                    </div>

                    <div class="summary-list" style="margin-top:14px;">
                        <div class="summary-item">
                            <div class="top"><div class="name">Step 1 · 地區</div><span class="badge att-badge att-present">先揀</span></div>
                            <div class="meta">用上面啲地區 chip 或者呢度嘅課堂清單過濾。例子：藍田、旺角、沙田。</div>
                        </div>
                        <div class="summary-item">
                            <div class="top"><div class="name">Step 2 · 課堂</div><span class="badge att-badge att-present">再揀</span></div>
                            <div class="meta">課堂名會似「星期六 1200-1300 coyi KPOP」咁顯示，方便導師即眼認到。</div>
                        </div>
                        <div class="summary-item">
                            <div class="top"><div class="name">Step 3 · 學生表格</div><span class="badge att-badge att-present">最終</span></div>
                            <div class="meta">管理員預先輸入名單，導師只需揀日期、剔選出席，必要時填缺席原因。</div>
                        </div>
                    </div>

                    <div class="lesson-board" style="margin-top:18px;">
                        <div class="lesson-board-head">
                            <div>
                                <h3 style="margin:0;">課堂名單</h3>
                                <div class="mini-meta">先揀地區，再揀一堂。下面係示範資料，之後可以換成真實班別。</div>
                            </div>
                            <div class="badge att-badge att-absent">{len(lesson_groups)} 個課堂</div>
                        </div>
                        {(_attendance_lesson_group_cards_html(lesson_groups, lesson_group_id) if lesson_groups else '<div class="lesson-empty">暫時未有課堂名單。你可以先用示範資料測試，或者再加真實班別。</div>')}
                    </div>

                    {roster_form_html}
                </div>

                <aside class="panel">
                    <h2>今日概覽</h2>
                    <p class="muted">目前篩選：{html.escape(selected_area_label)} · {html.escape(selected_teacher_label)} · {html.escape(selected_category_label)} · {html.escape(selected_status_label)} · {html.escape(date_range_label)}{f" · {html.escape(search_text)}" if search_text else ""}</p>
                    <div class="stats">
                        <div class="stat"><div class="num">{total_records}</div><div class="label">記錄總數</div></div>
                        <div class="stat"><div class="num">{today_records}</div><div class="label">今日記錄</div></div>
                        <div class="stat"><div class="num">{absent_records}</div><div class="label">缺席數</div></div>
                        <div class="stat"><div class="num">{unique_students}</div><div class="label">學生數</div></div>
                    </div>
                    <div style="margin-top:14px;" class="summary-list">
                        <div class="summary-item">
                            <div class="top"><div class="name">示範案例 1</div><span class="badge att-badge att-present">藍田</span></div>
                            <div class="meta">星期六 1200-1300 coyi KPOP · 6 位學生。適合展示「先揀地區，再揀課堂」。</div>
                        </div>
                        <div class="summary-item">
                            <div class="top"><div class="name">示範案例 2</div><span class="badge att-badge att-present">旺角</span></div>
                            <div class="meta">星期三 1530-1630 ring Street Dance · 5 位學生。導師只需剔選出席同填缺席原因。</div>
                        </div>
                        <div class="summary-item">
                            <div class="top"><div class="name">示範案例 3</div><span class="badge att-badge att-present">沙田</span></div>
                            <div class="meta">星期日 1000-1100 szelo Cheerleading · 4 位學生。管理員預先輸入名單後就可以直接使用。</div>
                        </div>
                    </div>
                </aside>
            </section>

            <section class="panel" style="margin-top:18px;">
                <div class="records-head">
                    <div>
                        <h2>最近點名記錄</h2>
                        <p class="muted">顯示最近 40 筆，方便核對學生出席同缺席原因。</p>
                    </div>
                    <div class="records-actions">
                        <a class="btn secondary" href="{export_href}">匯出 CSV</a>
                    </div>
                </div>
                <form method="get" action="/attendance" class="filter-card">
                    <input type="hidden" name="area" value="{html.escape(selected_area if selected_area else '', quote=True)}">
                    <div class="filter-grid">
                        <div class="field">
                            <label>搜尋</label>
                            <input class="filter-input" type="text" name="q" value="{html.escape(search_text, quote=True)}" placeholder="學生 / 類別 / 原因 / 記錄者">
                        </div>
                        <div class="field">
                            <label>導師</label>
                            <select name="teacher">
                                {_attendance_teacher_options_html(teacher_values, teacher_filter)}
                            </select>
                        </div>
                        <div class="field">
                            <label>課堂類別</label>
                            <select name="category">
                                <option value="">全部類別</option>
                                {"".join(f'<option value="{html.escape(item, quote=True)}"{" selected" if item == category_filter else ""}>{html.escape(item)}</option>' for item in ATTENDANCE_CATEGORY_OPTIONS)}
                            </select>
                        </div>
                        <div class="field">
                            <label>出席狀態</label>
                            <select name="status">
                                <option value="">全部狀態</option>
                                <option value="present"{' selected' if status_filter == 'present' else ''}>出席</option>
                                <option value="absent"{' selected' if status_filter == 'absent' else ''}>缺席</option>
                                <option value="dropped"{' selected' if status_filter == 'dropped' else ''}>已退學</option>
                            </select>
                        </div>
                        <div class="field">
                            <label>日期由</label>
                            <input type="date" name="date_from" value="{html.escape(date_from, quote=True)}">
                        </div>
                        <div class="field">
                            <label>日期至</label>
                            <input type="date" name="date_to" value="{html.escape(date_to, quote=True)}">
                        </div>
                    </div>
                    <div class="btn-row" style="margin-top:12px;">
                        <button class="btn secondary" type="submit">套用篩選</button>
                        <a class="btn" href="/attendance">清除篩選</a>
                    </div>
                </form>
                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>課堂時間</th>
                                <th>地區</th>
                                <th>學生</th>
                                <th>課堂類別</th>
                                <th>狀態</th>
                                <th>缺席原因</th>
                                <th>記錄者</th>
                            </tr>
                        </thead>
                        <tbody>{rows_html}</tbody>
                    </table>
                </div>
                <div class="att-cards">{cards_html}</div>
            </section>

            <div class="page-footer">學生點名系統 · 導師登入後使用 · 記錄會儲存於 SQLite</div>
        </div>
        <script>
        (function() {{
            const radios = Array.from(document.querySelectorAll('input[name="status"]'));
            const reason = document.getElementById('absence-reason');
            function syncReason() {{
                const selected = radios.find((item) => item.checked);
                const isAbsent = selected && selected.value === 'absent';
                if (reason) {{
                    reason.disabled = !isAbsent;
                    reason.closest('.field')?.querySelector('label')?.textContent = isAbsent ? '缺席原因 - 如有' : '缺席原因 - 缺席先填';
                    if (!isAbsent) {{
                        reason.value = '';
                    }}
                }}
            }}
            radios.forEach((radio) => radio.addEventListener('change', syncReason));
            syncReason();
        }})();
        (function() {{
            const rows = document.getElementById('batch-rows');
            const template = document.getElementById('batch-row-template');
            const addButton = document.getElementById('add-batch-row');
            if (!rows || !template || !addButton) return;

            addButton.addEventListener('click', () => {{
                const fragment = template.content.cloneNode(true);
                rows.appendChild(fragment);
            }});

            rows.addEventListener('click', (event) => {{
                const button = event.target.closest('[data-batch-remove]');
                if (!button) return;
                const row = button.closest('[data-batch-row]');
                if (!row) return;
                const allRows = Array.from(rows.querySelectorAll('[data-batch-row]'));
                if (allRows.length <= 1) return;
                row.remove();
            }});
        }})();
        (function() {{
            const rosterRows = Array.from(document.querySelectorAll('[data-roster-row]'));
            if (!rosterRows.length) return;
            const syncRow = (row) => {{
                const status = row.querySelector('select[name^="student_status_"]');
                const reason = row.querySelector('.roster-reason');
                if (!status || !reason) return;
                const isAbsent = status.value === 'absent';
                reason.placeholder = isAbsent ? '請填缺席原因' : '如有可備註';
            }};
            rosterRows.forEach((row) => {{
                const status = row.querySelector('select[name^="student_status_"]');
                if (!status) return;
                status.addEventListener('change', () => syncRow(row));
                syncRow(row);
            }});
        }})();
        </script>
    </body>
    </html>
    """)


@app.get("/attendance", response_class=HTMLResponse)
async def attendance_home(
    request: Request,
    area: str = Query(default=""),
    lesson_group_id: int = Query(default=0),
    q: str = Query(default=""),
    notice: str = Query(default=""),
    count: int = Query(default=0),
    teacher: str = Query(default=""),
    category: str = Query(default=""),
    status: str = Query(default=""),
    date_from: str = Query(default=""),
    date_to: str = Query(default=""),
    user: tuple = Depends(require_roles("admin", "tutor")),
):
    return _render_attendance_page(
        request,
        notice=notice,
        added_count=count,
        selected_area=area,
        lesson_group_id=lesson_group_id,
        search_text=q,
        teacher_filter=teacher,
        category_filter=category,
        status_filter=status,
        date_from=date_from,
        date_to=date_to,
    )


def _attendance_csv_response(
    selected_area: str = "",
    search_text: str = "",
    teacher_filter: str = "",
    category_filter: str = "",
    status_filter: str = "",
    date_from: str = "",
    date_to: str = "",
):
    where_sql, params = _attendance_records_where_clause(
        selected_area=selected_area,
        search_text=search_text,
        teacher_filter=teacher_filter,
        category_filter=category_filter,
        status_filter=status_filter,
        date_from=date_from,
        date_to=date_to,
    )
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        f"""
        SELECT class_date, area, COALESCE(NULLIF(lesson_title, ''), NULLIF(class_category, ''), '') AS lesson_title, student_name, status, absence_reason, COALESCE(NULLIF(recorded_by_display_name, ''), recorded_by_username, '') AS recorded_by, created_at
        FROM attendance_records
        {where_sql}
        ORDER BY class_date DESC, class_time DESC, id DESC
        """
        ,
        params,
    )
    rows = cursor.fetchall()
    conn.close()
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["日期", "地區", "課堂", "學生名", "狀態", "缺席原因", "記錄者", "記錄時間"])
    for row in rows:
        writer.writerow([
            row[0] or "",
            row[1] or "",
            row[2] or "",
            row[3] or "",
            row[4] or "",
            row[5] or "",
            row[6] or "",
            row[7] or "",
        ])
    csv_bytes = buffer.getvalue().encode("utf-8-sig")
    headers = {
        "Content-Disposition": 'attachment; filename="attendance_records.csv"',
    }
    return Response(content=csv_bytes, media_type="text/csv; charset=utf-8", headers=headers)


@app.get("/attendance/export.csv")
async def attendance_export_csv(
    request: Request,
    area: str = Query(default=""),
    q: str = Query(default=""),
    teacher: str = Query(default=""),
    category: str = Query(default=""),
    status: str = Query(default=""),
    date_from: str = Query(default=""),
    date_to: str = Query(default=""),
    user: tuple = Depends(require_roles("admin", "tutor")),
):
    return _attendance_csv_response(
        selected_area=area,
        search_text=q,
        teacher_filter=teacher,
        category_filter=category,
        status_filter=status,
        date_from=date_from,
        date_to=date_to,
    )


@app.post("/attendance/submit")
async def attendance_submit(
    request: Request,
    lesson_group_id: int = Form(...),
    class_date: str = Form(...),
    user: tuple = Depends(require_roles("admin", "tutor")),
):
    form = await request.form()
    lesson_group = _attendance_lesson_group_fetch(int(lesson_group_id or 0))
    if not lesson_group:
        return RedirectResponse("/attendance?notice=empty", status_code=303)

    lesson_students = _attendance_lesson_students_fetch(int(lesson_group_id or 0))
    if not lesson_students:
        return RedirectResponse("/attendance?notice=empty", status_code=303)

    lesson_id, area, class_title, weekday, class_time, class_category, teacher_name, school_name, notes, sort_order, is_demo, is_active = lesson_group

    prepared_rows = []
    for student_id, student_name, display_order, note in lesson_students:
        status_value = (form.get(f"student_status_{student_id}") or "present").strip().lower()
        status_value = "absent" if status_value == "absent" else "present"
        reason_value = (form.get(f"absence_reason_{student_id}") or "").strip() if status_value == "absent" else ""
        if status_value == "absent" and not reason_value:
            raise HTTPException(status_code=400, detail=f"{student_name or '學生'} 缺席原因必須填寫")
        prepared_rows.append(
            (
                int(student_id or 0),
                student_name or "",
                int(display_order or 0),
                status_value,
                reason_value,
            )
        )

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    inserted = 0
    inserted_students: list[str] = []
    cursor.execute(
        "DELETE FROM attendance_records WHERE lesson_group_id=? AND class_date=?",
        (int(lesson_id or lesson_group_id or 0), class_date.strip()),
    )
    for student_id, student_name, display_order, status_value, reason_value in prepared_rows:
        cursor.execute(
            """
            INSERT INTO attendance_records (
                lesson_group_id, area, student_name, class_date, class_time, class_category, lesson_title, student_order, status, absence_reason,
                recorded_by_username, recorded_by_display_name, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (
                int(lesson_id or lesson_group_id or 0),
                area or "",
                student_name or "",
                class_date.strip(),
                class_time or "",
                class_category or "",
                class_title or weekday or "",
                int(display_order or 0),
                status_value,
                reason_value,
                user[1] if len(user) > 1 else "",
                user[2] if len(user) > 2 else (user[1] if len(user) > 1 else ""),
            ),
        )
        inserted += 1
        if len(inserted_students) < 6:
            inserted_students.append(student_name or "")
    conn.commit()
    conn.close()
    _audit_action_request(
        request,
        "attendance_submit",
        target_type="attendance_record",
        target_id=str(lesson_group_id),
        actor=user,
        after={
            "lesson_group_id": int(lesson_group_id or 0),
            "class_date": class_date.strip(),
            "count": inserted,
            "students": inserted_students,
        },
    )
    review_query = urlencode({
        "lesson_group_id": int(lesson_group_id or 0),
        "class_date": class_date.strip(),
        "notice": "submitted",
    })
    return RedirectResponse(f"/attendance/review?{review_query}", status_code=303)


def _attendance_review_page(request: Request, lesson_group, records, class_date: str, notice: str = ""):
    lesson_id, area, class_title, weekday, class_time, class_category, teacher_name, school_name, notes, sort_order, is_demo, is_active = lesson_group
    total = len(records)
    present_count = sum(1 for row in records if (row[6] or "").strip().lower() == "present")
    absent_count = sum(1 for row in records if (row[6] or "").strip().lower() == "absent")
    dropped_count = sum(1 for row in records if (row[6] or "").strip().lower() == "dropped")
    record_rows_html = "".join(_attendance_row_html(row) for row in records) or '<tr><td colspan="7" class="empty-state">暫時未有已儲存記錄。</td></tr>'
    notice_html = '<div class="notice success">已完成提交，可供管理員核對。</div>' if notice == "submitted" else ""
    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html lang="zh-HK">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{APP_NAME} - 點名核對</title>
        <style>
            body {{ margin:0; font-family:-apple-system,BlinkMacSystemFont,"PingFang HK","Noto Sans TC",sans-serif; background:#f7f1e6; color:#111; padding:22px; }}
            .shell {{ max-width:1200px; margin:0 auto; display:grid; gap:16px; }}
            .panel {{ background:#fff; border:1px solid rgba(17,17,17,.1); border-radius:22px; padding:18px; }}
            .header {{ display:flex; justify-content:space-between; gap:10px; align-items:flex-end; flex-wrap:wrap; }}
            .lead {{ color:#66615b; margin:8px 0 0; line-height:1.6; }}
            .btn-row {{ display:flex; gap:10px; flex-wrap:wrap; margin-top:12px; }}
            .btn {{ display:inline-flex; align-items:center; justify-content:center; padding:10px 14px; border-radius:12px; text-decoration:none; font-weight:800; border:0; background:#b89d5d; color:#111; }}
            .btn.secondary {{ background:#111; color:#fff; }}
            .stats {{ display:grid; grid-template-columns:repeat(4, minmax(0,1fr)); gap:10px; margin-top:12px; }}
            .stat {{ padding:12px; border:1px solid rgba(17,17,17,.1); border-radius:16px; background:#faf8f2; }}
            .stat .num {{ font-size:22px; font-weight:900; }}
            .stat .label {{ color:#66615b; font-size:12px; }}
            .table-wrap {{ overflow-x:auto; }}
            table {{ width:100%; border-collapse:collapse; font-size:13px; }}
            th {{ text-align:left; padding:11px 10px; border-bottom:2px solid #ddd3c2; color:#66615b; font-size:11px; letter-spacing:.08em; text-transform:uppercase; }}
            td {{ padding:12px 10px; border-bottom:1px solid #eee6d8; vertical-align:top; }}
            .notice {{ margin-top:14px; border-radius:16px; padding:12px 14px; border:1px solid rgba(17,17,17,.1); background:#fff; }}
            .notice.success {{ background:#edf9f3; border-color:rgba(19,122,99,.18); color:#137a63; }}
            @media print {{
                .no-print {{ display:none !important; }}
                body {{ background:#fff; padding:0; }}
                .panel {{ border:0; box-shadow:none; }}
            }}
            @media (max-width:760px) {{
                body {{ padding:14px; }}
                .header {{ align-items:stretch; }}
                .btn-row {{ width:100%; }}
                .btn-row .btn, .btn-row a {{ width:100%; }}
                .stats {{ grid-template-columns:repeat(2, minmax(0,1fr)); }}
                .stat .num {{ font-size:20px; }}
                .table-wrap {{ overflow-x:auto; -webkit-overflow-scrolling: touch; }}
                th, td {{ white-space: nowrap; }}
            }}
        </style>
    </head>
    <body>
        <div class="shell">
            <div class="panel">
                <div class="header">
                    <div>
                        <h1 style="margin:0;">點名核對</h1>
                        <p class="lead">{html.escape(class_title or '課堂')} · {html.escape(area or '-')} · {html.escape(class_date)} · {html.escape(class_time or '')} · {html.escape(class_category or '')}</p>
                    </div>
                    <div class="btn-row no-print">
                        <button class="btn secondary" onclick="window.print()">列印 / 存成 PDF</button>
                        <a class="btn secondary" href="/attendance?area={html.escape(area or '', quote=True)}&lesson_group_id={int(lesson_id or 0)}">返回點名頁</a>
                        <a class="btn secondary" href="/attendance/manage">管理課堂</a>
                        <a class="btn secondary" href="/dashboard">返回主目錄</a>
                    </div>
                </div>
                {notice_html}
                <div class="stats">
                    <div class="stat"><div class="num">{total}</div><div class="label">總記錄</div></div>
                    <div class="stat"><div class="num">{present_count}</div><div class="label">出席</div></div>
                    <div class="stat"><div class="num">{absent_count}</div><div class="label">缺席</div></div>
                    <div class="stat"><div class="num">{dropped_count}</div><div class="label">已退學</div></div>
                </div>
            </div>
            <div class="panel">
                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>時間</th>
                                <th>地區</th>
                                <th>學生</th>
                                <th>課堂</th>
                                <th>狀態</th>
                                <th>缺席原因</th>
                                <th>記錄者</th>
                            </tr>
                        </thead>
                        <tbody>{record_rows_html}</tbody>
                    </table>
                </div>
            </div>
        </div>
    </body>
    </html>
    """)


@app.get("/attendance/review", response_class=HTMLResponse)
async def attendance_review(
    request: Request,
    lesson_group_id: int = Query(default=0),
    class_date: str = Query(default=""),
    notice: str = Query(default=""),
    user: tuple = Depends(require_roles("admin", "tutor")),
):
    lesson_group = _attendance_lesson_group_fetch(int(lesson_group_id or 0))
    if not lesson_group:
        return RedirectResponse("/attendance?notice=empty", status_code=303)
    records = _attendance_review_records_fetch(int(lesson_group_id or 0), class_date or "")
    return _attendance_review_page(request, lesson_group, records, class_date or "", notice=notice)


@app.post("/attendance/students/add")
async def attendance_students_add(
    request: Request,
    lesson_group_id: int = Form(...),
    student_name: str = Form(...),
    display_order: str = Form(""),
    user: tuple = Depends(require_roles("admin", "tutor")),
):
    lesson_group = _attendance_lesson_group_fetch(int(lesson_group_id or 0))
    if not lesson_group:
        return RedirectResponse("/attendance?notice=empty", status_code=303)

    name_value = student_name.strip()
    if not name_value:
        return RedirectResponse(f"/attendance?lesson_group_id={int(lesson_group_id or 0)}&notice=empty", status_code=303)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT COALESCE(MAX(COALESCE(display_order, 0)), 0) + 1 FROM attendance_lesson_students WHERE lesson_group_id=?",
        (int(lesson_group_id or 0),),
    )
    next_order = cursor.fetchone()[0] or 1
    try:
        order_value = int(display_order) if str(display_order or "").strip() else int(next_order)
    except ValueError:
        order_value = int(next_order)
    cursor.execute(
        """
        INSERT INTO attendance_lesson_students (
            lesson_group_id, student_name, display_order, is_active, updated_at
        ) VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP)
        """,
        (int(lesson_group_id or 0), name_value, order_value),
    )
    conn.commit()
    conn.close()
    _audit_action_request(
        request,
        "attendance_student_add",
        target_type="attendance_lesson_student",
        target_id=str(lesson_group_id),
        actor=user,
        after={"lesson_group_id": int(lesson_group_id or 0), "student_name": name_value, "display_order": order_value},
    )
    query = urlencode({
        "area": lesson_group[1] or "",
        "lesson_group_id": int(lesson_group_id or 0),
        "notice": "student_added",
    })
    return RedirectResponse(f"/attendance?{query}", status_code=303)


def _attendance_manage_group_card(request: Request, group_row):
    group_id, area, class_title, weekday, lesson_time, class_category, teacher_name, school_name, notes, sort_order, is_demo, is_active = group_row
    student_rows = _attendance_lesson_students_fetch(group_id)
    student_text = "\n".join(row[1] for row in student_rows)
    return f"""
    <div class="panel">
        <h3>課堂 #{group_id}</h3>
        <form method="post" action="/attendance/groups/{group_id}/save" class="stack">
            {_csrf_input_html(request)}
            <div class="form-grid">
                <div class="field"><label>地區</label><select name="area">{_attendance_area_options_html(area)}</select></div>
                <div class="field"><label>課堂名稱</label><input name="class_title" value="{html.escape(class_title or '', quote=True)}" required></div>
                <div class="field"><label>星期</label><select name="weekday">{_attendance_weekday_options_html(weekday)}</select></div>
                <div class="field"><label>時間</label><input name="lesson_time" value="{html.escape(lesson_time or '', quote=True)}"></div>
                <div class="field"><label>類別</label><input name="class_category" value="{html.escape(class_category or '', quote=True)}"></div>
                <div class="field"><label>導師</label><input name="teacher_name" value="{html.escape(teacher_name or '', quote=True)}"></div>
                <div class="field"><label>學校</label><input name="school_name" value="{html.escape(school_name or '', quote=True)}"></div>
                <div class="field"><label>排序</label><input name="sort_order" type="number" value="{int(sort_order or 0)}"></div>
                <div class="field"><label>示範</label><select name="is_demo"><option value="0"{' selected' if not int(is_demo or 0) else ''}>否</option><option value="1"{' selected' if int(is_demo or 0) else ''}>是</option></select></div>
                <div class="field"><label>啟用</label><select name="is_active"><option value="1"{' selected' if int(is_active or 0) else ''}>啟用</option><option value="0"{' selected' if not int(is_active or 0) else ''}>停用</option></select></div>
                <div class="field span-2"><label>備註</label><textarea name="notes">{html.escape(notes or '')}</textarea></div>
            </div>
            <div class="btn-row">
                <button type="submit" class="btn">儲存課堂資料</button>
                <a class="btn secondary" href="/attendance?area={html.escape(area or '', quote=True)}&lesson_group_id={group_id}">返回點名</a>
            </div>
        </form>
        <form method="post" action="/attendance/groups/{group_id}/students/save" class="stack" style="margin-top:14px;">
            {_csrf_input_html(request)}
            <div class="field">
                <label>學生名單</label>
                <textarea name="student_names" placeholder="每行一位學生">{html.escape(student_text)}</textarea>
            </div>
            <div class="btn-row">
                <button type="submit" class="btn secondary">更新學生名單</button>
            </div>
        </form>
    </div>
    """


@app.get("/attendance/manage", response_class=HTMLResponse)
async def attendance_manage(request: Request, notice: str = Query(default=""), user: tuple = Depends(require_roles("admin"))):
    groups = _attendance_lesson_groups_fetch("")
    manage_cards = "".join(_attendance_manage_group_card(request, group) for group in groups) or '<div class="lesson-empty">暫時未有課堂資料。</div>'
    notice_html = '<div class="notice success" style="margin-top:14px;">已更新課堂資料。</div>' if notice == "group_saved" else ""
    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html lang="zh-HK">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{APP_NAME} - 課堂資料管理</title>
        <style>
            body {{ margin:0; font-family:-apple-system,BlinkMacSystemFont,"PingFang HK","Noto Sans TC",sans-serif; background:#f7f1e6; color:#111; padding:22px; }}
            .shell {{ max-width:1200px; margin:0 auto; display:grid; gap:16px; }}
            .panel {{ background:#fff; border:1px solid rgba(17,17,17,.1); border-radius:22px; padding:18px; }}
            .header {{ display:flex; justify-content:space-between; gap:10px; align-items:flex-end; flex-wrap:wrap; }}
            .lead {{ color:#66615b; margin:8px 0 0; line-height:1.6; }}
            .btn-row {{ display:flex; gap:10px; flex-wrap:wrap; margin-top:12px; }}
            .btn {{ display:inline-flex; align-items:center; justify-content:center; padding:10px 14px; border-radius:12px; text-decoration:none; font-weight:800; border:0; background:#b89d5d; color:#111; }}
            .btn.secondary {{ background:#111; color:#fff; }}
            .form-grid {{ display:grid; grid-template-columns:repeat(2, minmax(0,1fr)); gap:10px; }}
            .field {{ display:grid; gap:6px; }}
            .field input, .field textarea, .field select {{ width:100%; padding:10px 12px; border:1px solid #d7d2c6; border-radius:12px; font-size:14px; }}
            .field textarea {{ min-height:92px; }}
            .span-2 {{ grid-column:1 / -1; }}
            .cards {{ display:grid; gap:14px; }}
            @media (max-width: 760px) {{
                body {{ padding:14px; }}
                .header {{ align-items:stretch; }}
                .btn-row {{ width:100%; }}
                .btn-row .btn, .btn-row a {{ width:100%; }}
                .form-grid {{ grid-template-columns:1fr; }}
                .span-2 {{ grid-column:auto; }}
                .panel {{ padding:14px; border-radius:18px; }}
                .cards {{ gap:12px; }}
                .field input, .field textarea, .field select {{ font-size:15px; }}
            }}
        </style>
    </head>
    <body>
        <div class="shell">
            <div class="panel">
                <div class="header">
                    <div>
                        <h1 style="margin:0;">課堂資料管理</h1>
                        <p class="lead">管理員可以喺呢度新增或修改課堂主檔，同埋重整學生名單。之後導師點名頁會即時讀呢份資料。</p>
                    </div>
                    <div class="btn-row">
                        <a class="btn secondary" href="/attendance">返回點名</a>
                        <a class="btn secondary" href="/dashboard">返回主目錄</a>
                    </div>
                </div>
            </div>
            {notice_html}
            <div class="panel">
                <h2 style="margin-top:0;">新增課堂</h2>
                <form method="post" action="/attendance/groups/new" class="stack">
                    {_csrf_input_html(request)}
                    <div class="form-grid">
                        <div class="field"><label>地區</label><select name="area">{_attendance_area_options_html()}</select></div>
                        <div class="field"><label>課堂名稱</label><input name="class_title" placeholder="星期六 1200-1300 coyi KPOP" required></div>
                        <div class="field"><label>星期</label><select name="weekday">{_attendance_weekday_options_html()}</select></div>
                        <div class="field"><label>時間</label><input name="lesson_time" placeholder="12:00-13:00"></div>
                        <div class="field"><label>類別</label><input name="class_category" placeholder="KPOP"></div>
                        <div class="field"><label>導師</label><input name="teacher_name" placeholder="Coyi"></div>
                        <div class="field"><label>學校</label><input name="school_name" placeholder="學校 / 地點"></div>
                        <div class="field"><label>排序</label><input name="sort_order" type="number" value="0"></div>
                        <div class="field"><label>示範</label><select name="is_demo"><option value="0">否</option><option value="1">是</option></select></div>
                        <div class="field"><label>啟用</label><select name="is_active"><option value="1">啟用</option><option value="0">停用</option></select></div>
                        <div class="field span-2"><label>備註</label><textarea name="notes" placeholder="管理員提示 / 內部備註"></textarea></div>
                    </div>
                    <div class="btn-row">
                        <button type="submit" class="btn">建立課堂</button>
                    </div>
                </form>
            </div>
            <div class="cards">
                {manage_cards}
            </div>
        </div>
    </body>
    </html>
    """)


@app.post("/attendance/groups/new")
async def attendance_group_new(
    request: Request,
    area: str = Form(""),
    class_title: str = Form(...),
    weekday: str = Form(""),
    lesson_time: str = Form(""),
    class_category: str = Form(""),
    teacher_name: str = Form(""),
    school_name: str = Form(""),
    notes: str = Form(""),
    sort_order: str = Form(""),
    is_demo: str = Form("0"),
    is_active: str = Form("1"),
    user: tuple = Depends(require_roles("admin")),
):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO attendance_lesson_groups (
            area, class_title, weekday, lesson_time, class_category, teacher_name, school_name, notes, sort_order, is_demo, is_active, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """,
        (
            area.strip(),
            class_title.strip(),
            weekday.strip(),
            lesson_time.strip(),
            class_category.strip(),
            teacher_name.strip(),
            school_name.strip(),
            notes.strip(),
            int(sort_order or 0),
            1 if str(is_demo).strip() == "1" else 0,
            1 if str(is_active).strip() != "0" else 0,
        ),
    )
    group_id = cursor.lastrowid
    conn.commit()
    conn.close()
    _audit_action_request(request, "attendance_group_new", target_type="attendance_lesson_group", target_id=str(group_id), actor=user, after={"class_title": class_title.strip()})
    return RedirectResponse("/attendance/manage?notice=group_saved", status_code=303)


@app.post("/attendance/groups/{group_id}/save")
async def attendance_group_save(
    request: Request,
    group_id: int,
    area: str = Form(""),
    class_title: str = Form(...),
    weekday: str = Form(""),
    lesson_time: str = Form(""),
    class_category: str = Form(""),
    teacher_name: str = Form(""),
    school_name: str = Form(""),
    notes: str = Form(""),
    sort_order: str = Form(""),
    is_demo: str = Form("0"),
    is_active: str = Form("1"),
    user: tuple = Depends(require_roles("admin")),
):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE attendance_lesson_groups
        SET area=?, class_title=?, weekday=?, lesson_time=?, class_category=?, teacher_name=?, school_name=?, notes=?, sort_order=?, is_demo=?, is_active=?, updated_at=CURRENT_TIMESTAMP
        WHERE id=?
        """,
        (
            area.strip(),
            class_title.strip(),
            weekday.strip(),
            lesson_time.strip(),
            class_category.strip(),
            teacher_name.strip(),
            school_name.strip(),
            notes.strip(),
            int(sort_order or 0),
            1 if str(is_demo).strip() == "1" else 0,
            1 if str(is_active).strip() != "0" else 0,
            group_id,
        ),
    )
    conn.commit()
    conn.close()
    _audit_action_request(request, "attendance_group_save", target_type="attendance_lesson_group", target_id=str(group_id), actor=user, after={"class_title": class_title.strip()})
    return RedirectResponse("/attendance/manage?notice=group_saved", status_code=303)


@app.post("/attendance/groups/{group_id}/students/save")
async def attendance_group_students_save(
    request: Request,
    group_id: int,
    student_names: str = Form(""),
    user: tuple = Depends(require_roles("admin")),
):
    group = _attendance_lesson_group_fetch(group_id)
    if not group:
        return RedirectResponse("/attendance/manage?notice=empty", status_code=303)
    names = []
    for line in (student_names or "").splitlines():
        item = line.strip()
        if item and item not in names:
            names.append(item)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM attendance_lesson_students WHERE lesson_group_id=?", (group_id,))
    for idx, name in enumerate(names, start=1):
        cursor.execute(
            """
            INSERT INTO attendance_lesson_students (lesson_group_id, student_name, display_order, is_active, updated_at)
            VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP)
            """,
            (group_id, name, idx),
        )
    conn.commit()
    conn.close()
    _audit_action_request(request, "attendance_group_students_save", target_type="attendance_lesson_group", target_id=str(group_id), actor=user, after={"count": len(names)})
    return RedirectResponse("/attendance/manage?notice=group_saved", status_code=303)


async def _attendance_create_manual_record(
    request: Request,
    area: str = Form(""),
    student_name: str = Form(...),
    class_date: str = Form(...),
    class_time: str = Form(...),
    class_category: str = Form(""),
    status: str = Form("present"),
    absence_reason: str = Form(""),
    user: tuple = Depends(require_roles("admin", "tutor")),
):
    area_value = area.strip()
    student_value = student_name.strip()
    date_value = class_date.strip()
    time_value = class_time.strip()
    category_value = class_category.strip()
    raw_status = str(status or "").strip().lower()
    status_value = raw_status if raw_status in {"present", "absent", "dropped"} else "present"
    reason_value = absence_reason.strip() if status_value == "absent" else ""
    if status_value == "absent" and not reason_value:
        raise HTTPException(status_code=400, detail="缺席原因必須填寫")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO attendance_records (
            area, student_name, class_date, class_time, class_category, status, absence_reason,
            recorded_by_username, recorded_by_display_name, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """,
        (
            area_value,
            student_value,
            date_value,
            time_value,
            category_value,
            status_value,
            reason_value,
            user[1] if len(user) > 1 else "",
            user[2] if len(user) > 2 else (user[1] if len(user) > 1 else ""),
        ),
    )
    record_id = cursor.lastrowid
    conn.commit()
    conn.close()
    _audit_action_request(
        request,
        "attendance_create",
        target_type="attendance_record",
        target_id=str(record_id),
        actor=user,
        after={
            "area": area_value,
            "student_name": student_value,
            "class_date": date_value,
            "class_time": time_value,
            "class_category": category_value,
            "status": status_value,
        },
    )
    return RedirectResponse("/attendance?notice=added", status_code=303)


@app.post("/attendance/create")
@app.post("/attendance/record")
async def attendance_create(
    request: Request,
    area: str = Form(""),
    student_name: str = Form(...),
    class_date: str = Form(...),
    class_time: str = Form(...),
    class_category: str = Form(""),
    status: str = Form("present"),
    absence_reason: str = Form(""),
    user: tuple = Depends(require_roles("admin", "tutor")),
):
    return await _attendance_create_manual_record(
        request=request,
        area=area,
        student_name=student_name,
        class_date=class_date,
        class_time=class_time,
        class_category=class_category,
        status=status,
        absence_reason=absence_reason,
        user=user,
    )


@app.post("/attendance/batch-create")
async def attendance_batch_create(
    request: Request,
    area: str = Form(""),
    class_date: str = Form(...),
    class_time: str = Form(...),
    class_category: str = Form(""),
    batch_student_name: List[str] = Form(default=[]),
    batch_status: List[str] = Form(default=[]),
    batch_absence_reason: List[str] = Form(default=[]),
    user: tuple = Depends(require_roles("admin", "tutor")),
):
    area_value = area.strip()
    date_value = class_date.strip()
    time_value = class_time.strip()
    category_value = class_category.strip()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    inserted = 0
    inserted_students: list[str] = []
    row_count = max(len(batch_student_name), len(batch_status), len(batch_absence_reason))
    for idx in range(row_count):
        student_value = (batch_student_name[idx] if idx < len(batch_student_name) else "").strip()
        if not student_value:
            continue
        raw_status = str(batch_status[idx]).strip().lower() if idx < len(batch_status) else "present"
        status_value = raw_status if raw_status in {"present", "absent", "dropped"} else "present"
        reason_value = (batch_absence_reason[idx] if idx < len(batch_absence_reason) else "").strip() if status_value == "absent" else ""
        if status_value == "absent" and not reason_value:
            raise HTTPException(status_code=400, detail=f"{student_value} 缺席原因必須填寫")
        cursor.execute(
            """
            INSERT INTO attendance_records (
                area, student_name, class_date, class_time, class_category, status, absence_reason,
                recorded_by_username, recorded_by_display_name, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (
                area_value,
                student_value,
                date_value,
                time_value,
                category_value,
                status_value,
                reason_value,
                user[1] if len(user) > 1 else "",
                user[2] if len(user) > 2 else (user[1] if len(user) > 1 else ""),
            ),
        )
        inserted += 1
        if len(inserted_students) < 6:
            inserted_students.append(student_value)
    conn.commit()
    conn.close()
    _audit_action_request(
        request,
        "attendance_batch_create",
        target_type="attendance_record",
        target_id=area_value or "batch",
        actor=user,
        after={
            "area": area_value,
            "class_date": date_value,
            "class_time": time_value,
            "class_category": category_value,
            "count": inserted,
            "students": inserted_students,
        },
    )
    if inserted:
        return RedirectResponse(f"/attendance?notice=added&count={inserted}", status_code=303)
    return RedirectResponse("/attendance?notice=empty", status_code=303)


def _render_accounts_page(request: Request, notice: str = ""):
    user = _require_admin(request)
    csrf_html = _csrf_input_html(request)
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
                    {csrf_html}
                    <button type="submit">{'停用' if r[4] else '啟用'}</button>
                </form>
                <form class="inline" action="/admin/accounts/{r[0]}/reset-password" method="post">
                    {csrf_html}
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
                    <a href="/admin/audit-logs">Audit Log</a>
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
                    {csrf_html}
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
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, title, body, pinned, created_by, image_filename, image_mime, image_blob, created_at, teacher_quote
            FROM announcements
            ORDER BY pinned DESC, created_at DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cursor.fetchall()
        conn.close()
        return rows
    except Exception:
        # Public pages must stay up even if the remote DB proxy is temporarily unavailable.
        return []


def _render_announcements_page(request: Request, notice: str = ""):
    user = _current_user_record(request)
    is_admin = bool(user and _normalize_role(user[3]) == "admin")
    csrf_html = _csrf_input_html(request)
    rows = _get_recent_announcements(20)
    notice_html = f'<div class="notice">{html.escape(notice)}</div>' if notice else ""
    items_html = ""
    for r in rows:
        delete_html = ""
        if is_admin:
            delete_html = f"""
            <form class="inline" action="/announcements/{r[0]}/delete" method="post" style="margin-top:12px;">
                {csrf_html}
                <button type="submit">刪除</button>
            </form>
            """
        img_html = ""
        if r[7]:
            mime = html.escape(r[6] or "image/png")
            alt = html.escape(r[5] or "announcement image")
            img_data = base64.b64encode(r[7]).decode("ascii")
            img_html = f'<div style="margin-top:14px;"><img src="data:{mime};base64,{img_data}" alt="{alt}" style="max-width:100%;border-radius:16px;border:1px solid #e5e7eb;display:block;"></div>'
        teacher_quote = html.escape(r[9] or "").replace("\n", "<br>")
        teacher_quote_html = ""
        if teacher_quote:
            teacher_quote_html = f'''
            <div style="margin-top:12px;padding:12px 14px;border-left:4px solid #b89d5d;background:#fff8e8;border-radius:14px;">
                <div style="font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:#8b6a20;font-weight:800;margin-bottom:6px;">導師的話</div>
                <div style="font-size:13px;line-height:1.7;color:#374151;">{teacher_quote}</div>
            </div>
            '''
        items_html += f"""
        <article class="item">
            <div class="meta">
                <span class="tag">{'置頂' if r[3] else '公告'}</span>
                <span>{html.escape(r[4] or 'system')}</span>
                <span>{html.escape(r[8] or '')}</span>
            </div>
            <h3>{html.escape(r[1])}</h3>
            <p>{html.escape(r[2]).replace(chr(10), '<br>')}</p>
            {teacher_quote_html}
            {img_html}
            {delete_html}
        </article>
        """
    form_html = ""
    if is_admin:
        form_html = f"""
            <div class="card">
                <h2>新增公告</h2>
                <form action="/announcements" method="post" enctype="multipart/form-data">
                    {csrf_html}
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
                    <label style="margin-top:12px;">導師的話</label>
                    <textarea name="teacher_quote" rows="4" placeholder="例如：今日辛苦大家，繼續加油！"></textarea>
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
            .quote {{ margin-top: 12px; padding: 12px 14px; border-left: 4px solid #b89d5d; background: #fff8e8; border-radius: 14px; }}
            .quote .label {{ font-size: 11px; letter-spacing: .16em; text-transform: uppercase; color: #8b6a20; font-weight: 800; margin-bottom: 6px; }}
            .quote .text {{ font-size: 13px; line-height: 1.7; color: #374151; }}
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


@app.post("/announcements")
async def announcements_create(
    request: Request,
    title: str = Form(...),
    body: str = Form(...),
    teacher_quote: str = Form(""),
    pinned: str = Form("0"),
    image: Optional[UploadFile] = File(None),
    user: tuple = Depends(require_roles("admin")),
):
    title = title.strip()
    body = body.strip()
    teacher_quote = teacher_quote.strip()
    if not title or not body:
        return HTMLResponse(_render_announcements_page(request, "標題同內容不可留空。"), status_code=400)

    image_filename = ""
    image_mime = ""
    image_blob = None
    if image and getattr(image, "filename", ""):
        image_filename = image.filename or ""
        image_mime = image.content_type or "image/png"
        image_blob = await image.read()
        if not image_blob:
            image_blob = None

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO announcements (title, body, pinned, created_by, image_filename, image_mime, image_blob, teacher_quote)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            title,
            body,
            1 if str(pinned).strip() in {"1", "true", "yes", "on"} else 0,
            _current_display_name(request) or "system",
            image_filename,
            image_mime,
            image_blob,
            teacher_quote,
        ),
    )
    conn.commit()
    conn.close()
    _audit_action_request(
        request,
        "announcement_create",
        target_type="announcement",
        target_id=title,
        actor=user,
        after={"title": title, "pinned": pinned, "teacher_quote": teacher_quote},
    )
    return RedirectResponse("/announcements", status_code=303)


@app.get("/admin/audit-logs", response_class=HTMLResponse)
async def admin_audit_logs(
    request: Request,
    action: str = Query(default=""),
    actor: str = Query(default=""),
    page: int = Query(default=1, ge=1, le=5000),
    user: tuple = Depends(require_roles("admin")),
):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    filters = []
    params = []
    if action.strip():
        filters.append("action LIKE ?")
        params.append(f"%{action.strip()}%")
    if actor.strip():
        filters.append("actor_username LIKE ?")
        params.append(f"%{actor.strip()}%")
    where_sql = f"WHERE {' AND '.join(filters)}" if filters else ""
    page_size = 50
    offset = (page - 1) * page_size
    cursor.execute(f"SELECT COUNT(*) FROM audit_logs {where_sql}", params)
    total = cursor.fetchone()[0] or 0
    cursor.execute(
        f"""
        SELECT event_id, created_at_utc, request_id, actor_username, normalized_role, action, target_type, target_id, route, http_method, result, source_ip, user_agent
        FROM audit_logs
        {where_sql}
        ORDER BY id DESC
        LIMIT ? OFFSET ?
        """,
        params + [page_size, offset],
    )
    rows = cursor.fetchall()
    conn.close()
    row_html = "".join(
        f"<tr><td>{html.escape(r[1])}</td><td>{html.escape(r[3] or '')}</td><td>{html.escape(r[4] or '')}</td><td>{html.escape(r[5])}</td><td>{html.escape(r[6] or '')}</td><td>{html.escape(r[7] or '')}</td><td>{html.escape(r[10])}</td><td>{html.escape(r[8])}</td></tr>"
        for r in rows
    )
    total_pages = max(1, (total + page_size - 1) // page_size)
    nav = f"<div class='muted'>第 {page} / {total_pages} 頁，共 {total} 筆</div>"
    return HTMLResponse(
        f"""
        <html lang="zh-HK">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>{APP_NAME} - Audit Log</title>
            <style>
                body {{ margin:0; font-family:-apple-system,BlinkMacSystemFont,"PingFang HK","Noto Sans TC",sans-serif; background:#f5f1e8; color:#111; padding:22px; }}
                .shell {{ max-width: 1280px; margin: 0 auto; }}
                .topbar, .card {{ background:#fff; border:1px solid #e5e7eb; border-radius:20px; padding:18px; margin-bottom:16px; }}
                table {{ width:100%; border-collapse:collapse; }}
                th, td {{ padding:10px 8px; border-bottom:1px solid #e5e7eb; text-align:left; vertical-align:top; }}
                th {{ font-size:12px; color:#6b7280; text-transform:uppercase; letter-spacing:.08em; }}
                .filters {{ display:flex; gap:10px; flex-wrap:wrap; margin-bottom:12px; }}
                input {{ padding:10px 12px; border:1px solid #d1d5db; border-radius:10px; }}
                a {{ color:#111; text-decoration:none; }}
            </style>
        </head>
        <body>
            <div class="shell">
                <div class="topbar">
                    <h1 style="margin:0;">Audit Log</h1>
                    <div class="muted">只讀審計紀錄，無修改 / 刪除入口。</div>
                    <div style="margin-top:10px;"><a href="/admin/accounts">返回帳戶管理</a></div>
                </div>
                <div class="card">
                    <form class="filters" method="get">
                        <input name="action" value="{html.escape(action)}" placeholder="action filter">
                        <input name="actor" value="{html.escape(actor)}" placeholder="actor filter">
                        <input name="page" type="number" min="1" value="{page}" style="max-width:120px;">
                        <button type="submit">篩選</button>
                    </form>
                    {nav}
                    <table>
                        <thead><tr><th>UTC</th><th>Actor</th><th>Role</th><th>Action</th><th>Target</th><th>Result</th><th>Route</th><th>Method</th></tr></thead>
                        <tbody>{row_html or '<tr><td colspan="8">查無資料</td></tr>'}</tbody>
                    </table>
                </div>
            </div>
        </body>
        </html>
        """
    )


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
        _audit_action_request(request, "account_create", target_type="account", target_id=username, actor=_current_user_record(request), after={"username": username, "display_name": display_name, "role": role, "is_active": 1})
    except sqlite3.IntegrityError:
        notice = "帳戶名稱已存在"
    conn.close()
    return HTMLResponse(_render_accounts_page(request, notice))


@app.post("/admin/accounts/{user_id}/toggle")
async def admin_accounts_toggle(request: Request, user_id: int):
    _require_admin(request)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, display_name, role, is_active FROM app_users WHERE id=?", (user_id,))
    before_row = cursor.fetchone()
    cursor.execute("UPDATE app_users SET is_active = CASE WHEN is_active=1 THEN 0 ELSE 1 END, updated_at=CURRENT_TIMESTAMP WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    _audit_action_request(request, "account_toggle", target_type="account", target_id=str(user_id), actor=_current_user_record(request), before=before_row)
    return RedirectResponse("/admin/accounts", status_code=303)


@app.post("/admin/accounts/{user_id}/reset-password")
async def admin_accounts_reset_password(request: Request, user_id: int, password: str = Form(...)):
    _require_admin(request)
    password = password.strip()
    if not password:
        return HTMLResponse(_render_accounts_page(request, "密碼不可留空"))
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, display_name, role, is_active FROM app_users WHERE id=?", (user_id,))
    before_row = cursor.fetchone()
    cursor.execute(
        "UPDATE app_users SET password=?, failed_attempts=0, locked_until=NULL, password_updated_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE id=?",
        (_hash_password(password), user_id),
    )
    conn.commit()
    conn.close()
    _audit_action_request(request, "password_reset", target_type="account", target_id=str(user_id), actor=_current_user_record(request), before=before_row)
    return RedirectResponse("/admin/accounts", status_code=303)


@app.get("/invoice", response_class=HTMLResponse)
async def invoice_home(request: Request, username: str = Depends(_require_admin_username)):
    today = datetime.now().strftime("%Y年%m月%d日")
    logo_html = '<div style="text-align:center; margin-bottom:40px;"><img src="/logo.png" style="max-width:220px; background:white; padding:10px; border-radius:4px;"></div>' if (BASE_DIR / "logo.png").exists() else ""
    csrf_html = _csrf_input_html(request)
    csrf_script = _csrf_fetch_script(request)

    recent_rows = []
    preset_rows = []
    common_client_rows = []
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT doc_no, doc_type, client, total_amount FROM records ORDER BY created_at DESC LIMIT 5")
            recent_rows = cursor.fetchall()
        except sqlite3.OperationalError as exc:
            if not _is_sqlite_locked_error(exc):
                raise
        try:
            cursor.execute("SELECT id, name, updated_at FROM form_presets ORDER BY updated_at DESC, id DESC")
            preset_rows = cursor.fetchall()
        except sqlite3.OperationalError as exc:
            if not _is_sqlite_locked_error(exc):
                raise
        try:
            cursor.execute("SELECT id, name, client_name, project_name, doc_type, category, notes, updated_at FROM common_clients ORDER BY updated_at DESC, id DESC")
            common_client_rows = cursor.fetchall()
        except sqlite3.OperationalError as exc:
            if not _is_sqlite_locked_error(exc):
                raise
        conn.close()
    except sqlite3.OperationalError as exc:
        if not _is_sqlite_locked_error(exc):
            raise
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
            {csrf_script}
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

                function defaultQuotationRemark() {{
                    return '「客戶名稱」簽回報價文件以確認服務提供。';
                }}

                function syncDocTypeDefaultRemarks() {{
                    const docTypeSelect = document.querySelector('select[name="doc_type"]');
                    const remarksField = document.querySelector('[name="custom_remarks"]');
                    if (!docTypeSelect || !remarksField) return;
                    const current = remarksField.value.trim();
                    const defaultRemark = defaultQuotationRemark();
                    if (docTypeSelect.value === '報價單') {{
                        if (!current) {{
                            remarksField.value = defaultRemark;
                        }}
                    }} else if (current === defaultRemark) {{
                        remarksField.value = '';
                    }}
                }}

                function bindAutosave() {{
                    const form = document.querySelector('form[action="/generate"]');
                    form.addEventListener('input', saveDraft);
                    form.addEventListener('change', saveDraft);
                    const docTypeSelect = document.querySelector('select[name="doc_type"]');
                    if (docTypeSelect) {{
                        docTypeSelect.addEventListener('change', () => {{
                            syncDocTypeDefaultRemarks();
                            saveDraft();
                        }});
                    }}
                    document.getElementById('preset_name').addEventListener('input', saveDraft);
                    document.getElementById('preset_select').addEventListener('change', saveDraft);
                    document.getElementById('common_client_name').addEventListener('input', saveDraft);
                    const selectedIdField = document.getElementById('common_client_selected_id');
                    if (selectedIdField) selectedIdField.addEventListener('change', saveDraft);
                }}

                document.addEventListener('DOMContentLoaded', () => {{
                    restoreDraft();
                    syncDocTypeDefaultRemarks();
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
                            {csrf_html}
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
                            <a href="/invoice/scrc"><strong>性罪行查核信</strong><span>中文姓名同身份證號碼一鍵出信</span></a>
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
    rows = []
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, client_name, project_name, doc_type, category, notes, updated_at FROM common_clients ORDER BY updated_at DESC, id DESC")
        rows = cursor.fetchall()
        conn.close()
        rows = _unique_common_client_rows(rows)
    except sqlite3.OperationalError as exc:
        if _is_sqlite_locked_error(exc):
            notice = notice or "資料庫忙緊中，常用客戶暫時未能載入，請稍後再試。"
            rows = []
        else:
            raise
    csrf_html = _csrf_input_html(request)
    csrf_script = _csrf_fetch_script(request)
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
                                    {csrf_html}
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
        {csrf_script}
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
                    {csrf_html}
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
    matched_id = None
    before_row = None
    try:
        conn = _bootstrap_sqlite_connect(DB_PATH)
        cursor = conn.cursor()
        canonical = _normalize_common_client_name(name)
        cursor.execute("SELECT id, name FROM common_clients")
        for existing_id, existing_name in cursor.fetchall():
            if _normalize_common_client_name(existing_name) == canonical:
                matched_id = existing_id
                break
        if matched_id:
            cursor.execute("SELECT id, name, client_name, project_name, doc_type, category, notes FROM common_clients WHERE id=?", (matched_id,))
            before_row = cursor.fetchone()
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
    except sqlite3.IntegrityError:
        try:
            conn = _bootstrap_sqlite_connect(DB_PATH)
            cursor = conn.cursor()
            canonical = _normalize_common_client_name(name)
            cursor.execute("SELECT id, name, client_name, project_name, doc_type, category, notes FROM common_clients")
            for existing_id, existing_name, *_ in cursor.fetchall():
                if _normalize_common_client_name(existing_name) == canonical:
                    matched_id = existing_id
                    cursor.execute(
                        "UPDATE common_clients SET client_name=?, project_name=?, doc_type=?, category=?, notes=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                        (client_name, project_name.strip(), doc_type.strip(), category.strip(), notes.strip(), matched_id),
                    )
                    conn.commit()
                    conn.close()
                    break
            else:
                conn.close()
                return _html_error_page("常用客戶儲存失敗", "名稱已存在，請改一個名稱再儲存。", "/invoice/clients")
        except Exception:
            return _html_error_page("常用客戶儲存失敗", "資料儲存時出現錯誤，請稍後再試。", "/invoice/clients")
    except sqlite3.OperationalError as exc:
        if _is_sqlite_locked_error(exc):
            return HTMLResponse(_render_common_clients_page(request, "資料庫忙緊中，請稍後再儲存常用客戶。"), status_code=503)
        return _html_error_page("常用客戶儲存失敗", f"資料庫發生錯誤：{exc}", "/invoice/clients")
    except Exception as exc:
        return _html_error_page("常用客戶儲存失敗", f"資料儲存時出現錯誤：{exc}", "/invoice/clients")
    if matched_id:
        _audit_action_request(request, "common_client_update", target_type="common_client", target_id=str(matched_id), actor=_current_user_record(request), before=before_row, after={"name": name, "client_name": client_name, "project_name": project_name.strip(), "doc_type": doc_type.strip(), "category": category.strip(), "notes": notes.strip()})
    else:
        _audit_action_request(request, "common_client_create", target_type="common_client", target_id=name, actor=_current_user_record(request), after={"name": name, "client_name": client_name, "project_name": project_name.strip(), "doc_type": doc_type.strip(), "category": category.strip(), "notes": notes.strip()})
    return RedirectResponse("/invoice/clients", status_code=303)


@app.post("/invoice/clients/{client_key}/delete")
async def invoice_clients_delete(request: Request, client_key: str, username: str = Depends(_require_admin_username)):
    before_row = None
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, client_name, project_name, doc_type, category, notes FROM common_clients WHERE id=? OR name=?", (client_key, client_key))
    before_row = cursor.fetchone()
    conn.close()
    _delete_common_client_by_key(client_key)
    _audit_action_request(request, "common_client_delete", target_type="common_client", target_id=str(client_key), actor=_current_user_record(request), before=before_row)
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


def _build_scrc_pdf_html(chinese_name: str, id_number: str = "", issue_date: Optional[datetime] = None, with_sign: bool = True):
    issue_date = issue_date or datetime.now()
    logo_src = f"file://{(BASE_DIR / 'logo.png').as_posix()}"
    sig_src = f"file://{(BASE_DIR / 'signature.png').as_posix()}"
    stamp_src = f"file://{(BASE_DIR / 'stamp.png').as_posix()}"
    issue_date_text = _cn_date_text(issue_date)
    name_block = chinese_name.strip()
    id_block = id_number.strip()
    # The generated document is intentionally locked to the Chinese name only.
    display_name = name_block

    signature_html = ""
    if with_sign:
        signature_html = f"""
        <div class="sign-name">廖成達校長</div>
        <img class="sig-img" src="{sig_src}" alt="signature">
        <img class="stamp-img" src="{stamp_src}" alt="stamp">
        """

    return f"""
<!DOCTYPE html>
<html lang="zh-HK">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>性罪行查核證明書</title>
<style>
  @page {{
    size: A4;
    margin: 0;
  }}
  html, body {{
    margin: 0;
    padding: 0;
    background: #fff;
    color: #111;
    font-family: "PingFang HK","PingFang TC","Microsoft JhengHei","Noto Sans TC",Arial,sans-serif;
  }}
  .page {{
    width: 210mm;
    min-height: 297mm;
    box-sizing: border-box;
    padding: 8mm 10mm 8mm 10mm;
  }}
  .outer {{
    position: relative;
    min-height: 240mm;
    border: 1px solid #111;
    padding: 9mm 10mm 9mm 10mm;
    box-sizing: border-box;
  }}
  .topline {{
    font-size: 12pt;
    line-height: 1.4;
    margin-bottom: 10mm;
  }}
  .title {{
    text-align: center;
    line-height: 1.35;
    margin-bottom: 7mm;
  }}
  .title-main {{
    display: inline-block;
    font-size: 13pt;
    border-bottom: 1px solid #111;
    padding: 0 8px 1px;
  }}
  .title-sub {{
    font-size: 16pt;
    margin-top: 2px;
  }}
  .para {{
    font-size: 12pt;
    line-height: 1.45;
    text-align: left;
    margin: 0 0 6mm;
    padding-left: 2mm;
  }}
  .field-area {{
    width: 100%;
    max-width: 170mm;
    margin: 0 auto;
  }}
  .row {{
    display: grid;
    grid-template-columns: 95mm 1fr;
    align-items: end;
    column-gap: 7mm;
    margin-bottom: 4.5mm;
  }}
  .label {{
    font-size: 12pt;
    font-weight: 700;
    white-space: nowrap;
  }}
  .value {{
    font-size: 12pt;
    border-bottom: 1px solid #111;
    min-height: 5.5mm;
    padding-left: 2mm;
    display: flex;
    align-items: end;
  }}
  .category-label {{
    font-size: 12pt;
    font-weight: 700;
    margin-bottom: 4mm;
  }}
  .choices {{
    display: flex;
    justify-content: space-between;
    gap: 6mm;
    font-size: 11.5pt;
    margin-bottom: 4.5mm;
    padding-left: 1mm;
  }}
  .choice {{
    display: inline-flex;
    align-items: center;
    gap: 1mm;
    white-space: nowrap;
  }}
  .circle {{
    font-size: 16pt;
    line-height: 1;
    display: inline-block;
    width: 6mm;
    text-align: center;
  }}
  .selected .circle {{
    font-size: 18pt;
    font-weight: 700;
  }}
  .para2 {{
    font-size: 9.6pt;
    line-height: 1.35;
    text-align: left;
    width: 140mm;
    max-width: 140mm;
    margin: 0 0 3.5mm 0;
    padding-left: 0;
    transform: translateX(-4mm);
  }}
  .instruction {{
    font-size: 8.8pt;
    line-height: 1.3;
    text-align: left;
    width: 140mm;
    max-width: 140mm;
    margin: 0 0 2.5mm 0;
    padding-left: 0;
    transform: translateX(-4mm);
  }}
  .heads {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    font-size: 12pt;
    font-weight: 700;
    width: 140mm;
    margin: 0 0 2mm 0;
    transform: translateX(-4mm);
  }}
  .heads div {{
    text-align: left;
    padding-left: 2mm;
  }}
  .employer-table {{
    width: 100%;
    border-collapse: collapse;
    table-layout: fixed;
    font-size: 10pt;
  }}
  .employer-table td {{
    border: 1px solid #111;
    vertical-align: top;
    padding: 1.2mm 2mm;
  }}
  .left-col {{
    width: 64%;
  }}
  .left-col .cell-label {{
    width: 38%;
  }}
  .right-col {{
    width: 36%;
  }}
  .cell-grid {{
    width: 100%;
    border-collapse: collapse;
    table-layout: fixed;
  }}
  .cell-grid td {{
    border: 0;
    padding: 0;
    vertical-align: top;
    font-size: 10pt;
    line-height: 1.45;
  }}
  .cell-grid tr + tr td {{
    border-top: 1px solid #111;
  }}
  .cell-label {{
    width: 58%;
    padding: 1mm 1.2mm 1mm 0;
    white-space: nowrap;
  }}
  .cell-label.long {{
    white-space: normal;
    line-height: 1.35;
  }}
  .right-col .cell-label.long {{
    font-size: 9.4pt;
    line-height: 1.2;
  }}
  .cell-value {{
    padding: 1mm 0 1mm 0;
    min-height: 11mm;
  }}
  .addr-value {{
    line-height: 1.35;
  }}
  .sign-cell {{
    min-height: 28mm;
    padding-right: 0;
  }}
  .sign-box {{
    position: relative;
    width: 100%;
    min-height: 26mm;
    margin-top: 0;
  }}
  .sign-name {{
    position: absolute;
    left: -4mm;
    bottom: 4.8mm;
    font-size: 10pt;
    font-weight: 700;
    white-space: nowrap;
  }}
  .sig-img {{
    position: absolute;
    left: 27mm;
    bottom: 2.0mm;
    width: 14mm;
    height: auto;
    display: block;
    opacity: 0.95;
  }}
  .stamp-img {{
    position: absolute;
    left: 49mm;
    bottom: 2.0mm;
    width: 9.2mm;
    height: auto;
    display: block;
  }}
  .blank-space {{
    min-height: 16mm;
  }}
  .right-col .blank-space {{
    min-height: 24mm;
  }}
  .footer-notes {{
    margin-top: 3mm;
    font-size: 10pt;
    line-height: 1.5;
  }}
  .footer-notes .note-title {{
    margin-bottom: 1mm;
  }}
  .revision {{
    margin-top: 3mm;
    font-size: 11pt;
  }}
</style>
</head>
<body>
<div class="page">
  <div class="outer">
    <div class="topline">致性罪行定罪紀錄查核辦事處：</div>
    <div class="title">
      <div class="title-main">《性罪行定罪紀錄查核》</div>
      <div class="title-sub">僱主證明書</div>
    </div>
    <div class="para">本人／本機構茲證明以下申請人在本人／本機構的聘任下的日常工作將涉及或相當可能涉<br>及與兒童或精神上無行為能力人士有經常或定期接觸。</div>

    <div class="field-area">
      <div class="row">
        <div class="label">申請人姓名（須與身份證明文件相同）：</div>
        <div class="value">{html.escape(display_name)}</div>
      </div>
      <div class="row">
        <div class="label">申請人身份證明文件號碼：</div>
        <div class="value">{html.escape(id_block)}</div>
      </div>
      <div class="row">
        <div class="label">職位名稱：</div>
        <div class="value">導師</div>
      </div>
      <div>
        <div class="category-label">申請人類別（請選取其中一項）：</div>
        <div class="choices">
          <div class="choice"><span class="circle">○</span><span>準僱員</span></div>
          <div class="choice"><span class="circle">○</span><span>合約續期僱員</span></div>
          <div class="choice selected"><span class="circle">✓</span><span>準自僱人士</span></div>
          <div class="choice"><span class="circle">○</span><span>志願工作者</span></div>
        </div>
      </div>
    </div>

    <div class="para2">
      茲確認本人／本機構已經閱讀《性罪行定罪紀錄查核》機制的《僱主須知》，並完全明白<br>
      這項服務的條款及條件，以及僱主需要履行的責任，包括不得將申請人的查詢密碼、查核結果或<br>
      其他個人資料，透露予不直接參與聘任相關程序的人士，亦不得使用有關個人資料作遴選、招募<br>
      或聘用以外的任何其他用途。
    </div>

    <div class="instruction">
      機構僱主請填寫以下甲欄目；個人僱主請填寫乙欄目。<br>
      （只須填寫其中一欄。「個人僱主」選項不適用於「志願工作者」。）
    </div>

    <div class="heads">
      <div>甲、機構僱主適用</div>
      <div>乙、個人僱主適用</div>
    </div>

    <table class="employer-table">
      <tr>
        <td class="left-col" rowspan="4">
          <table class="cell-grid" style="height:100%;">
            <tr>
              <td class="cell-label">機構僱主名稱：</td>
              <td class="cell-value">{html.escape('狄易達軍團跳舞學校')}</td>
            </tr>
            <tr>
              <td class="cell-label">機構僱主地址：</td>
              <td class="cell-value addr-value">香港九龍紅磡鶴園街2G號<br>恒豐工業大廈1期<br>3樓C室</td>
            </tr>
            <tr>
              <td class="cell-label long">機構蓋印或發信人姓名、職位及簽署：</td>
              <td class="cell-value sign-cell">
                <div class="sign-box">
                  {signature_html}
                </div>
              </td>
            </tr>
            <tr>
              <td class="cell-label">日期：</td>
              <td class="cell-value">{html.escape(issue_date_text)}</td>
            </tr>
          </table>
        </td>
        <td class="right-col" rowspan="4">
          <table class="cell-grid" style="height:100%;">
            <tr>
              <td class="cell-label long">個人僱主姓名（須與身份證明文件相同）：</td>
              <td class="cell-value blank-space"></td>
            </tr>
            <tr>
              <td class="cell-label long">個人僱主身份證明文件號碼首英文字母及頭三<br>位數字（如A123 或 XY123）：</td>
              <td class="cell-value blank-space"></td>
            </tr>
            <tr>
              <td class="cell-label">個人僱主簽署：</td>
              <td class="cell-value blank-space"></td>
            </tr>
            <tr>
              <td class="cell-label">日期：</td>
              <td class="cell-value blank-space"></td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </div>

  <div class="footer-notes">
    <div class="note-title">註﹕</div>
    <div>1. &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;機構及個人僱主可按各自需要調整僱主證明書的格式，但必須涵蓋以上要求的所有資料，否則申請將不獲處理。</div>
    <div>2. &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;性罪行定罪紀錄查核辦事處在任何時候，均保留最終權利，決定申請人之僱主證明書是否合乎申請要求。</div>
  </div>
  <div class="revision">12/2025 修訂</div>
</div>
</body>
</html>
"""


_SCRC_DEFAULT_COORDS = {
    "page": {
        "width": 595.276,
        "height": 841.89,
        "origin": "bottom-left",
        "base_pdf": str(SCRC_BASE_PDF_PATH),
    },
    "fields": {
        "applicant_name": {"x": 314.0, "y": 633.5, "fontSize": 10.4},
        "document_number": {"x": 314.0, "y": 606.5, "fontSize": 10.0},
        "position": {"x": 314.0, "y": 579.5, "fontSize": 10.0},
        "employment_type_tick": {"x": 286.0, "y": 536.0, "size": 7.6},
        "organisation_name": {"x": 146.0, "y": 351.8, "fontSize": 10.5},
        "organisation_address": {"x": 146.0, "y": 294.3, "width": 132.0, "lineHeight": 12.0, "fontSize": 9.6, "maxLines": 3},
        "signatory": {"x": 45.0, "y": 204.0, "fontSize": 10.0},
        "signature": {"x": 102.0, "y": 157.5, "width": 36.0, "height": 24.16},
        "stamp": {"x": 217.0, "y": 174.0, "width": 20.0, "height": 17.79},
        "date": {"x": 170.0, "y": 139.0, "fontSize": 10.0},
    },
    "applicant_type_marks": {
        "employee": {"x": 85.0, "y": 545.0},
        "contract_renewal": {"x": 176.0, "y": 545.0},
        "self_employed": {"x": 288.5, "y": 545.0},
        "volunteer": {"x": 395.0, "y": 545.0},
    },
}


def _load_scrc_overlay_coordinates():
    if SCRC_COORDINATE_MAP_PATH.exists():
        try:
            data = json.loads(SCRC_COORDINATE_MAP_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict) and data.get("fields"):
                return data
        except Exception:
            pass
    return _SCRC_DEFAULT_COORDS


def _scrc_font_name():
    if not REPORTLAB_AVAILABLE:
        return None
    candidates = [
        (FONT_DIR / "NotoSansTC-wght.ttf", None),
        (Path("/System/Library/Fonts/Supplemental/Songti.ttc"), 7),  # Songti TC Regular
        (Path("/System/Library/Fonts/Supplemental/Songti.ttc"), 5),  # Songti TC Light fallback if needed
    ]
    for idx, (path, subfont_index) in enumerate(candidates):
        if not path.exists():
            continue
        try:
            font_name = f"SCRCChinese_{idx}"
            kwargs = {"subfontIndex": subfont_index} if subfont_index is not None else {}
            pdfmetrics.registerFont(TTFont(font_name, str(path), **kwargs))
            return font_name
        except Exception:
            continue
    return None


def _scrc_text_block(canvas_obj, font_name: str, x: float, y: float, text: str, font_size: float, leading: Optional[float] = None):
    if not text:
        return
    canvas_obj.setFont(font_name, font_size)
    text_obj = canvas_obj.beginText()
    text_obj.setTextOrigin(x, y)
    text_obj.setLeading(leading or (font_size * 1.28))
    for line in str(text).splitlines():
        text_obj.textLine(line)
    canvas_obj.drawText(text_obj)


def _scrc_validate_font_rendering(font_name: str):
    if not font_name or not REPORTLAB_AVAILABLE:
        raise RuntimeError("SCRC font not available")
    required_texts = [
        "狄易達軍團跳舞學校",
        "香港九龍紅磡鶴園街2G號",
        "恒豐工業大廈1期3樓C室",
        "廖成達校長",
        "導師",
        "二零二六年八月二日",
    ]
    with tempfile.TemporaryDirectory(prefix="docmagic-scrc-fontcheck-") as tmpdir:
        tmp_pdf = Path(tmpdir) / "fontcheck.pdf"
        buf = io.BytesIO()
        c = canvas.Canvas(buf, pagesize=(595.276, 841.89))
        c.setFont(font_name, 12)
        y = 780
        for text in required_texts:
            c.drawString(40, y, text)
            y -= 26
        c.save()
        tmp_pdf.write_bytes(buf.getvalue())
        try:
            result = subprocess.run(["pdftotext", str(tmp_pdf), "-"], capture_output=True, text=True, timeout=20)
        except Exception as exc:
            raise RuntimeError(f"SCRC font validation failed: {exc}") from exc
        if result.returncode != 0:
            raise RuntimeError((result.stderr or result.stdout or "pdftotext validation failed").strip())
        extracted = result.stdout or ""
        for text in required_texts:
            if text not in extracted:
                raise RuntimeError(f"SCRC font validation missing text: {text}")


def _scrc_draw_tick(canvas_obj, x: float, y: float, size: float = 7.6):
    canvas_obj.saveState()
    canvas_obj.setLineCap(1)
    canvas_obj.setLineJoin(1)
    canvas_obj.setStrokeColorRGB(0, 0, 0)
    canvas_obj.setLineWidth(1.05)
    # Small check mark centred in the selected circle.
    canvas_obj.line(x - size * 0.45, y + size * 0.02, x - size * 0.12, y - size * 0.34)
    canvas_obj.line(x - size * 0.12, y - size * 0.34, x + size * 0.48, y + size * 0.32)
    canvas_obj.restoreState()


def _scrc_trimmed_image_reader(image_path: Path):
    with Image.open(image_path) as src:
        rgba = src.convert("RGBA")
        bbox = rgba.getchannel("A").getbbox()
        if bbox:
            rgba = rgba.crop(bbox)
        buf = io.BytesIO()
        rgba.save(buf, format="PNG")
    buf.seek(0)
    return ImageReader(buf)


def _scrc_build_overlay_pdf(
    chinese_name: str,
    id_number: str = "",
    issue_date: Optional[datetime] = None,
    with_sign: bool = True,
    position: str = "導師",
    applicant_type: str = "準自僱人士",
    signatory: str = SCRC_SIGNATORY_DEFAULT,
    organisation_name: str = SCRC_ORG_NAME,
    organisation_address_lines: Optional[List[str]] = None,
):
    if not REPORTLAB_AVAILABLE:
        raise RuntimeError("ReportLab unavailable for SCRC overlay rendering")
    issue_date = issue_date or datetime.now()
    coords = _load_scrc_overlay_coordinates()
    page = coords.get("page", {})
    fields = coords.get("fields", {})
    marks = coords.get("applicant_type_marks", {})
    page_w = float(page.get("width", 595.276))
    page_h = float(page.get("height", 841.89))
    font_name = _scrc_font_name() or "Helvetica"

    applicant_type_key = {
        "準僱員": "employee",
        "employee": "employee",
        "合同續期僱員": "contract_renewal",
        "合約續期僱員": "contract_renewal",
        "contract_renewal": "contract_renewal",
        "準自僱人士": "self_employed",
        "self_employed": "self_employed",
        "志願工作者": "volunteer",
        "volunteer": "volunteer",
    }.get((applicant_type or "").strip(), "self_employed")

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(page_w, page_h))
    c.setAuthor("OpenClaw")
    c.setTitle("SCRC 僱主證明書")
    c.setSubject("SCRC employer proof overlay")
    c.setCreator("DocMagic SCRC overlay generator")
    c.setFillColorRGB(0, 0, 0)
    c.setStrokeColorRGB(0, 0, 0)

    _scrc_text_block(c, font_name, fields["applicant_name"]["x"], fields["applicant_name"]["y"], chinese_name.strip(), fields["applicant_name"]["fontSize"])
    _scrc_text_block(c, font_name, fields["document_number"]["x"], fields["document_number"]["y"], id_number.strip(), fields["document_number"]["fontSize"])
    _scrc_text_block(c, font_name, fields["position"]["x"], fields["position"]["y"], position.strip() or "導師", fields["position"]["fontSize"])

    selected_mark = marks.get(applicant_type_key) or marks.get("self_employed")
    if selected_mark:
        _scrc_draw_tick(c, float(selected_mark["x"]), float(selected_mark["y"]), float(fields["employment_type_tick"].get("size", 7.6)))

    _scrc_text_block(c, font_name, fields["organisation_name"]["x"], fields["organisation_name"]["y"], organisation_name.strip() or SCRC_ORG_NAME, fields["organisation_name"]["fontSize"])
    org_lines = organisation_address_lines or SCRC_ORG_ADDRESS_LINES
    addr_cfg = fields["organisation_address"]
    addr_x = float(addr_cfg["x"])
    addr_y = float(addr_cfg["y"])
    addr_font_size = float(addr_cfg.get("fontSize", 10.9))
    addr_leading = float(addr_cfg.get("lineHeight", addr_font_size * 1.2))
    _scrc_text_block(c, font_name, addr_x, addr_y, "\n".join(org_lines[: int(addr_cfg.get("maxLines", 3))]), addr_font_size, addr_leading)

    _scrc_text_block(c, font_name, fields["signatory"]["x"], fields["signatory"]["y"], signatory.strip() or SCRC_SIGNATORY_DEFAULT, fields["signatory"]["fontSize"])
    _scrc_text_block(c, font_name, fields["date"]["x"], fields["date"]["y"], _cn_date_text(issue_date), fields["date"]["fontSize"])

    if with_sign:
        sig_cfg = fields["signature"]
        stamp_cfg = fields["stamp"]
        if SCRC_SIGNATURE_PNG.exists():
            sig_reader = _scrc_trimmed_image_reader(SCRC_SIGNATURE_PNG)
            c.drawImage(
                sig_reader,
                float(sig_cfg["x"]),
                float(sig_cfg["y"]),
                width=float(sig_cfg["width"]) * 3.0,
                height=float(sig_cfg["height"]) * 3.0,
                preserveAspectRatio=True,
                mask="auto",
            )
        if SCRC_STAMP_PNG.exists():
            stamp_reader = _scrc_trimmed_image_reader(SCRC_STAMP_PNG)
            c.drawImage(
                stamp_reader,
                float(stamp_cfg["x"]),
                float(stamp_cfg["y"]),
                width=float(stamp_cfg["width"]) * 3.0,
                height=float(stamp_cfg["height"]) * 3.0,
                preserveAspectRatio=True,
                mask="auto",
            )

    c.save()
    return buf.getvalue()


def _merge_pdf_overlay(base_pdf_path: Path, overlay_pdf_bytes: bytes):
    if not PYPDF_AVAILABLE:
        raise RuntimeError("pypdf unavailable for SCRC PDF merge")
    base_reader = PdfReader(str(base_pdf_path))
    if not base_reader.pages:
        raise RuntimeError("SCRC base PDF has no pages")
    overlay_reader = PdfReader(io.BytesIO(overlay_pdf_bytes))
    if not overlay_reader.pages:
        raise RuntimeError("SCRC overlay PDF has no pages")
    base_page = base_reader.pages[0]
    base_page.merge_page(overlay_reader.pages[0])
    writer = PdfWriter()
    writer.add_page(base_page)
    try:
        if "/Annots" in writer.pages[0]:
            del writer.pages[0]["/Annots"]
    except Exception:
        pass
    if base_reader.metadata:
        try:
            writer.add_metadata({k: str(v) for k, v in base_reader.metadata.items() if v is not None})
        except Exception:
            pass
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def _generate_scrc_pdf(
    chinese_name: str,
    id_number: str = "",
    issue_date: Optional[datetime] = None,
    with_sign: bool = True,
    position: str = "導師",
    applicant_type: str = "準自僱人士",
    signatory: str = SCRC_SIGNATORY_DEFAULT,
    organisation_name: str = SCRC_ORG_NAME,
    organisation_address_lines: Optional[List[str]] = None,
):
    if not SCRC_BASE_PDF_PATH.exists():
        raise RuntimeError(f"SCRC base PDF not found: {SCRC_BASE_PDF_PATH}")
    overlay_pdf = _scrc_build_overlay_pdf(
        chinese_name=chinese_name,
        id_number=id_number,
        issue_date=issue_date,
        with_sign=with_sign,
        position=position,
        applicant_type=applicant_type,
        signatory=signatory,
        organisation_name=organisation_name,
        organisation_address_lines=organisation_address_lines,
    )
    return _merge_pdf_overlay(SCRC_BASE_PDF_PATH, overlay_pdf)


def _scrc_unique_filename() -> str:
    return f"SCRC_letter_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}_{secrets.token_hex(4)}.pdf"


def _render_scrc_preview_page(
    chinese_name: str,
    english_name: str,
    id_number: str,
    pdf_content: bytes,
    filename: str,
    position: str = "導師",
    applicant_type: str = "準自僱人士",
    signatory: str = SCRC_SIGNATORY_DEFAULT,
):
    pdf_b64 = base64.b64encode(pdf_content).decode("ascii")
    chinese_name_html = html.escape(chinese_name)
    id_number_html = html.escape(id_number)
    download_query = urlencode({
        "chinese_name": chinese_name,
        "id_number": id_number,
        "position": position,
        "applicant_type": applicant_type,
        "signatory": signatory,
    })
    return f"""
    <html lang="zh-HK">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>SCRC 預覽</title>
        <style>
            body {{
                margin: 0;
                font-family: -apple-system, BlinkMacSystemFont, "PingFang HK", "Noto Sans TC", sans-serif;
                background: #f4f1ea;
                color: #111;
            }}
            .topbar {{
                display: flex;
                gap: 12px;
                align-items: center;
                justify-content: space-between;
                padding: 14px 18px;
                background: #fff;
                border-bottom: 1px solid #e5e7eb;
                position: sticky;
                top: 0;
                z-index: 2;
            }}
            .meta {{
                font-size: 13px;
                color: #4b5563;
                line-height: 1.6;
            }}
            .btn {{
                display: inline-flex;
                align-items: center;
                justify-content: center;
                padding: 10px 14px;
                border-radius: 12px;
                text-decoration: none;
                font-weight: 800;
                border: 1px solid #d1d5db;
                background: #fff;
                color: #111;
                cursor: pointer;
            }}
            .frame-wrap {{
                padding: 18px;
            }}
            iframe {{
                width: 100%;
                height: calc(100vh - 110px);
                border: 1px solid #d1d5db;
                border-radius: 16px;
                background: #fff;
            }}
        </style>
    </head>
    <body>
        <div class="topbar">
            <div class="meta">
                <div><strong>SCRC 預覽</strong></div>
                <div>中文姓名：{chinese_name_html} ｜ 身份證：{id_number_html} ｜ 職位：{html.escape(position)} ｜ 類別：{html.escape(applicant_type)}</div>
            </div>
            <div style="display:flex; gap:10px; flex-wrap:wrap; align-items:center;">
                <a class="btn" href="/invoice/scrc/download?{download_query}" target="_blank" rel="noopener">下載 PDF</a>
                <a class="btn" href="/invoice/scrc">返回表單</a>
            </div>
        </div>
        <div class="frame-wrap">
            <iframe src="data:application/pdf;base64,{pdf_b64}" title="SCRC PDF Preview"></iframe>
        </div>
    </body>
    </html>
    """


def _render_scrc_page(request: Request, notice: str = ""):
    csrf_html = _csrf_input_html(request)
    notice_html = f'<div class="notice">{html.escape(notice)}</div>' if notice else ""
    today_text = _cn_date_text()
    download_script = """
        <script>
        (function () {
            const form = document.getElementById('scrc-form');
            const submitBtn = document.getElementById('scrc-submit');
            if (!form || !submitBtn) return;
            form.addEventListener('submit', async (event) => {
                event.preventDefault();
                submitBtn.disabled = true;
                const originalText = submitBtn.textContent;
                submitBtn.textContent = '處理中...';
                try {
                    const formData = new FormData(form);
                    const params = new URLSearchParams();
                    for (const [key, value] of formData.entries()) {
                        if (typeof value === 'string') {
                            params.append(key, value);
                        }
                    }
                    params.set('_ts', Date.now().toString());
                    const previewUrl = `/invoice/scrc/preview?${params.toString()}`;
                    const downloadUrl = `/invoice/scrc/download?${params.toString()}`;
                    window.open(previewUrl, '_blank', 'noopener');
                    const hiddenFrame = document.createElement('iframe');
                    hiddenFrame.style.display = 'none';
                    hiddenFrame.src = downloadUrl;
                    document.body.appendChild(hiddenFrame);
                    setTimeout(() => hiddenFrame.remove(), 60000);
                } catch (err) {
                    form.submit();
                } finally {
                    submitBtn.disabled = false;
                    submitBtn.textContent = originalText;
                }
            });
        })();
        </script>
    """
    return f"""
    <html lang="zh-HK">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{APP_NAME} - 性罪行查核信</title>
        <style>
            :root {{
                --bg: #f7f4ee;
                --paper: #ffffff;
                --ink: #111111;
                --muted: #5f646d;
                --line: rgba(17,17,17,.10);
                --accent: #b89d5d;
            }}
            * {{ box-sizing: border-box; }}
            body {{
                margin: 0;
                font-family: -apple-system, BlinkMacSystemFont, "PingFang HK", "Noto Sans TC", sans-serif;
                background:
                    radial-gradient(circle at top right, rgba(184,157,93,.14), transparent 22%),
                    linear-gradient(135deg, #faf7f0 0%, #efe8d8 100%);
                color: var(--ink);
                padding: 22px;
            }}
            .shell {{ max-width: 1080px; margin: 0 auto; }}
            .hero {{
                background: rgba(255,255,255,.9);
                border: 1px solid var(--line);
                border-radius: 28px;
                padding: 24px 28px;
                box-shadow: 0 18px 46px rgba(17,17,17,.06);
                margin-bottom: 18px;
            }}
            .hero-top {{
                display: flex;
                justify-content: space-between;
                gap: 16px;
                align-items: end;
                flex-wrap: wrap;
            }}
            h1 {{ margin: 0; font-size: 30px; letter-spacing: -0.03em; }}
            .hero p {{ margin: 8px 0 0; color: var(--muted); line-height: 1.7; }}
            .chips {{ display: flex; gap: 10px; flex-wrap: wrap; }}
            .chip {{
                display: inline-flex;
                align-items: center;
                border-radius: 999px;
                padding: 9px 14px;
                background: #fff8e8;
                color: #6b5730;
                font-size: 12px;
                font-weight: 800;
                border: 1px solid rgba(184,157,93,.32);
            }}
            .grid {{
                display: grid;
                grid-template-columns: repeat(12, minmax(0, 1fr));
                gap: 18px;
            }}
            .card {{
                grid-column: span 8;
                background: rgba(255,255,255,.94);
                border: 1px solid var(--line);
                border-radius: 24px;
                padding: 24px;
                box-shadow: 0 16px 40px rgba(17,17,17,.05);
            }}
            .side {{
                grid-column: span 4;
                background: rgba(255,255,255,.94);
                border: 1px solid var(--line);
                border-radius: 24px;
                padding: 22px;
                box-shadow: 0 16px 40px rgba(17,17,17,.05);
            }}
            .section-title {{ font-size: 16px; font-weight: 800; margin: 0 0 16px; }}
            label {{
                display: block;
                margin: 14px 0 8px;
                color: #6b7280;
                font-size: 12px;
                letter-spacing: .08em;
                text-transform: uppercase;
            }}
            input, select {{
                width: 100%;
                border: 1px solid #d1d5db;
                border-radius: 14px;
                padding: 13px 14px;
                font-size: 15px;
                background: #fff;
                color: #111;
                outline: none;
            }}
            input:focus, select:focus {{
                border-color: rgba(184,157,93,.9);
                box-shadow: 0 0 0 3px rgba(184,157,93,.15);
            }}
            .notice {{
                margin-bottom: 14px;
                padding: 12px 14px;
                border-radius: 14px;
                background: #fff8e8;
                border: 1px solid rgba(184,157,93,.35);
                color: #6b5730;
            }}
            .hint {{
                color: var(--muted);
                font-size: 12px;
                line-height: 1.6;
                margin-top: 8px;
            }}
            .actions {{
                display: flex;
                gap: 10px;
                margin-top: 18px;
                flex-wrap: wrap;
            }}
            .actions a, .actions button {{
                display: inline-flex;
                align-items: center;
                justify-content: center;
                border-radius: 14px;
                padding: 12px 16px;
                text-decoration: none;
                font-size: 14px;
                font-weight: 800;
                border: 1px solid var(--line);
                cursor: pointer;
            }}
            .actions button {{
                background: linear-gradient(135deg, #b89d5d, #d8bf88);
                color: #111;
                border-color: rgba(184,157,93,.65);
            }}
            .actions a {{
                background: #fff;
                color: #111;
            }}
            .preview-box {{
                padding: 18px;
                border-radius: 18px;
                background: linear-gradient(180deg, #fff, #faf8f2);
                border: 1px solid var(--line);
                line-height: 1.8;
            }}
            .preview-box strong {{ display: block; margin-bottom: 10px; }}
            @media (max-width: 900px) {{
                .card, .side {{ grid-column: span 12; }}
            }}
            @media (max-width: 720px) {{
                body {{ padding: 14px; }}
                .hero, .card, .side {{ padding: 18px; border-radius: 20px; }}
            }}
        </style>
    </head>
    <body>
        <div class="shell">
        <div class="hero">
                <div class="hero-top">
                    <div>
                        <h1>性罪行查核證明信件</h1>
                        <p>只需填上中文姓名同身份證號碼（包括括號），系統會自動鎖定機構資料、職位名稱同查核類別。</p>
                    </div>
                    <div class="chips">
                        <span class="chip">Admin only</span>
                        <span class="chip">PDF 生成</span>
                        <span class="chip">範本固定格式</span>
                    </div>
                </div>
            </div>
            <div class="grid">
                <div class="card">
                    {notice_html}
                    <form id="scrc-form" action="/invoice/scrc/generate" method="post">
                        {csrf_html}
                        <label for="chinese_name">中文姓名</label>
                        <input id="chinese_name" name="chinese_name" type="text" placeholder="例如：黃小明" required>

                        <label for="id_number">身份證號碼（包括括號）</label>
                        <input id="id_number" name="id_number" type="text" placeholder="例如：A123456(7)" required>

                        <label for="position">職位名稱</label>
                        <input id="position" name="position" type="text" value="導師" required>

                        <label for="applicant_type">申請人類別</label>
                        <select id="applicant_type" name="applicant_type">
                            <option value="準僱員">準僱員</option>
                            <option value="合約續期僱員">合約續期僱員</option>
                            <option value="準自僱人士" selected>準自僱人士</option>
                            <option value="志願工作者">志願工作者</option>
                        </select>

                        <label for="signatory">發信人姓名及職位</label>
                        <input id="signatory" name="signatory" type="text" value="{html.escape(SCRC_SIGNATORY_DEFAULT, quote=True)}" required>

                        <div class="actions">
                            <button type="submit" id="scrc-submit">預覽 + 下載 PDF</button>
                            <a href="/invoice">返回發票系統</a>
                            <a href="/dashboard">返回主選單</a>
                        </div>
                    </form>
                    <div class="hint" style="margin-top:16px;">
                        生成後會同時開啟 PDF 預覽頁同下載檔案。請先確認姓名同證件號碼完全正確。
                    </div>
                </div>
                <div class="side">
                    <h3 class="section-title">範本重點</h3>
                    <div class="preview-box">
                        <strong>固定格式</strong>
                        <div>• 機構僱主名稱：狄易達軍團跳舞學校</div>
                        <div>• 職位名稱：可改</div>
                        <div>• 申請人類別：可改</div>
                        <div>• 發信人：可改</div>
                        <div>• 內文同抬頭固定，唔需要再輸入其他資料</div>
                        <div>• PDF 只需一頁</div>
                        <div style="margin-top:12px; color:#6b7280;">日期：{today_text}</div>
                    </div>
                </div>
            </div>
        </div>
        {download_script}
    </body>
    </html>
    """


@app.get("/invoice/scrc", response_class=HTMLResponse)
async def invoice_scrc_home(request: Request, username: str = Depends(_require_admin_username)):
    return HTMLResponse(
        _render_scrc_page(request),
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
        },
    )


@app.get("/invoice/scrc/preview", response_class=HTMLResponse)
async def invoice_scrc_preview(
    request: Request,
    chinese_name: str = Query(...),
    id_number: str = Query(...),
    position: str = Query("導師"),
    applicant_type: str = Query("準自僱人士"),
    signatory: str = Query(SCRC_SIGNATORY_DEFAULT),
    username: str = Depends(_require_admin_username),
):
    chinese_name = chinese_name.strip()
    id_number = re.sub(r"\s+", "", id_number.strip()).upper()
    if not chinese_name or not id_number:
        return HTMLResponse(_render_scrc_page(request, "中文姓名同身份證號碼不可留空。"), status_code=400)
    try:
        pdf_content = _generate_scrc_pdf(chinese_name, id_number, datetime.now(), with_sign=True, position=position, applicant_type=applicant_type, signatory=signatory)
    except Exception as exc:
        return HTMLResponse(_render_scrc_page(request, f"PDF 預覽失敗：{exc}"), status_code=500)
    filename = _scrc_unique_filename()
    return HTMLResponse(
        _render_scrc_preview_page(chinese_name, "", id_number, pdf_content, filename, position=position, applicant_type=applicant_type, signatory=signatory),
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
        },
    )


@app.get("/invoice/scrc/download")
async def invoice_scrc_download(
    request: Request,
    chinese_name: str = Query(...),
    id_number: str = Query(...),
    position: str = Query("導師"),
    applicant_type: str = Query("準自僱人士"),
    signatory: str = Query(SCRC_SIGNATORY_DEFAULT),
    username: str = Depends(_require_admin_username),
):
    chinese_name = chinese_name.strip()
    id_number = re.sub(r"\s+", "", id_number.strip()).upper()
    if not chinese_name or not id_number:
        return HTMLResponse(_render_scrc_page(request, "中文姓名同身份證號碼不可留空。"), status_code=400)
    try:
        pdf_content = _generate_scrc_pdf(chinese_name, id_number, datetime.now(), with_sign=True, position=position, applicant_type=applicant_type, signatory=signatory)
    except Exception as exc:
        return HTMLResponse(_render_scrc_page(request, f"PDF 下載失敗：{exc}"), status_code=500)
    filename = _scrc_unique_filename()
    return Response(
        content=pdf_content,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


@app.post("/invoice/scrc/generate")
async def invoice_scrc_generate(
    request: Request,
    chinese_name: str = Form(...),
    id_number: str = Form(...),
    position: str = Form("導師"),
    applicant_type: str = Form("準自僱人士"),
    signatory: str = Form(SCRC_SIGNATORY_DEFAULT),
    username: str = Depends(_require_admin_username),
):
    chinese_name = chinese_name.strip()
    id_number = re.sub(r"\s+", "", id_number.strip()).upper()
    if not chinese_name or not id_number:
        return HTMLResponse(_render_scrc_page(request, "中文姓名同身份證號碼不可留空。"), status_code=400)
    try:
        pdf_content = _generate_scrc_pdf(chinese_name, id_number, datetime.now(), with_sign=True, position=position, applicant_type=applicant_type, signatory=signatory)
    except Exception as exc:
        return HTMLResponse(_render_scrc_page(request, f"PDF 生成失敗：{exc}"), status_code=500)
    _audit_action_request(
        request,
        "scrc_generate",
        target_type="scrc_letter",
        target_id=datetime.now().strftime("%Y%m%d%H%M%S"),
        actor=_current_user_record(request),
        after={"name_len": len(chinese_name), "id_len": len(id_number), "position": position, "applicant_type": applicant_type, "fixed_fields": True},
    )
    filename = _scrc_unique_filename()
    return Response(
        content=pdf_content,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.get("/api/pantene-friends-dinner/{share_token}")
async def pantene_friends_dinner_detail(share_token: str, visitor_token: str = Query("", alias="visitorToken")):
    bundle = _pantene_meeting_bundle(share_token, visitor_token=visitor_token)
    if not bundle:
        return Response("Not Found", status_code=404)
    return bundle


@app.post("/api/pantene-friends-dinner")
async def pantene_friends_dinner_create(request: Request):
    payload = await _pantene_request_json(request)
    title = str(payload.get("title") or "").strip()
    meeting_date = str(payload.get("meetingDate") or payload.get("date") or "").strip()
    district = str(payload.get("district") or "").strip()
    budget = str(payload.get("budget") or "").strip()
    share_permission = _pantene_normalize_permission(payload.get("sharePermission") or payload.get("permission") or "vote")
    expires_at = str(payload.get("expiresAt") or "").strip()
    notes = str(payload.get("notes") or "").strip()
    created_by = str(payload.get("createdBy") or "").strip()
    candidates = _pantene_payload_candidates(payload)
    if not title or not meeting_date:
        return Response("標題同日期不可留空", status_code=400)
    if len(candidates) < 2 or len(candidates) > 6:
        return Response("候選餐廳數目要介乎 2 至 6 間", status_code=400)
    if expires_at and _pantene_parse_datetime(expires_at) is None:
        return Response("連結到期日格式不正確", status_code=400)
    token = secrets.token_urlsafe(18)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    cursor = conn.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
    except Exception:
        pass
    cursor.execute(
        """
        INSERT INTO pantene_meetings (token, title, meeting_date, district, budget, share_permission, expires_at, is_active, created_by, notes, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, CURRENT_TIMESTAMP)
        """,
        (token, title, meeting_date, district, budget, share_permission, expires_at or None, created_by, notes),
    )
    meeting_id = cursor.lastrowid
    for candidate in candidates:
        cursor.execute(
            """
            INSERT INTO pantene_meeting_candidates (token, meeting_id, restaurant_name, district, cuisine, note, sort_order, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (
                candidate["token"],
                meeting_id,
                candidate["restaurantName"],
                candidate["district"],
                candidate["cuisine"],
                candidate["note"],
                candidate["sortOrder"],
            ),
        )
    conn.commit()
    conn.close()
    bundle = _pantene_meeting_bundle(token)
    return {
        "token": token,
        "publicUrl": f"/pantene-foodie-journey/friends-dinner/{token}",
        "shareUrl": f"/pantene-foodie-journey/friends-dinner/{token}",
        "meeting": bundle["meeting"] if bundle else None,
    }


@app.post("/api/pantene-friends-dinner/{share_token}/status")
async def pantene_friends_dinner_status(request: Request, share_token: str):
    payload = await _pantene_request_json(request)
    is_active = payload.get("isActive")
    if is_active is None:
        is_active = payload.get("active")
    if isinstance(is_active, str):
        is_active = is_active.strip().lower() in {"1", "true", "yes", "on"}
    bundle = _pantene_meeting_bundle(share_token)
    if not bundle:
        return Response("Not Found", status_code=404)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE pantene_meetings SET is_active=?, updated_at=CURRENT_TIMESTAMP WHERE token=?",
        (1 if bool(is_active) else 0, share_token),
    )
    conn.commit()
    conn.close()
    return {"ok": True, "meeting": _pantene_meeting_bundle(share_token)["meeting"]}


@app.post("/api/pantene-friends-dinner/{share_token}/vote")
async def pantene_friends_dinner_vote(request: Request, share_token: str):
    payload = await _pantene_request_json(request)
    visitor_token = _pantene_request_visitor_token(request, payload)
    nickname = str(payload.get("nickname") or "").strip()
    candidate_token = str(payload.get("candidateToken") or payload.get("candidateId") or "").strip()
    vote_value = str(payload.get("vote") or payload.get("voteValue") or "").strip().lower()
    if vote_value not in {"want", "okay", "no"}:
        return Response("投票選項不正確", status_code=400)
    if not visitor_token:
        return Response("缺少訪客識別", status_code=400)
    if not nickname:
        return Response("暱稱不可留空", status_code=400)
    bundle = _pantene_meeting_bundle(share_token, visitor_token=visitor_token)
    if not bundle:
        return Response("Not Found", status_code=404)
    meeting = bundle["meeting"] or {}
    if not meeting.get("isActive"):
        return Response("此連結已停用", status_code=410)
    if _pantene_bundle_is_expired(bundle):
        return Response("此連結已過期", status_code=410)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id FROM pantene_meetings WHERE token=?",
        (share_token,),
    )
    meeting_row = cursor.fetchone()
    if not meeting_row:
        conn.close()
        return Response("Not Found", status_code=404)
    meeting_id = meeting_row[0]
    cursor.execute(
        "SELECT id, restaurant_name FROM pantene_meeting_candidates WHERE meeting_id=? AND token=?",
        (meeting_id, candidate_token),
    )
    candidate_row = cursor.fetchone()
    if not candidate_row:
        conn.close()
        return Response("未搵到候選餐廳", status_code=404)
    if _pantene_permission_level(meeting.get("sharePermission")) < 1:
        conn.close()
        return Response("此連結為只讀", status_code=403)
    cursor.execute(
        """
        INSERT INTO pantene_meeting_votes (meeting_id, candidate_id, visitor_token, nickname, vote_value, updated_at)
        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(meeting_id, candidate_id, visitor_token)
        DO UPDATE SET nickname=excluded.nickname, vote_value=excluded.vote_value, updated_at=CURRENT_TIMESTAMP
        """,
        (meeting_id, candidate_row[0], visitor_token, nickname, vote_value),
    )
    conn.commit()
    conn.close()
    return {"ok": True, "bundle": _pantene_meeting_bundle(share_token, visitor_token=visitor_token)}


@app.post("/api/pantene-friends-dinner/{share_token}/comment")
async def pantene_friends_dinner_comment(request: Request, share_token: str):
    payload = await _pantene_request_json(request)
    payload["targetType"] = "meeting"
    payload["targetToken"] = share_token
    return await pantene_comments_create(request, payload_override=payload)


@app.delete("/api/pantene-friends-dinner/{share_token}")
async def pantene_friends_dinner_disable(share_token: str):
    bundle = _pantene_meeting_bundle(share_token)
    if not bundle:
        return Response("Not Found", status_code=404)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE pantene_meetings SET is_active=0, updated_at=CURRENT_TIMESTAMP WHERE token=?",
        (share_token,),
    )
    conn.commit()
    conn.close()
    return {"ok": True, "meeting": _pantene_meeting_bundle(share_token)["meeting"]}


@app.get("/api/pantene-comments")
async def pantene_comments_detail(
    target_type: str = Query("meeting", alias="targetType"),
    target_token: str = Query("", alias="targetToken"),
    visitor_token: str = Query("", alias="visitorToken"),
):
    target_type = _pantene_comment_target_type(target_type)
    target_token = str(target_token or "").strip()
    if not target_token:
        return Response("Not Found", status_code=404)
    bundle = _pantene_comment_bundle(target_type, target_token, visitor_token=visitor_token)
    return {"targetType": target_type, "targetToken": target_token, **bundle}


@app.post("/api/pantene-comments")
async def pantene_comments_create(request: Request, payload_override: Optional[dict] = None):
    payload = payload_override if isinstance(payload_override, dict) else await _pantene_request_json(request)
    visitor_token = _pantene_request_visitor_token(request, payload)
    target_type = _pantene_comment_target_type(payload.get("targetType") or payload.get("target_type") or "meeting")
    target_token = str(payload.get("targetToken") or payload.get("target_token") or "").strip()
    nickname = str(payload.get("nickname") or "").strip()
    body = str(payload.get("body") or payload.get("comment") or "").strip()
    parent_comment_id = payload.get("parentCommentId") or payload.get("parent_comment_id") or None
    if not visitor_token:
        return Response("缺少訪客識別", status_code=400)
    ok, error = _pantene_comment_limit_ok(body)
    if not ok:
        return Response(error, status_code=400)
    if not nickname:
        return Response("暱稱不可留空", status_code=400)
    if not target_token:
        return Response("留言目標不可留空", status_code=400)
    if target_type == "meeting":
        bundle = _pantene_meeting_bundle(target_token, visitor_token=visitor_token)
        if not bundle:
            return Response("Not Found", status_code=404)
        meeting = bundle["meeting"] or {}
        if not meeting.get("isActive"):
            return Response("此連結已停用", status_code=410)
        if _pantene_bundle_is_expired(bundle):
            return Response("此連結已過期", status_code=410)
        if _pantene_permission_level(meeting.get("sharePermission")) < 2:
            return Response("此連結未開放留言", status_code=403)
    if not _pantene_comment_target_allowed(target_type, target_token):
        return Response("Not Found", status_code=404)
    moderation_status, moderation_reason = _pantene_comment_flag(body)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    cursor = conn.cursor()
    if _pantene_comment_rate_limited(conn, target_type, target_token, visitor_token):
        conn.close()
        return Response("提交太密，請稍後再試", status_code=429)
    if parent_comment_id:
        try:
            parent_comment_id = int(parent_comment_id)
        except Exception:
            parent_comment_id = None
    if parent_comment_id:
        cursor.execute(
            "SELECT target_type, target_token FROM pantene_comments WHERE id=?",
            (parent_comment_id,),
        )
        parent_row = cursor.fetchone()
        if not parent_row:
            conn.close()
            return Response("回覆對象不存在", status_code=404)
        if not target_token:
            target_type = parent_row[0]
            target_token = parent_row[1]
        if _pantene_comment_target_type(parent_row[0]) != target_type or parent_row[1] != target_token:
            conn.close()
            return Response("回覆對象不一致", status_code=400)
    cursor.execute(
        """
        INSERT INTO pantene_comments (
            target_type, target_token, parent_comment_id, visitor_token, nickname, body,
            moderation_status, hidden_reason, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """,
        (
            target_type,
            target_token,
            parent_comment_id,
            visitor_token,
            nickname,
            body,
            moderation_status,
            moderation_reason,
        ),
    )
    comment_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return {
        "ok": True,
        "status": moderation_status,
        "bundle": _pantene_comment_bundle(target_type, target_token, visitor_token=visitor_token),
        "commentId": comment_id,
    }


@app.post("/api/pantene-comments/{comment_id}/reaction")
async def pantene_comment_reaction(request: Request, comment_id: int):
    payload = await _pantene_request_json(request)
    visitor_token = _pantene_request_visitor_token(request, payload)
    emoji = str(payload.get("emoji") or "").strip()
    if not visitor_token:
        return Response("缺少訪客識別", status_code=400)
    if emoji and len(emoji) > 4:
        return Response("Emoji 不正確", status_code=400)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    cursor = conn.cursor()
    cursor.execute("SELECT target_type, target_token FROM pantene_comments WHERE id=?", (comment_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return Response("Not Found", status_code=404)
    if not emoji:
        cursor.execute("DELETE FROM pantene_comment_reactions WHERE comment_id=? AND visitor_token=?", (comment_id, visitor_token))
    else:
        cursor.execute(
            """
            INSERT INTO pantene_comment_reactions (comment_id, visitor_token, emoji, created_at, updated_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ON CONFLICT(comment_id, visitor_token)
            DO UPDATE SET emoji=excluded.emoji, updated_at=CURRENT_TIMESTAMP
            """,
            (comment_id, visitor_token, emoji),
        )
    conn.commit()
    conn.close()
    bundle = _pantene_comment_bundle(row[0], row[1], visitor_token=visitor_token)
    return {"ok": True, "bundle": bundle}


@app.post("/api/pantene-comments/{comment_id}/reply")
async def pantene_comment_reply(request: Request, comment_id: int):
    payload = await _pantene_request_json(request)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    cursor = conn.cursor()
    cursor.execute("SELECT target_type, target_token FROM pantene_comments WHERE id=?", (comment_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return Response("Not Found", status_code=404)
    payload["parentCommentId"] = comment_id
    payload["targetType"] = row[0]
    payload["targetToken"] = row[1]
    return await pantene_comments_create(request, payload_override=payload)


@app.post("/api/pantene-comments/{comment_id}/moderate")
async def pantene_comment_moderate(
    request: Request,
    comment_id: int,
    username: str = Depends(_require_admin_username),
):
    payload = await _pantene_request_json(request)
    moderation_status = str(payload.get("moderationStatus") or payload.get("status") or "visible").strip().lower()
    if moderation_status not in {"visible", "hidden", "pending"}:
        return Response("moderationStatus 不正確", status_code=400)
    reason = str(payload.get("reason") or "").strip()
    conn = sqlite3.connect(DB_PATH, timeout=30)
    cursor = conn.cursor()
    cursor.execute("SELECT target_type, target_token FROM pantene_comments WHERE id=?", (comment_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return Response("Not Found", status_code=404)
    if moderation_status == "hidden":
        cursor.execute(
            """
            UPDATE pantene_comments
            SET moderation_status=?, hidden_at=CURRENT_TIMESTAMP, hidden_by=?, hidden_reason=?, updated_at=CURRENT_TIMESTAMP
            WHERE id=?
            """,
            (moderation_status, username, reason, comment_id),
        )
    else:
        cursor.execute(
            """
            UPDATE pantene_comments
            SET moderation_status=?, hidden_at=NULL, hidden_by=NULL, hidden_reason=?, updated_at=CURRENT_TIMESTAMP
            WHERE id=?
            """,
            (moderation_status, reason, comment_id),
        )
    conn.commit()
    conn.close()
    return {"ok": True, "bundle": _pantene_comment_bundle(row[0], row[1], visitor_token="")}


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
    _audit_action_request(request, "announcement_create", target_type="announcement", target_id=title, actor=user, after={"title": title, "pinned": str(pinned) == "1", "created_by": user[1]})
    return RedirectResponse("/announcements", status_code=303)


@app.post("/announcements/{announcement_id}/delete")
async def announcements_delete(
    request: Request,
    announcement_id: int,
    user: tuple = Depends(require_roles("admin")),
):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, created_by, pinned, created_at FROM announcements WHERE id=?", (announcement_id,))
    before_row = cursor.fetchone()
    cursor.execute("DELETE FROM announcements WHERE id=?", (announcement_id,))
    conn.commit()
    conn.close()
    _audit_action_request(request, "announcement_delete", target_type="announcement", target_id=str(announcement_id), actor=user, before=before_row)
    return RedirectResponse("/announcements", status_code=303)


@app.post("/generate")
async def handle_generate(
    request: Request,
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
        _audit_action_request(request, "invoice_generate", target_type="record", target_id=doc_no, actor=_current_user_record(request), after={"doc_no": doc_no, "doc_type": doc_type, "total_amount": total_amount})

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
    _audit_action_request(request, "preset_update" if existing else "preset_create", target_type="preset", target_id=name, actor=_current_user_record(request), after={"name": name})
    return {"ok": True, "id": preset_id, "name": name}

@app.delete("/api/presets/{preset_id}")
async def delete_form_preset(request: Request, preset_id: int, username: str = Depends(_require_admin_username)):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, name FROM form_presets WHERE id=?", (preset_id,))
    before_row = c.fetchone()
    c.execute("DELETE FROM form_presets WHERE id=?", (preset_id,))
    deleted = c.rowcount
    conn.commit()
    conn.close()
    if not deleted:
        raise HTTPException(status_code=404, detail="Preset not found")
    _audit_action_request(request, "preset_delete", target_type="preset", target_id=str(preset_id), actor=_current_user_record(request), before=before_row)
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
        _audit_action_request(request, "common_client_update", target_type="common_client", target_id=str(client_id), actor=_current_user_record(request), after={"name": name, "client_name": client_name})
    else:
        c.execute(
            "INSERT INTO common_clients (name, client_name, project_name, doc_type, category, notes) VALUES (?, ?, ?, ?, ?, ?)",
            (name, client_name, project_name, doc_type, category, notes),
        )
        client_id = c.lastrowid
        _audit_action_request(request, "common_client_create", target_type="common_client", target_id=str(client_id), actor=_current_user_record(request), after={"name": name, "client_name": client_name})
    conn.commit()
    conn.close()
    return {"ok": True, "id": client_id, "name": name}


@app.delete("/api/common-clients/{client_key}")
async def delete_common_client(request: Request, client_key: str, username: str = Depends(_require_admin_username)):
    deleted = _delete_common_client_by_key(client_key)
    if not deleted:
        raise HTTPException(status_code=404, detail="Common client not found")
    _audit_action_request(request, "common_client_delete", target_type="common_client", target_id=str(client_key), actor=_current_user_record(request), after={"deleted": deleted})
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
@_retry_sqlite_locked
def init_salary_db():
    conn = _bootstrap_sqlite_connect(DB_PATH)
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
        CREATE TABLE IF NOT EXISTS school_schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            school_year TEXT DEFAULT '',
            weekday TEXT DEFAULT '',
            school_name TEXT NOT NULL,
            teacher_name TEXT DEFAULT '',
            semester1 TEXT DEFAULT '',
            semester2 TEXT DEFAULT '',
            note TEXT DEFAULT '',
            sort_order INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1
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
        CREATE TABLE IF NOT EXISTS schools (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            school_year TEXT DEFAULT '',
            name TEXT NOT NULL,
            area TEXT DEFAULT '',
            location_address TEXT DEFAULT '',
            cooperation_type TEXT DEFAULT '',
            cooperation_status TEXT DEFAULT '潛在合作',
            current_class_count INTEGER DEFAULT 0,
            internal_owner TEXT DEFAULT '',
            next_followup_date TEXT DEFAULT '',
            next_followup_task TEXT DEFAULT '',
            followup_owner TEXT DEFAULT '',
            last_followup_note TEXT DEFAULT '',
            risk_tags TEXT DEFAULT '',
            note TEXT DEFAULT '',
            class_date TEXT DEFAULT '',
            class_time TEXT DEFAULT '',
            teacher_name TEXT DEFAULT '',
            teacher_contact TEXT DEFAULT '',
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    c.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_schools_year_name
        ON schools(school_year, name)
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS school_contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            school_id INTEGER NOT NULL,
            name TEXT DEFAULT '',
            position TEXT DEFAULT '',
            phone TEXT DEFAULT '',
            whatsapp TEXT DEFAULT '',
            email TEXT DEFAULT '',
            is_primary INTEGER DEFAULT 0,
            notes TEXT DEFAULT '',
            sort_order INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(school_id) REFERENCES schools(id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS school_followups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            school_id INTEGER NOT NULL,
            followup_date TEXT DEFAULT '',
            next_action TEXT DEFAULT '',
            owner TEXT DEFAULT '',
            due_date TEXT DEFAULT '',
            status TEXT DEFAULT '待跟進',
            summary TEXT DEFAULT '',
            note TEXT DEFAULT '',
            created_by TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(school_id) REFERENCES schools(id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS school_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            school_id INTEGER NOT NULL,
            document_name TEXT DEFAULT '',
            document_type TEXT DEFAULT '',
            file_name TEXT DEFAULT '',
            file_path TEXT DEFAULT '',
            mime_type TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            uploaded_by TEXT DEFAULT '',
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(school_id) REFERENCES schools(id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS school_finance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            school_id INTEGER NOT NULL,
            billing_name TEXT DEFAULT '',
            invoice_no TEXT DEFAULT '',
            cooperation_fee REAL DEFAULT 0,
            received_amount REAL DEFAULT 0,
            outstanding_amount REAL DEFAULT 0,
            billing_status TEXT DEFAULT '',
            invoice_date TEXT DEFAULT '',
            payment_due_date TEXT DEFAULT '',
            last_payment_date TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            restricted_view INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(school_id) REFERENCES schools(id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS class_tutors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            school_class_id INTEGER NOT NULL,
            teacher_id INTEGER,
            role TEXT DEFAULT '',
            confirmation_status TEXT DEFAULT '待回覆',
            notes TEXT DEFAULT '',
            sort_order INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(school_class_id) REFERENCES school_classes(id),
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
        ("email", "TEXT DEFAULT ''"),
        ("data_consent", "TEXT DEFAULT ''"),
        ("scnc_result", "TEXT DEFAULT ''"),
        ("english_name", "TEXT DEFAULT ''"),
        ("stage_name", "TEXT DEFAULT ''"),
        ("phone", "TEXT DEFAULT ''"),
        ("area", "TEXT DEFAULT ''"),
        ("bank_name", "TEXT DEFAULT ''"),
        ("bank_account_number", "TEXT DEFAULT ''"),
        ("bank_holder_name", "TEXT DEFAULT ''"),
        ("fps_id", "TEXT DEFAULT ''"),
        ("dance_styles", "TEXT DEFAULT ''"),
        ("teaching_targets", "TEXT DEFAULT ''"),
        ("experience", "TEXT DEFAULT ''"),
        ("bio", "TEXT DEFAULT ''"),
        ("car_plate", "TEXT DEFAULT ''"),
        ("teaching_availability", "TEXT DEFAULT ''"),
        ("extra_work", "TEXT DEFAULT ''"),
        ("instagram", "TEXT DEFAULT ''"),
        ("remarks", "TEXT DEFAULT ''"),
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
    c.execute("PRAGMA table_info(school_schedules)")
    schedule_cols = {row[1] for row in c.fetchall()}
    for col_name, col_def in [
        ("school_year", "TEXT DEFAULT ''"),
        ("weekday", "TEXT DEFAULT ''"),
        ("teacher_name", "TEXT DEFAULT ''"),
        ("semester1", "TEXT DEFAULT ''"),
        ("semester2", "TEXT DEFAULT ''"),
        ("note", "TEXT DEFAULT ''"),
        ("sort_order", "INTEGER DEFAULT 0"),
        ("is_active", "INTEGER DEFAULT 1"),
    ]:
        if col_name not in schedule_cols:
            c.execute(f"ALTER TABLE school_schedules ADD COLUMN {col_name} {col_def}")
    c.execute("PRAGMA table_info(schools)")
    school_cols = {row[1] for row in c.fetchall()}
    for col_name, col_def in [
        ("school_year", "TEXT DEFAULT ''"),
        ("name", "TEXT DEFAULT ''"),
        ("area", "TEXT DEFAULT ''"),
        ("location_address", "TEXT DEFAULT ''"),
        ("cooperation_type", "TEXT DEFAULT ''"),
        ("cooperation_status", "TEXT DEFAULT '潛在合作'"),
        ("current_class_count", "INTEGER DEFAULT 0"),
        ("internal_owner", "TEXT DEFAULT ''"),
        ("next_followup_date", "TEXT DEFAULT ''"),
        ("next_followup_task", "TEXT DEFAULT ''"),
        ("followup_owner", "TEXT DEFAULT ''"),
        ("last_followup_note", "TEXT DEFAULT ''"),
        ("risk_tags", "TEXT DEFAULT ''"),
        ("note", "TEXT DEFAULT ''"),
        ("class_date", "TEXT DEFAULT ''"),
        ("class_time", "TEXT DEFAULT ''"),
        ("teacher_name", "TEXT DEFAULT ''"),
        ("teacher_contact", "TEXT DEFAULT ''"),
        ("is_active", "INTEGER DEFAULT 1"),
        ("created_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
        ("updated_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
    ]:
        if col_name not in school_cols:
            c.execute(f"ALTER TABLE schools ADD COLUMN {col_name} {col_def}")
    c.execute("PRAGMA table_info(school_contacts)")
    contact_cols = {row[1] for row in c.fetchall()}
    for col_name, col_def in [
        ("school_id", "INTEGER DEFAULT 0"),
        ("name", "TEXT DEFAULT ''"),
        ("position", "TEXT DEFAULT ''"),
        ("phone", "TEXT DEFAULT ''"),
        ("whatsapp", "TEXT DEFAULT ''"),
        ("email", "TEXT DEFAULT ''"),
        ("is_primary", "INTEGER DEFAULT 0"),
        ("notes", "TEXT DEFAULT ''"),
        ("sort_order", "INTEGER DEFAULT 0"),
        ("is_active", "INTEGER DEFAULT 1"),
        ("created_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
        ("updated_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
    ]:
        if col_name not in contact_cols:
            c.execute(f"ALTER TABLE school_contacts ADD COLUMN {col_name} {col_def}")
    c.execute("PRAGMA table_info(school_followups)")
    followup_cols = {row[1] for row in c.fetchall()}
    for col_name, col_def in [
        ("school_id", "INTEGER DEFAULT 0"),
        ("followup_date", "TEXT DEFAULT ''"),
        ("next_action", "TEXT DEFAULT ''"),
        ("owner", "TEXT DEFAULT ''"),
        ("due_date", "TEXT DEFAULT ''"),
        ("status", "TEXT DEFAULT '待跟進'"),
        ("summary", "TEXT DEFAULT ''"),
        ("note", "TEXT DEFAULT ''"),
        ("created_by", "TEXT DEFAULT ''"),
        ("created_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
    ]:
        if col_name not in followup_cols:
            c.execute(f"ALTER TABLE school_followups ADD COLUMN {col_name} {col_def}")
    c.execute("PRAGMA table_info(school_documents)")
    document_cols = {row[1] for row in c.fetchall()}
    for col_name, col_def in [
        ("school_id", "INTEGER DEFAULT 0"),
        ("document_name", "TEXT DEFAULT ''"),
        ("document_type", "TEXT DEFAULT ''"),
        ("file_name", "TEXT DEFAULT ''"),
        ("file_path", "TEXT DEFAULT ''"),
        ("mime_type", "TEXT DEFAULT ''"),
        ("notes", "TEXT DEFAULT ''"),
        ("uploaded_by", "TEXT DEFAULT ''"),
        ("uploaded_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
    ]:
        if col_name not in document_cols:
            c.execute(f"ALTER TABLE school_documents ADD COLUMN {col_name} {col_def}")
    c.execute("PRAGMA table_info(school_finance)")
    finance_cols = {row[1] for row in c.fetchall()}
    for col_name, col_def in [
        ("school_id", "INTEGER DEFAULT 0"),
        ("billing_name", "TEXT DEFAULT ''"),
        ("invoice_no", "TEXT DEFAULT ''"),
        ("cooperation_fee", "REAL DEFAULT 0"),
        ("received_amount", "REAL DEFAULT 0"),
        ("outstanding_amount", "REAL DEFAULT 0"),
        ("billing_status", "TEXT DEFAULT ''"),
        ("invoice_date", "TEXT DEFAULT ''"),
        ("payment_due_date", "TEXT DEFAULT ''"),
        ("last_payment_date", "TEXT DEFAULT ''"),
        ("notes", "TEXT DEFAULT ''"),
        ("restricted_view", "INTEGER DEFAULT 1"),
        ("created_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
        ("updated_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
    ]:
        if col_name not in finance_cols:
            c.execute(f"ALTER TABLE school_finance ADD COLUMN {col_name} {col_def}")
    c.execute("PRAGMA table_info(class_tutors)")
    class_tutor_cols = {row[1] for row in c.fetchall()}
    for col_name, col_def in [
        ("school_class_id", "INTEGER DEFAULT 0"),
        ("teacher_id", "INTEGER DEFAULT NULL"),
        ("role", "TEXT DEFAULT ''"),
        ("confirmation_status", "TEXT DEFAULT '待回覆'"),
        ("notes", "TEXT DEFAULT ''"),
        ("sort_order", "INTEGER DEFAULT 0"),
        ("is_active", "INTEGER DEFAULT 1"),
        ("created_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
        ("updated_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
    ]:
        if col_name not in class_tutor_cols:
            c.execute(f"ALTER TABLE class_tutors ADD COLUMN {col_name} {col_def}")
    c.execute("""
        INSERT INTO schools (school_year, name, current_class_count, is_active)
        SELECT
            COALESCE(school_year, ''),
            school_name,
            0,
            MAX(COALESCE(is_active, 1))
        FROM school_schedules
        WHERE COALESCE(school_name, '') <> ''
        GROUP BY COALESCE(school_year, ''), school_name
        ON CONFLICT(school_year, name) DO UPDATE SET
            current_class_count=excluded.current_class_count,
            is_active=CASE WHEN excluded.is_active IS NULL THEN schools.is_active ELSE excluded.is_active END,
            updated_at=CURRENT_TIMESTAMP
    """)
    c.execute("""
        UPDATE schools
        SET current_class_count = (
            SELECT COUNT(*)
            FROM school_classes sc
            WHERE sc.is_active = 1
              AND COALESCE(sc.school_name, '') = schools.name
        ),
        updated_at = CURRENT_TIMESTAMP
    """)
    conn.commit()
    conn.close()

init_salary_db()

ATTENDANCE_AREA_OPTIONS = [
    "藍田",
    "旺角",
    "屯門",
    "何文田",
    "奧海城",
    "青衣",
    "北角",
    "元朗",
    "沙田",
]

ATTENDANCE_CATEGORY_OPTIONS = [
    "街舞",
    "KPOP",
    "Pop Dance",
    "Cheerleading",
    "Hip Hop",
    "Jazz Funk",
    "其他",
]

ATTENDANCE_STATUS_OPTIONS = [
    ("present", "✓ 出席"),
    ("absent", "✗ 缺席"),
    ("dropped", "⛔ 已退學"),
]


@_retry_sqlite_locked
def init_attendance_db():
    conn = _bootstrap_sqlite_connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attendance_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            lesson_group_id INTEGER DEFAULT 0,
            area TEXT DEFAULT '',
            student_name TEXT NOT NULL,
            class_date TEXT DEFAULT '',
            class_time TEXT DEFAULT '',
            class_category TEXT DEFAULT '',
            lesson_title TEXT DEFAULT '',
            student_order INTEGER DEFAULT 0,
            status TEXT DEFAULT 'present',
            absence_reason TEXT DEFAULT '',
            recorded_by_username TEXT DEFAULT '',
            recorded_by_display_name TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attendance_lesson_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            area TEXT DEFAULT '',
            class_title TEXT NOT NULL,
            weekday TEXT DEFAULT '',
            lesson_time TEXT DEFAULT '',
            class_category TEXT DEFAULT '',
            teacher_name TEXT DEFAULT '',
            school_name TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            sort_order INTEGER DEFAULT 0,
            is_demo INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attendance_lesson_students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            lesson_group_id INTEGER NOT NULL,
            student_name TEXT NOT NULL,
            display_order INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1,
            note TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(lesson_group_id) REFERENCES attendance_lesson_groups(id)
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_attendance_records_date ON attendance_records(class_date, class_time)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_attendance_records_area ON attendance_records(area)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_attendance_records_student ON attendance_records(student_name)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_attendance_lesson_groups_area ON attendance_lesson_groups(area, is_active, sort_order)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_attendance_lesson_students_group ON attendance_lesson_students(lesson_group_id, is_active, display_order)")
    cursor.execute("PRAGMA table_info(attendance_records)")
    attendance_cols = {row[1] for row in cursor.fetchall()}
    for col_name, col_def in [
        ("lesson_group_id", "INTEGER DEFAULT 0"),
        ("area", "TEXT DEFAULT ''"),
        ("student_name", "TEXT DEFAULT ''"),
        ("class_date", "TEXT DEFAULT ''"),
        ("class_time", "TEXT DEFAULT ''"),
        ("class_category", "TEXT DEFAULT ''"),
        ("lesson_title", "TEXT DEFAULT ''"),
        ("student_order", "INTEGER DEFAULT 0"),
        ("status", "TEXT DEFAULT 'present'"),
        ("absence_reason", "TEXT DEFAULT ''"),
        ("recorded_by_username", "TEXT DEFAULT ''"),
        ("recorded_by_display_name", "TEXT DEFAULT ''"),
        ("created_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
        ("updated_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
    ]:
        if col_name not in attendance_cols:
            cursor.execute(f"ALTER TABLE attendance_records ADD COLUMN {col_name} {col_def}")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_attendance_records_lesson_group ON attendance_records(lesson_group_id)")
    cursor.execute("PRAGMA table_info(attendance_lesson_groups)")
    lesson_group_cols = {row[1] for row in cursor.fetchall()}
    for col_name, col_def in [
        ("area", "TEXT DEFAULT ''"),
        ("class_title", "TEXT DEFAULT ''"),
        ("weekday", "TEXT DEFAULT ''"),
        ("lesson_time", "TEXT DEFAULT ''"),
        ("class_category", "TEXT DEFAULT ''"),
        ("teacher_name", "TEXT DEFAULT ''"),
        ("school_name", "TEXT DEFAULT ''"),
        ("notes", "TEXT DEFAULT ''"),
        ("sort_order", "INTEGER DEFAULT 0"),
        ("is_demo", "INTEGER DEFAULT 0"),
        ("is_active", "INTEGER DEFAULT 1"),
        ("created_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
        ("updated_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
    ]:
        if col_name not in lesson_group_cols:
            cursor.execute(f"ALTER TABLE attendance_lesson_groups ADD COLUMN {col_name} {col_def}")
    cursor.execute("PRAGMA table_info(attendance_lesson_students)")
    lesson_student_cols = {row[1] for row in cursor.fetchall()}
    for col_name, col_def in [
        ("lesson_group_id", "INTEGER DEFAULT 0"),
        ("student_name", "TEXT DEFAULT ''"),
        ("display_order", "INTEGER DEFAULT 0"),
        ("is_active", "INTEGER DEFAULT 1"),
        ("note", "TEXT DEFAULT ''"),
        ("created_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
        ("updated_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
    ]:
        if col_name not in lesson_student_cols:
            cursor.execute(f"ALTER TABLE attendance_lesson_students ADD COLUMN {col_name} {col_def}")

    cursor.execute("SELECT COUNT(*) FROM attendance_lesson_groups WHERE is_active=1")
    if (cursor.fetchone() or [0])[0] == 0:
        demo_groups = [
            ("藍田", "星期六 1200-1300 coyi KPOP", "星期六", "12:00-13:00", "KPOP", "Coyi", "藍田示範中心", "導師先揀地區，再揀課堂。", 10, 1, 1),
            ("旺角", "星期三 1530-1630 ring Street Dance", "星期三", "15:30-16:30", "Street Dance", "Ring", "旺角示範中心", "點名時只需揀當日日期同出席位置。", 20, 1, 1),
            ("沙田", "星期日 1000-1100 szelo Cheerleading", "星期日", "10:00-11:00", "Cheerleading", "Szelo", "沙田示範中心", "學生名單由管理員預先輸入。", 30, 1, 1),
        ]
        cursor.executemany(
            """
            INSERT INTO attendance_lesson_groups (
                area, class_title, weekday, lesson_time, class_category, teacher_name, school_name, notes, sort_order, is_demo, is_active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            demo_groups,
        )
        cursor.execute("SELECT id, class_title FROM attendance_lesson_groups WHERE is_demo=1 ORDER BY id")
        demo_ids = cursor.fetchall()
        demo_students = {
            "星期六 1200-1300 coyi KPOP": ["陳小明", "黃詠欣", "李柏熙", "張樂兒", "何子朗", "劉芷晴"],
            "星期三 1530-1630 ring Street Dance": ["王嘉怡", "陳俊傑", "林雅詩", "鄭浩然", "梁心怡"],
            "星期日 1000-1100 szelo Cheerleading": ["吳思妍", "許梓軒", "郭芷彤", "黃皓然"],
        }
        for lesson_id, class_title in demo_ids:
            names = demo_students.get(class_title, [])
            cursor.executemany(
                """
                INSERT INTO attendance_lesson_students (lesson_group_id, student_name, display_order, is_active)
                VALUES (?, ?, ?, 1)
                """,
                [(lesson_id, name, idx + 1) for idx, name in enumerate(names)],
            )
    conn.commit()
    conn.close()


init_attendance_db()

SCHOOL_STATUS_CHOICES = [
    "潛在合作",
    "洽談中",
    "等待報價",
    "等待確認",
    "已開班",
    "暫停合作",
    "已結束",
]

SCHOOL_RISK_CHOICES = [
    "未簽合約",
    "未收款",
    "導師未定",
    "學生人數不足",
    "場地未確認",
    "文件未齊",
    "需要跟進",
]


def _school_tags_from_text(value: str) -> list[str]:
    text = (value or "").strip()
    if not text:
        return []
    parts = re.split(r"[,\n，、]+", text)
    tags: list[str] = []
    for part in parts:
        item = part.strip()
        if item and item not in tags:
            tags.append(item)
    return tags


def _school_tags_to_text(tags: list[str]) -> str:
    cleaned: list[str] = []
    for item in tags:
        value = (item or "").strip()
        if value and value not in cleaned:
            cleaned.append(value)
    return "、".join(cleaned)


def _school_status_badge(status: str) -> str:
    status = (status or "潛在合作").strip()
    mapping = {
        "潛在合作": "badge-slate",
        "洽談中": "badge-blue",
        "等待報價": "badge-amber",
        "等待確認": "badge-amber",
        "已開班": "badge-teal",
        "暫停合作": "badge-rose",
        "已結束": "badge-slate",
    }
    return mapping.get(status, "badge-slate")


def _school_risk_badge(risk: str) -> str:
    mapping = {
        "未簽合約": "badge-amber",
        "未收款": "badge-rose",
        "導師未定": "badge-blue",
        "學生人數不足": "badge-amber",
        "場地未確認": "badge-blue",
        "文件未齊": "badge-rose",
        "需要跟進": "badge-amber",
    }
    return mapping.get(risk, "badge-slate")


_SCHOOL_LOCATION_RULES = [
    ("紅磡", "九龍城區", "香港九龍紅磡"),
    ("土瓜灣", "九龍城區", "香港九龍土瓜灣"),
    ("啟德", "九龍城區", "香港九龍啟德"),
    ("何文田", "九龍城區", "香港九龍何文田"),
    ("九龍城", "九龍城區", "香港九龍城"),
    ("旺角", "油尖旺區", "香港九龍旺角"),
    ("油麻地", "油尖旺區", "香港九龍油麻地"),
    ("尖沙咀", "油尖旺區", "香港九龍尖沙咀"),
    ("太子", "油尖旺區", "香港九龍太子"),
    ("大角咀", "油尖旺區", "香港九龍大角咀"),
    ("深水埗", "深水埗區", "香港九龍深水埗"),
    ("長沙灣", "深水埗區", "香港九龍長沙灣"),
    ("荔枝角", "深水埗區", "香港九龍荔枝角"),
    ("新蒲崗", "黃大仙區", "香港九龍新蒲崗"),
    ("黃大仙", "黃大仙區", "香港九龍黃大仙"),
    ("九龍灣", "觀塘區", "香港九龍九龍灣"),
    ("牛頭角", "觀塘區", "香港九龍牛頭角"),
    ("觀塘", "觀塘區", "香港九龍觀塘"),
    ("青衣", "葵青區", "香港新界青衣"),
    ("荃灣", "荃灣區", "香港新界荃灣"),
    ("葵芳", "葵青區", "香港新界葵芳"),
    ("屯門", "屯門區", "香港新界屯門"),
    ("元朗", "元朗區", "香港新界元朗"),
    ("沙田", "沙田區", "香港新界沙田"),
    ("大埔", "大埔區", "香港新界大埔"),
    ("北角", "東區", "香港島北角"),
    ("鰂魚涌", "東區", "香港島鰂魚涌"),
    ("柴灣", "東區", "香港島柴灣"),
    ("灣仔", "灣仔區", "香港島灣仔"),
    ("中環", "中西區", "香港島中環"),
    ("金鐘", "中西區", "香港島金鐘"),
    ("銅鑼灣", "灣仔區", "香港島銅鑼灣"),
    ("香港仔", "南區", "香港島香港仔"),
    ("鴨脷洲", "南區", "香港島鴨脷洲"),
    ("東涌", "離島區", "香港離島東涌"),
]

SCHOOL_AREA_OPTIONS = [
    "中西區",
    "灣仔區",
    "東區",
    "南區",
    "油尖旺區",
    "深水埗區",
    "九龍城區",
    "黃大仙區",
    "觀塘區",
    "離島區",
    "葵青區",
    "北區",
    "西貢區",
    "沙田區",
    "大埔區",
    "荃灣區",
    "屯門區",
    "元朗區",
]


def _school_area_options_html(selected_value: str = ""):
    selected_value = str(selected_value or "").strip()
    pieces = ['<option value="">請選擇地區</option>']
    for option in SCHOOL_AREA_OPTIONS:
        selected = " selected" if option == selected_value else ""
        pieces.append(f'<option value="{html.escape(option, quote=True)}"{selected}>{html.escape(option)}</option>')
    return "".join(pieces)


def _school_location_lookup(school_name: str):
    name = (school_name or "").strip()
    if not name:
        return "", ""
    for keyword, area, address in _SCHOOL_LOCATION_RULES:
        if keyword and keyword in name:
            return area, address
    return "", ""


def _sync_school_class_counts(conn: sqlite3.Connection, school_id: Optional[int] = None):
    cursor = conn.cursor()
    if school_id is None:
        cursor.execute(
            """
            UPDATE schools
            SET current_class_count = (
                SELECT COUNT(*)
                FROM school_classes sc
                WHERE sc.is_active = 1
                  AND COALESCE(sc.school_name, '') = schools.name
            ),
            updated_at = CURRENT_TIMESTAMP
            """
        )
    else:
        cursor.execute("SELECT name FROM schools WHERE id=?", (school_id,))
        row = cursor.fetchone()
        if not row:
            return
        name = row[0] or ""
        cursor.execute(
            """
            UPDATE schools
            SET current_class_count = (
                SELECT COUNT(*)
                FROM school_classes sc
                WHERE sc.is_active = 1
                  AND COALESCE(sc.school_name, '') = ?
            ),
            updated_at = CURRENT_TIMESTAMP
            WHERE id=?
            """,
            (name, school_id),
        )


def _ensure_school_entry(conn: sqlite3.Connection, school_year: str, school_name: str) -> int:
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO schools (school_year, name, is_active, current_class_count)
        VALUES (?, ?, 1, 0)
        ON CONFLICT(school_year, name) DO UPDATE SET
            is_active=1,
            updated_at=CURRENT_TIMESTAMP
        """,
        (school_year.strip(), school_name.strip()),
    )
    cursor.execute(
        "SELECT id FROM schools WHERE school_year=? AND name=?",
        (school_year.strip(), school_name.strip()),
    )
    row = cursor.fetchone()
    return int(row[0]) if row else 0


def _school_list_filters(
    search: str = "",
    area: str = "",
    status: str = "",
    owner: str = "",
    risk: str = "",
    followup_only: bool = False,
):
    filters = ["s.is_active=1"]
    params: list = []
    if search.strip():
        like = f"%{search.strip()}%"
        filters.append("(s.name LIKE ? OR COALESCE(s.note,'') LIKE ?)")
        params.extend([like, like])
    if area.strip():
        filters.append("COALESCE(s.area, '') = ?")
        params.append(area.strip())
    if status.strip():
        filters.append("COALESCE(s.cooperation_status, '') = ?")
        params.append(status.strip())
    if owner.strip():
        filters.append("COALESCE(s.internal_owner, '') = ?")
        params.append(owner.strip())
    if risk.strip():
        filters.append("COALESCE(s.risk_tags, '') LIKE ?")
        params.append(f"%{risk.strip()}%")
    if followup_only:
        filters.append(
            """(
                COALESCE(s.next_followup_date, '') <> ''
                AND date(s.next_followup_date) <= date('now')
            ) OR COALESCE(s.next_followup_task, '') <> '' OR COALESCE(s.risk_tags, '') LIKE '%需要跟進%'"""
        )
    return filters, params


def _fetch_school_overview_rows(
    school_year: str = "",
    search: str = "",
    area: str = "",
    status: str = "",
    owner: str = "",
    risk: str = "",
    followup_only: bool = False,
):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        filters, params = _school_list_filters(search, area, status, owner, risk, followup_only)
        if school_year.strip():
            filters.append("COALESCE(s.school_year, '') = ?")
            params.append(school_year.strip())
        where_sql = "WHERE " + " AND ".join(filters) if filters else ""
        cursor.execute(
            f"""
            SELECT
                s.id,
                s.school_year,
                s.name,
                COALESCE(s.area, ''),
                COALESCE(s.cooperation_type, ''),
                COALESCE(s.cooperation_status, ''),
                COALESCE(s.current_class_count, 0),
                COALESCE(s.internal_owner, ''),
                COALESCE(s.next_followup_date, ''),
                COALESCE(s.next_followup_task, ''),
                COALESCE(s.followup_owner, ''),
                COALESCE(s.last_followup_note, ''),
                COALESCE(s.risk_tags, ''),
                COALESCE(s.note, ''),
                COALESCE(s.is_active, 1),
                (
                    CASE
                        WHEN COALESCE(s.next_followup_date, '') <> '' AND date(s.next_followup_date) <= date('now') THEN 1
                        WHEN COALESCE(s.next_followup_task, '') <> '' AND COALESCE(s.cooperation_status, '') IN ('洽談中', '等待報價', '等待確認') THEN 1
                        WHEN COALESCE(s.risk_tags, '') LIKE '%需要跟進%' THEN 1
                        ELSE 0
                    END
                ) AS needs_followup,
                COALESCE((
                    SELECT COUNT(*)
                    FROM school_schedules ss
                    WHERE COALESCE(ss.school_year, '') = COALESCE(s.school_year, '')
                      AND COALESCE(ss.school_name, '') = COALESCE(s.name, '')
                      AND COALESCE(ss.is_active, 1) = 1
                ), 0) AS schedule_count
            FROM schools s
            {where_sql}
            ORDER BY
                needs_followup DESC,
                CASE COALESCE(s.cooperation_status, '')
                    WHEN '洽談中' THEN 1
                    WHEN '等待報價' THEN 2
                    WHEN '等待確認' THEN 3
                    WHEN '已開班' THEN 4
                    WHEN '潛在合作' THEN 5
                    WHEN '暫停合作' THEN 6
                    WHEN '已結束' THEN 7
                    ELSE 8
                END,
                COALESCE(s.next_followup_date, ''),
                s.name COLLATE NOCASE
            """,
            params,
        )
        rows = cursor.fetchall()
        conn.close()
        return rows
    except sqlite3.OperationalError as exc:
        if _is_sqlite_locked_error(exc):
            return []
        raise


def _fetch_school_detail(school_id: int):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, school_year, name, area, location_address, cooperation_type, cooperation_status, current_class_count,
                   internal_owner, next_followup_date, next_followup_task, followup_owner, last_followup_note,
                   risk_tags, note, is_active, created_at, updated_at, class_date, class_time, teacher_name, teacher_contact
            FROM schools
            WHERE id=?
            """,
            (school_id,),
        )
        school = cursor.fetchone()
        if not school:
            conn.close()
            return None
        cursor.execute(
            """
            SELECT id, name, position, phone, whatsapp, email, is_primary, notes, sort_order, is_active
            FROM school_contacts
            WHERE school_id=?
            ORDER BY COALESCE(sort_order, 0), is_primary DESC, name
            """,
            (school_id,),
        )
        contacts = cursor.fetchall()
        cursor.execute(
            """
            SELECT id, followup_date, next_action, owner, due_date, status, summary, note, created_by, created_at
            FROM school_followups
            WHERE school_id=?
            ORDER BY COALESCE(followup_date, created_at) DESC, id DESC
            """,
            (school_id,),
        )
        followups = cursor.fetchall()
        cursor.execute("SELECT school_year, name FROM schools WHERE id=?", (school_id,))
        row = cursor.fetchone()
        school_year = row[0] if row else ""
        school_name = row[1] if row else ""
        cursor.execute(
            """
            SELECT id, school_year, weekday, school_name, teacher_name, semester1, semester2, note, sort_order, is_active
            FROM school_schedules
            WHERE COALESCE(school_year, '') = ? AND COALESCE(school_name, '') = ?
            ORDER BY COALESCE(sort_order, 0), weekday, id
            """,
            (school_year, school_name),
        )
        schedules = cursor.fetchall()
        cursor.execute(
            """
            SELECT id, area, school_name, weekday, lesson_time, salary_per_hour, total_lessons, completed_lessons, lessons_this_month, is_active, teacher_id
            FROM school_classes
            WHERE COALESCE(school_name, '') = ? AND COALESCE(is_active, 1) = 1
            ORDER BY weekday, lesson_time, id
            """,
            (school_name,),
        )
        classes = cursor.fetchall()
        cursor.execute(
            """
            SELECT id, school_id, billing_name, invoice_no, cooperation_fee, received_amount, outstanding_amount,
                   billing_status, invoice_date, payment_due_date, last_payment_date, notes, restricted_view
            FROM school_finance
            WHERE school_id=?
            ORDER BY id DESC
            """,
            (school_id,),
        )
        finance = cursor.fetchall()
        cursor.execute(
            """
            SELECT id, school_class_id, teacher_id, role, confirmation_status, notes, sort_order, is_active
            FROM class_tutors
            WHERE school_class_id IN (
                SELECT id FROM school_classes WHERE COALESCE(school_name, '') = ?
            )
            ORDER BY COALESCE(sort_order, 0), id
            """,
            (school_name,),
        )
        tutor_rows = cursor.fetchall()
        conn.close()
        return {
            "school": school,
            "contacts": contacts,
            "followups": followups,
            "schedules": schedules,
            "classes": classes,
            "finance": finance,
            "tutor_rows": tutor_rows,
        }
    except sqlite3.OperationalError as exc:
        if _is_sqlite_locked_error(exc):
            return None
        raise


def _school_form_html(request: Request, school=None):
    row = school or ("", "", "", "", "", "", "潛在合作", 0, "", "", "", "", "", "", 1, "", "", "", "", "", "", "")
    (
        sid,
        school_year,
        name,
        area,
        location_address,
        cooperation_type,
        cooperation_status,
        current_class_count,
        internal_owner,
        next_followup_date,
        next_followup_task,
        followup_owner,
        last_followup_note,
        risk_tags,
        note,
        is_active,
        created_at,
        updated_at,
        class_date,
        class_time,
        teacher_name,
        teacher_contact,
    ) = row
    auto_area, auto_address = _school_location_lookup(name)
    if not (area or "").strip() and auto_area:
        area = auto_area
    if not (location_address or "").strip() and auto_address:
        location_address = auto_address
    selected_risks = set(_school_tags_from_text(risk_tags))
    action = f"/salary/schools/{sid}/save" if sid else "/salary/schools/new/save"
    risk_checks = "".join(
        f"""
        <label class="multi-check">
            <input type="checkbox" name="risk_tags" value="{html.escape(risk, quote=True)}"{' checked' if risk in selected_risks else ''}>
            <span class="multi-check-text">{html.escape(risk)}</span>
        </label>
        """
        for risk in SCHOOL_RISK_CHOICES
    )
    status_opts = "".join(
        f"<option value=\"{html.escape(status, quote=True)}\"{' selected' if status == cooperation_status else ''}>{html.escape(status)}</option>"
        for status in SCHOOL_STATUS_CHOICES
    )
    school_location_data = json.dumps(_SCHOOL_LOCATION_RULES, ensure_ascii=False).replace("</", "<\\/")
    return f"""
    <div class="card">
        <h3>{'編輯學校合作資料' if sid else '新增學校合作資料'}</h3>
        <p class="muted">目前班數會自動根據已開啟班別同步，不建議手動填寫。</p>
        <form method="post" action="{action}" class="stack">
            {_csrf_input_html(request)}
            <div class="school-filter-bar" style="grid-template-columns: repeat(2, minmax(0, 1fr));">
                <div class="field">
                    <label>學年</label>
                    <input name="school_year" value="{html.escape(school_year or '', quote=True)}" placeholder="2026-27">
                </div>
                <div class="field">
                    <label>學校 / 機構名稱</label>
                    <input id="school-name-input" name="name" value="{html.escape(name or '', quote=True)}" required>
                </div>
            </div>
            <div class="school-filter-bar">
                <div class="field">
                    <label>地區</label>
                    <select id="school-area-input" name="area">
                        {_school_area_options_html(area)}
                    </select>
                </div>
                <div class="field">
                    <label>校址</label>
                    <input id="school-address-input" name="location_address" value="{html.escape(location_address or '', quote=True)}" placeholder="香港九龍...">
                </div>
                <div class="field">
                    <label>合作類型</label>
                    <input name="cooperation_type" value="{html.escape(cooperation_type or '', quote=True)}" placeholder="校本班 / 活動 / 合作計劃">
                </div>
                <div class="field">
                    <label>合作狀態</label>
                    <select name="cooperation_status">{status_opts}</select>
                </div>
                <div class="field">
                    <label>內部負責人</label>
                    <input name="internal_owner" value="{html.escape(internal_owner or '', quote=True)}" placeholder="Mei">
                </div>
                <div class="field">
                    <label>下次跟進日期</label>
                    <input name="next_followup_date" type="date" value="{html.escape(next_followup_date or '', quote=True)}">
                </div>
                <div class="field">
                    <label>跟進負責人</label>
                    <input name="followup_owner" value="{html.escape(followup_owner or '', quote=True)}" placeholder="Mei">
                </div>
                <div class="field">
                    <label>課堂日期</label>
                    <input name="class_date" type="date" value="{html.escape(class_date or '', quote=True)}">
                </div>
                <div class="field">
                    <label>上課時間</label>
                    <input name="class_time" value="{html.escape(class_time or '', quote=True)}" placeholder="14:30-16:00">
                </div>
                <div class="field">
                    <label>導師姓名</label>
                    <input name="teacher_name" value="{html.escape(teacher_name or '', quote=True)}" placeholder="導師姓名">
                </div>
                <div class="field">
                    <label>導師聯絡資料</label>
                    <input name="teacher_contact" value="{html.escape(teacher_contact or '', quote=True)}" placeholder="電話 / WhatsApp / Email">
                </div>
            </div>
            <div class="field">
                <label>下一步要做甚麼</label>
                <textarea name="next_followup_task" rows="3" placeholder="例如：WhatsApp 主任確認 9 月開班時間">{html.escape(next_followup_task or '')}</textarea>
            </div>
            <div class="field">
                <label>最近一次跟進紀錄</label>
                <textarea name="last_followup_note" rows="3" placeholder="例如：已與校方確認初步意向">{html.escape(last_followup_note or '')}</textarea>
            </div>
            <div class="field">
                <label>風險標籤</label>
                <div class="checkbox-grid">{risk_checks}</div>
            </div>
            <div class="field">
                <label>備註</label>
                <textarea name="note" rows="4" placeholder="補充合作細節、內部提醒、歷史背景">{html.escape(note or '')}</textarea>
            </div>
            <div class="field">
                <label><input type="checkbox" name="is_active" value="1" {'checked' if int(is_active or 0) else ''}> 啟用</label>
            </div>
            <div class="detail-panel">
                <div class="detail-line"><span>自動班數</span><strong>{int(current_class_count or 0)} 班</strong></div>
                <div class="detail-line"><span>建立時間</span><strong>{html.escape(str(created_at or '-'))}</strong></div>
                <div class="detail-line"><span>更新時間</span><strong>{html.escape(str(updated_at or '-'))}</strong></div>
            </div>
            <div class="flex">
                <button type="submit" class="btn btn-primary">儲存</button>
                <a href="/salary/schools" class="btn btn-outline btn-small">返回列表</a>
            </div>
        </form>
    </div>
    <script>
    (() => {{
        const rules = {school_location_data};
        const nameInput = document.getElementById('school-name-input');
        const areaInput = document.getElementById('school-area-input');
        const addressInput = document.getElementById('school-address-input');
        if (!nameInput || !areaInput || !addressInput) return;
        const applyLookup = () => {{
            const value = (nameInput.value || '').trim();
            if (!value) return;
            for (const rule of rules) {{
                const [keyword, area, address] = rule;
                if (keyword && value.includes(keyword)) {{
                    if (!areaInput.value.trim()) areaInput.value = area || '';
                    if (!addressInput.value.trim()) addressInput.value = address || '';
                    return;
                }}
            }}
        }};
        nameInput.addEventListener('blur', applyLookup);
        nameInput.addEventListener('change', applyLookup);
        applyLookup();
    }})();
    </script>
    """

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
.badge-teal {{ background: #d9f4ee; color: #0f766e; }}
.badge-rose {{ background: #fde2e7; color: #be123c; }}
.badge-amber {{ background: #fff0cc; color: #92400e; }}
.badge-slate {{ background: #e5e7eb; color: #374151; }}
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
.filter-bar {{ display: grid; grid-template-columns: 1.4fr .8fr .9fr auto; gap: 10px; align-items: end; margin-bottom: 16px; }}
.filter-bar .field label {{ display: block; margin-bottom: 4px; font-size: 12px; color: #6b7280; font-weight: 600; }}
.filter-bar .field input,
.filter-bar .field select {{ width: 100%; padding: 8px 10px; border: 1px solid #d1d5db; border-radius: 8px; font-size: 13px; background: #fff; }}
.table-wrap {{ overflow-x: auto; }}
.muted-cell {{ color: #6b7280; font-size: 12px; }}
.teacher-badges {{ display: flex; gap: 6px; flex-wrap: wrap; margin-top: 6px; }}
.teacher-cards {{ display: none; }}
.teacher-card {{ position: relative; border: 1px solid #e5e7eb; border-left: 5px solid {BRAND_BLUE}; border-radius: 16px; background: #fff; padding: 16px; box-shadow: 0 2px 12px rgba(17,24,39,0.04); overflow: hidden; }}
.teacher-card::before {{ content: ""; position: absolute; inset: 0 auto 0 0; width: 5px; background: linear-gradient(180deg, {BRAND_BLUE}, #88a6d9); }}
.teacher-card-top {{ display: flex; justify-content: space-between; gap: 12px; align-items: flex-start; }}
.teacher-name {{ font-size: 16px; font-weight: 800; color: {TEXT_DARK}; line-height: 1.2; }}
.teacher-metrics {{ margin-top: 12px; display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px 12px; }}
.metric {{ background: #fafafa; border-radius: 12px; padding: 10px 12px; }}
.metric span {{ display: block; font-size: 11px; color: #6b7280; margin-bottom: 3px; }}
.metric strong {{ font-size: 13px; color: {TEXT_DARK}; }}
.metric.fps {{ grid-column: 1 / -1; }}
.quick-links {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 14px; padding: 10px; border: 1px solid #e5e7eb; border-radius: 16px; background: linear-gradient(180deg, rgba(255,255,255,.95), rgba(250,250,250,.92)); }}
.quick-links a {{ display: inline-flex; align-items: center; gap: 6px; padding: 8px 13px; border-radius: 999px; border: 1px solid #d1d5db; background: #fff; color: {TEXT_DARK}; text-decoration: none; font-size: 12px; font-weight: 800; letter-spacing: .01em; box-shadow: 0 1px 2px rgba(17,24,39,.04); }}
.quick-links a:hover {{ background: {BRAND_LIGHT}; }}
.quick-links a.active {{ background: {BRAND_BLUE}; border-color: {BRAND_BLUE}; color: #111111; }}
.quick-links .reset {{ margin-left: auto; padding: 10px 16px; font-size: 13px; border-width: 2px; background: #111827; border-color: #111827; color: #fff; }}
.quick-links .reset:hover {{ background: #1f2937; }}
.teacher-meta-line {{ margin-top: 8px; font-size: 12px; color: #6b7280; line-height: 1.5; }}
.detail-shell {{ display: grid; gap: 14px; }}
.detail-header {{ display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; padding: 16px; border: 1px solid #e5e7eb; border-radius: 16px; background: linear-gradient(180deg, #fff, #fafafa); }}
.detail-header h2 {{ margin: 0; font-size: 22px; line-height: 1.15; }}
.detail-header .sub {{ margin-top: 6px; font-size: 12px; color: #6b7280; line-height: 1.5; }}
.detail-header .tag-row {{ display: flex; gap: 6px; flex-wrap: wrap; margin-top: 10px; }}
.detail-header .tag-row .badge {{ font-size: 11px; }}
.detail-summary {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }}
.detail-summary .stat-card {{ padding: 14px 12px; }}
.detail-summary .num {{ font-size: 22px; }}
.detail-panel {{ border: 1px solid #e5e7eb; border-radius: 16px; background: #fff; padding: 16px; }}
.detail-panel h3 {{ margin-bottom: 10px; font-size: 15px; }}
.detail-lines {{ display: grid; gap: 8px; font-size: 13px; color: {TEXT_DARK}; }}
.detail-line {{ display: flex; gap: 10px; justify-content: space-between; align-items: baseline; }}
.detail-line span {{ color: #6b7280; min-width: 92px; }}
.school-tabs {{ display: flex; gap: 8px; flex-wrap: wrap; margin: 12px 0; }}
.school-tab-btn {{ border: 1px solid #d1d5db; background: #fff; color: {TEXT_DARK}; padding: 8px 12px; border-radius: 999px; font-size: 13px; font-weight: 700; cursor: pointer; }}
.school-tab-btn.active {{ background: {BRAND_BLUE}; color: #fff; border-color: {BRAND_BLUE}; }}
.school-section {{ display: none; }}
.school-section.active {{ display: grid; gap: 14px; }}
.school-section-card {{ border: 1px solid #e5e7eb; border-radius: 16px; background: #fff; padding: 16px; }}
.school-section-card h4 {{ margin: 0 0 10px; font-size: 16px; }}
.school-section-meta {{ display: grid; gap: 8px; }}
.school-section-line {{ display: flex; gap: 10px; justify-content: space-between; align-items: flex-start; }}
.school-section-line span {{ color: #6b7280; font-size: 12px; line-height: 1.4; }}
.school-section-line strong {{ text-align: right; }}
.school-card-shell {{ border: 1px solid #e5e7eb; border-radius: 16px; background: #fff; padding: 16px; }}
.school-card-shell + .school-card-shell {{ margin-top: 12px; }}
.school-card-header {{ display: flex; justify-content: space-between; gap: 12px; align-items: flex-start; }}
.school-card-title {{ font-size: 17px; font-weight: 800; line-height: 1.35; }}
.school-card-sub {{ color: #6b7280; font-size: 12px; margin-top: 4px; line-height: 1.45; }}
.school-card-badges {{ display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }}
.school-metrics {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; margin-top: 14px; }}
.school-metric {{ padding: 10px 12px; border: 1px solid #edf0f4; border-radius: 12px; background: #fafafa; }}
.school-metric span {{ display: block; color: #6b7280; font-size: 11px; margin-bottom: 4px; }}
.school-metric strong {{ font-size: 13px; line-height: 1.4; }}
.school-card-actions {{ display: flex; gap: 8px; flex-wrap: wrap; margin-top: 14px; }}
.school-contact-grid {{ display: grid; gap: 10px; }}
.school-contact-card {{ border: 1px solid #edf0f4; border-radius: 14px; padding: 14px; background: #fff; }}
.school-contact-top {{ display: flex; justify-content: space-between; gap: 10px; align-items: flex-start; }}
.school-followup-card {{ border: 1px solid #edf0f4; border-radius: 14px; padding: 14px; background: #fff; }}
.school-followup-head {{ display: flex; justify-content: space-between; gap: 10px; align-items: center; margin-bottom: 8px; }}
.school-table-wrap {{ overflow-x: auto; }}
.school-card-view {{ display: none; gap: 12px; }}
.school-filter-bar {{ display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 10px; margin-top: 14px; }}
.alert-info {{ background: #fafafa; border-left: 3px solid {BRAND_BLUE}; padding: 12px 16px; border-radius: 8px; font-size: 13px; margin-bottom: 16px; color: #4b5563; }}
.footer {{ text-align: center; padding: 24px; font-size: 11px; color: #999; }}
.mt-2 {{ margin-top: 12px; }}
.flex {{ display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }}
.stack {{ display: grid; gap: 10px; }}
.field {{ display: grid; gap: 6px; }}
.field label {{ font-size: 13px; font-weight: 700; color: {TEXT_DARK}; }}
.field input,
.field select,
.field textarea {{ width: 100%; padding: 10px 12px; border: 1px solid #d1d5db; border-radius: 10px; font-size: 14px; background: #fff; color: {TEXT_DARK}; }}
.field textarea {{ min-height: 92px; resize: vertical; line-height: 1.5; }}
.teacher-form-grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }}
.teacher-form-grid .span-2 {{ grid-column: 1 / -1; }}
.checkbox-grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px 10px; align-items: start; }}
.multi-check {{
    display: grid;
    grid-template-columns: 18px minmax(0, 1fr);
    width: 100%;
    box-sizing: border-box;
    gap: 8px;
    align-items: start;
    justify-content: flex-start;
    padding: 10px 12px;
    border: 1px solid #e5e7eb;
    border-radius: 10px;
    background: #fafafa;
    font-size: 13px;
    line-height: 1.35;
    text-align: left;
    min-height: 44px;
    overflow-wrap: anywhere;
}}
.multi-check input {{
    width: 16px;
    height: 16px;
    margin: 1px 0 0;
    flex: 0 0 auto;
}}
.multi-check-text {{ display: block; min-width: 0; white-space: normal; }}
.schedule-table {{ display: grid; gap: 8px; }}
.schedule-head, .schedule-row {{ display: grid; grid-template-columns: 120px 1fr 1fr; gap: 8px; align-items: center; }}
.schedule-head {{ font-size: 12px; font-weight: 700; color: #6b7280; }}
.schedule-row strong {{ font-size: 13px; }}
@media (max-width: 768px) {{
    .teacher-form-grid {{ grid-template-columns: 1fr; }}
    .teacher-form-grid .span-2 {{ grid-column: auto; }}
    .checkbox-grid, .schedule-head, .schedule-row {{ grid-template-columns: 1fr; }}
    .schedule-head {{ display: none; }}
}}
.report-box {{ border: 1px solid #e5e7eb; border-radius: 14px; padding: 16px; margin-top: 14px; background: #fff; }}
.report-title {{ font-size: 15px; font-weight: 800; margin-bottom: 8px; }}
.muted {{ color: #6b7280; }}
.print-bar {{ display: flex; gap: 10px; flex-wrap: wrap; margin: 12px 0 18px; }}
@media print {{
    .nav, .footer, .print-bar, .no-print {{ display: none !important; }}
    body {{ background: #fff; }}
    .card, .report-box {{ box-shadow: none; border-color: #ccc; }}
}}
@media (max-width: 768px) {{
    .nav {{ padding: 12px 16px; }}
    .nav .flex {{ gap: 6px; }}
    .filter-bar {{ grid-template-columns: 1fr; }}
    .table-wrap {{ display: none; }}
    .school-table-wrap {{ display: none; }}
    .teacher-cards {{ display: grid; gap: 12px; }}
    .school-card-view {{ display: grid; }}
    .teacher-card {{ padding: 12px; }}
    .teacher-card-top {{ flex-direction: column; align-items: stretch; gap: 8px; }}
    .teacher-card-top .btn {{ align-self: flex-start; }}
    .teacher-metrics {{ grid-template-columns: 1fr 1fr; gap: 6px; margin-top: 10px; }}
    .metric {{ padding: 8px 9px; border-radius: 10px; }}
    .teacher-badges {{ margin-top: 4px; gap: 5px; }}
    .metric.fps {{ display: none; }}
    .teacher-meta-line {{ display: none; }}
    .quick-links {{ margin-bottom: 10px; }}
    .quick-links a {{ font-size: 11px; padding: 7px 10px; }}
    .quick-links .reset {{ width: 100%; margin-left: 0; justify-content: center; }}
    .quick-links {{ padding: 9px; }}
    .quick-links a {{ flex: 1 1 calc(50% - 8px); justify-content: center; }}
    .quick-links a.active {{ box-shadow: 0 0 0 1px rgba(255,255,255,.3) inset; }}
    .school-filter-bar {{ grid-template-columns: 1fr 1fr; }}
    .school-metrics {{ grid-template-columns: 1fr 1fr; }}
    .school-card-header {{ flex-direction: column; }}
    .school-section-line {{ flex-direction: column; gap: 3px; }}
    .school-section-line strong {{ text-align: left; }}
    .detail-header {{ flex-direction: column; padding: 14px; }}
    .detail-header h2 {{ font-size: 18px; }}
    .detail-header .sub {{ display: none; }}
    .detail-header .tag-row {{ margin-top: 8px; }}
    .detail-summary, .detail-panel {{ display: none; }}
    .detail-panel {{ padding: 14px; }}
    .detail-line {{ flex-direction: column; gap: 2px; }}
    .detail-line span {{ min-width: 0; }}
    .detail-shell > form {{ display: none; }}
    .teacher-card-top {{ gap: 6px; }}
    .teacher-name {{ font-size: 15px; }}
    .teacher-badges .badge {{ font-size: 10px; padding: 2px 8px; }}
    .teacher-metrics {{ grid-template-columns: 1fr; gap: 6px; margin-top: 8px; }}
    .metric {{ padding: 8px 10px; display: flex; align-items: center; justify-content: space-between; gap: 10px; }}
    .metric span {{ margin-bottom: 0; font-size: 10px; }}
    .metric strong {{ font-size: 12px; text-align: right; }}
    .metric.fps {{ display: none; }}
}}
</style></head><body>
<div class="nav">
<div><h1>💃 導師薪酬系統</h1></div>
<div class="flex">
<a href="/salary">📊 Dashboard</a>
<a href="/salary/payroll">🧾 月薪頁</a>
<a href="/salary/teachers">👨‍🏫 導師</a>
<a href="/salary/schools">🏫 學校資料</a>
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


def _format_salary_month_label(year: int, month: int):
    return f"{int(year)}年{int(month)}月"


def _parse_money_value(value):
    text = str(value or "").strip()
    if not text:
        return 0.0
    cleaned = re.sub(r"[^\d.\-]", "", text.replace(",", ""))
    if cleaned in {"", ".", "-", "-.", ".-"}:
        return 0.0
    try:
        return float(cleaned)
    except Exception:
        return 0.0


def _normalize_payroll_sheet_url(url: str):
    text = str(url or "").strip()
    if not text:
        return ""
    if "export?format=csv" in text:
        return text
    if "docs.google.com/spreadsheets/d/" not in text:
        return text
    base = text.split("/edit", 1)[0].rstrip("/")
    gid = ""
    match = re.search(r"[?&]gid=(\d+)", text)
    if match:
        gid = match.group(1)
    export = f"{base}/export?format=csv"
    if gid:
        export += f"&gid={gid}"
    return export


def _download_text_from_url(url: str):
    with urllib.request.urlopen(url) as response:
        raw = response.read()
    for encoding in ("utf-8-sig", "utf-8", "cp950"):
        try:
            return raw.decode(encoding)
        except Exception:
            pass
    return raw.decode("utf-8", errors="ignore")


def _salary_month_records(year: int, month: int):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT t.id, t.name, t.bank_name, t.bank_account_number, t.fps_id,
               COALESCE(sr.total_amount, 0), COALESCE(sr.status, 'pending')
        FROM teachers t
        LEFT JOIN salary_records sr ON sr.teacher_id = t.id AND sr.year=? AND sr.month=?
        WHERE t.is_active=1
        ORDER BY t.name
        """,
        (int(year), int(month)),
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


def _build_salary_xlsx_bytes(year: int, month: int, rows):
    month_label = _format_salary_month_label(year, month)
    out = io.BytesIO()

    def cell_ref(col_idx, row_idx):
        n = col_idx
        letters = ""
        while n:
            n, rem = divmod(n - 1, 26)
            letters = chr(65 + rem) + letters
        return f"{letters}{row_idx}"

    sheet_rows = []
    headers = ["導師", "銀行名稱", "戶口號碼", "FPS", "月份", "金額", "狀態"]
    sheet_rows.append(headers)
    for row in rows:
        sheet_rows.append([
            row[1] or "",
            row[2] or "",
            row[3] or "",
            row[4] or "",
            month_label,
            float(row[5] or 0),
            "已支付" if (row[6] or "") == "paid" else "待處理",
        ])

    sheet_xml_rows = []
    for r_idx, row in enumerate(sheet_rows, start=1):
        cells = []
        for c_idx, value in enumerate(row, start=1):
            ref = cell_ref(c_idx, r_idx)
            if isinstance(value, (int, float)) and c_idx == 6:
                cells.append(f'<c r="{ref}"><v>{value:.2f}</v></c>')
            else:
                cells.append(f'<c r="{ref}" t="inlineStr"><is><t>{xml_escape(str(value))}</t></is></c>')
        sheet_xml_rows.append(f'<row r="{r_idx}">{"".join(cells)}</row>')

    sheet_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
 xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheetData>
    {''.join(sheet_xml_rows)}
  </sheetData>
</worksheet>"""

    workbook_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
 xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="Payroll" sheetId="1" r:id="rId1"/>
  </sheets>
</workbook>"""

    content_types_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>"""

    rels_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="R1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"""

    workbook_rels_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>"""

    core_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
 xmlns:dc="http://purl.org/dc/elements/1.1/"
 xmlns:dcterms="http://purl.org/dc/terms/"
 xmlns:dcmitype="http://purl.org/dc/dcmitype/"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:title>Dance Kingdom Payroll {xml_escape(month_label)}</dc:title>
  <dc:creator>MEIMEI</dc:creator>
  <cp:lastModifiedBy>MEIMEI</cp:lastModifiedBy>
  <dcterms:created xsi:type="dcterms:W3CDTF">{datetime.utcnow().replace(microsecond=0).isoformat()}Z</dcterms:created>
</cp:coreProperties>"""

    app_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"
 xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
  <Application>Microsoft Excel</Application>
  <DocSecurity>0</DocSecurity>
  <ScaleCrop>false</ScaleCrop>
  <HeadingPairs>
    <vt:vector size="2" baseType="variant">
      <vt:variant><vt:lpstr>工作表</vt:lpstr></vt:variant>
      <vt:variant><vt:i4>1</vt:i4></vt:variant>
    </vt:vector>
  </HeadingPairs>
  <TitlesOfParts>
    <vt:vector size="1" baseType="lpstr">
      <vt:lpstr>Payroll</vt:lpstr>
    </vt:vector>
  </TitlesOfParts>
</Properties>"""

    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types_xml)
        zf.writestr("_rels/.rels", rels_xml)
        zf.writestr("xl/workbook.xml", workbook_xml)
        zf.writestr("xl/_rels/workbook.xml.rels", workbook_rels_xml)
        zf.writestr("xl/worksheets/sheet1.xml", sheet_xml)
        zf.writestr("docProps/core.xml", core_xml)
        zf.writestr("docProps/app.xml", app_xml)

    return out.getvalue()


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
        email = _csv_row_value(row, "email", "電郵地址")
        data_consent = _csv_row_value(row, "data_consent", "個人資料收集聲明確認")
        english_name = _csv_row_value(row, "english_name", "英文姓名")
        stage_name = _csv_row_value(row, "stage_name", "藝名", "常用名")
        instagram = _csv_row_value(row, "instagram", "IG")
        phone = _csv_row_value(row, "phone", "聯絡電話")
        area = _csv_row_value(row, "area", "居住區域")
        bank_name = _csv_row_value(row, "bank_name", "銀行名稱")
        bank_account_number = _csv_row_value(row, "bank_account_number", "戶口號碼")
        bank_holder_name = _csv_row_value(row, "bank_holder_name", "戶口持有人")
        fps_id = _csv_row_value(row, "fps_id", "FPS ID", "fps")
        dance_styles = _csv_row_value(row, "dance_styles", "擅長舞種")
        teaching_targets = _csv_row_value(row, "teaching_targets", "教授對象")
        experience = _csv_row_value(row, "experience", "教學經驗")
        bio = _csv_row_value(row, "bio", "個人簡介")
        car_plate = _csv_row_value(row, "car_plate", "車牌")
        extra_work = _csv_row_value(row, "extra_work", "除了常規課堂")
        scnc_result = _csv_row_value(row, "scnc_result", "性罪行查核")
        is_active = 1 if _truthy(_csv_row_value(row, "is_active", "啟用", default="1")) else 0
        cursor.execute("SELECT id FROM teachers WHERE name=?", (name,))
        existing = cursor.fetchone()
        if existing:
            cursor.execute(
                """
                UPDATE teachers
                SET email=?, data_consent=?, english_name=?, stage_name=?, instagram=?, phone=?, area=?, bank_name=?, bank_account_number=?,
                    bank_holder_name=?, fps_id=?, dance_styles=?, teaching_targets=?, experience=?, bio=?, car_plate=?, extra_work=?, scnc_result=?, is_active=?
                WHERE id=?
                """,
                (
                    email,
                    data_consent,
                    english_name,
                    stage_name,
                    instagram,
                    phone,
                    area,
                    bank_name,
                    bank_account_number,
                    bank_holder_name,
                    fps_id,
                    dance_styles,
                    teaching_targets,
                    experience,
                    bio,
                    car_plate,
                    extra_work,
                    scnc_result,
                    is_active,
                    existing[0],
                ),
            )
        else:
            cursor.execute(
                """
                INSERT INTO teachers (
                    name, email, data_consent, english_name, stage_name, instagram, phone, area, bank_name, bank_account_number,
                    bank_holder_name, fps_id, dance_styles, teaching_targets, experience, bio, car_plate, extra_work, scnc_result, is_active
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    name,
                    email,
                    data_consent,
                    english_name,
                    stage_name,
                    instagram,
                    phone,
                    area,
                    bank_name,
                    bank_account_number,
                    bank_holder_name,
                    fps_id,
                    dance_styles,
                    teaching_targets,
                    experience,
                    bio,
                    car_plate,
                    extra_work,
                    scnc_result,
                    is_active,
                ),
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
        cursor.execute("UPDATE school_classes SET is_active=0")
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
        _ensure_school_entry(conn, "2026-27", school_name)
        imported += 1
    _sync_school_class_counts(conn)
    conn.commit()
    conn.close()
    return imported


def _import_payroll_csv_text(csv_text: str, year: int, month: int, replace: bool = False):
    rows = list(csv.DictReader(io.StringIO(csv_text)))
    conn = _REAL_SQLITE_CONNECT(DB_PATH)
    cursor = conn.cursor()
    imported_teachers = 0
    imported_records = 0
    skipped_rows = 0
    total_amount = 0.0
    if replace:
        cursor.execute("DELETE FROM salary_records WHERE year=? AND month=?", (int(year), int(month)))
    for row in rows:
        teacher_name = _csv_row_value(row, "name", "teacher_name", "teacher", "導師")
        if not teacher_name:
            continue
        bank_name = _csv_row_value(row, "bank name", "bank_name", "銀行名稱", "bank")
        account_number = _csv_row_value(row, "account number", "bank_account_number", "戶口號碼", "account")
        fps_id = _csv_row_value(row, "fps_id", "fps", "FPS ID")
        note = _csv_row_value(row, "status", "note", "備註")
        amount = _parse_money_value(_csv_row_value(row, "June $$$", "June", "amount", "薪金", "salary", default="0"))
        if not fps_id and note:
            fps_match = re.search(r"fps\s*([0-9\- ]+)", note, re.IGNORECASE)
            if fps_match:
                fps_id = fps_match.group(1).strip()

        cursor.execute("SELECT id FROM teachers WHERE name=?", (teacher_name,))
        existing_teacher = cursor.fetchone()
        if existing_teacher:
            cursor.execute(
                """
                UPDATE teachers
                SET bank_name = CASE WHEN ? <> '' THEN ? ELSE bank_name END,
                    bank_account_number = CASE WHEN ? <> '' THEN ? ELSE bank_account_number END,
                    fps_id = CASE WHEN ? <> '' THEN ? ELSE fps_id END
                WHERE id=?
                """,
                (
                    bank_name, bank_name,
                    account_number, account_number,
                    fps_id, fps_id,
                    existing_teacher[0],
                ),
            )
            teacher_id = existing_teacher[0]
        else:
            cursor.execute(
                "INSERT INTO teachers (name, bank_name, bank_account_number, fps_id, is_active) VALUES (?, ?, ?, ?, 1)",
                (teacher_name, bank_name, account_number, fps_id),
            )
            teacher_id = cursor.lastrowid
            imported_teachers += 1

        if amount <= 0:
            skipped_rows += 1
            continue

        total_amount += amount
        cursor.execute(
            """
            INSERT INTO salary_records (teacher_id, month, year, total_classes, total_amount, status, created_at)
            VALUES (?, ?, ?, ?, ?, 'paid', CURRENT_TIMESTAMP)
            ON CONFLICT(teacher_id, year, month) DO UPDATE SET
                total_classes=excluded.total_classes,
                total_amount=excluded.total_amount,
                status='paid',
                created_at=CURRENT_TIMESTAMP
            """,
            (teacher_id, int(month), int(year), 0, amount),
        )
        imported_records += 1
    conn.commit()
    conn.close()
    return {
        "teachers": imported_teachers,
        "records": imported_records,
        "skipped": skipped_rows,
        "total_amount": total_amount,
        "rows": len(rows),
    }


def _import_school_schedule_csv_text(csv_text: str, school_year: str = "", replace: bool = False):
    rows = list(csv.DictReader(io.StringIO(csv_text)))
    conn = _REAL_SQLITE_CONNECT(DB_PATH)
    cursor = conn.cursor()
    imported = 0
    current_weekday = ""
    if replace:
        if school_year:
            cursor.execute("UPDATE school_schedules SET is_active=0 WHERE school_year=?", (school_year,))
        else:
            cursor.execute("UPDATE school_schedules SET is_active=0")
    for row in rows:
        school = _csv_row_value(row, "學校", "school", "school_name")
        sem1 = _csv_row_value(row, "上學期", "semester1", "first_term")
        sem2 = _csv_row_value(row, "下學期", "semester2", "second_term")
        teacher_name = _csv_row_value(row, "負責導師", "teacher", "teacher_name")
        note = _csv_row_value(row, "備註", "note", "remarks")
        if school and school.startswith("星期"):
            current_weekday = school
            continue
        if not school:
            continue
        cursor.execute(
            """
            INSERT INTO school_schedules
                (school_year, weekday, school_name, teacher_name, semester1, semester2, note, sort_order, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
            """,
            (
                school_year,
                current_weekday,
                school,
                teacher_name,
                sem1,
                sem2,
                note,
                imported,
            ),
        )
        imported += 1
    cursor.execute(
        """
        INSERT INTO schools (school_year, name, current_class_count, is_active)
        SELECT
            COALESCE(school_year, ''),
            school_name,
            0,
            1
        FROM school_schedules
        WHERE COALESCE(school_name, '') <> ''
        GROUP BY COALESCE(school_year, ''), school_name
        ON CONFLICT(school_year, name) DO UPDATE SET
            is_active=1,
            updated_at=CURRENT_TIMESTAMP
        """
    )
    cursor.execute("""
        UPDATE schools
        SET current_class_count = (
            SELECT COUNT(*)
            FROM school_classes sc
            WHERE sc.is_active = 1
              AND COALESCE(sc.school_name, '') = schools.name
        ),
        updated_at = CURRENT_TIMESTAMP
    """)
    conn.commit()
    conn.close()
    return {"imported": imported, "rows": len(rows), "school_year": school_year}


def _school_schedules_fetch(school_year: str = ""):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if school_year:
        cursor.execute(
            """
            SELECT id, school_year, weekday, school_name, teacher_name, semester1, semester2, note, sort_order, is_active
            FROM school_schedules
            WHERE school_year=?
            ORDER BY COALESCE(sort_order, 0), weekday, school_name, id
            """,
            (school_year,),
        )
    else:
        cursor.execute(
            """
            SELECT id, school_year, weekday, school_name, teacher_name, semester1, semester2, note, sort_order, is_active
            FROM school_schedules
            ORDER BY COALESCE(sort_order, 0), school_year, weekday, school_name, id
            """
        )
    rows = cursor.fetchall()
    conn.close()
    return rows


def _teacher_form_html(request: Request, teacher=None):
    teacher = teacher or ("", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", 1)
    tid = teacher[0] if len(teacher) > 0 else ""
    name = str(teacher[1] if len(teacher) > 1 else "")
    email = str(teacher[2] if len(teacher) > 2 else "")
    data_consent = _teacher_csv_list(teacher[3] if len(teacher) > 3 else "")
    english_name = str(teacher[4] if len(teacher) > 4 else "")
    stage_name = str(teacher[5] if len(teacher) > 5 else "")
    instagram = str(teacher[6] if len(teacher) > 6 else "")
    phone = str(teacher[7] if len(teacher) > 7 else "")
    area = str(teacher[8] if len(teacher) > 8 else "")
    bank_name = str(teacher[9] if len(teacher) > 9 else "")
    bank_account_number = str(teacher[10] if len(teacher) > 10 else "")
    bank_holder_name = str(teacher[11] if len(teacher) > 11 else "")
    fps_id = str(teacher[12] if len(teacher) > 12 else "")
    dance_styles = _teacher_csv_list(teacher[13] if len(teacher) > 13 else "")
    teaching_targets = _teacher_csv_list(teacher[14] if len(teacher) > 14 else "")
    experience = str(teacher[15] if len(teacher) > 15 else "")
    bio = str(teacher[16] if len(teacher) > 16 else "")
    car_plate = str(teacher[17] if len(teacher) > 17 else "")
    teaching_availability = _teacher_csv_list(teacher[18] if len(teacher) > 18 else "")
    extra_work = _teacher_csv_list(teacher[19] if len(teacher) > 19 else "")
    scnc_result = str(teacher[20] if len(teacher) > 20 else "")
    remarks = str(teacher[21] if len(teacher) > 21 else "")
    is_active = int(teacher[22] if len(teacher) > 22 else 1)
    csrf_html = _csrf_input_html(request)
    return f"""
    <div class="card">
        <h3>{'編輯導師' if tid else '新增導師'}</h3>
        <form method="post" action="/salary/teacher/{tid}/edit" class="stack">
            {csrf_html}
            <div class="teacher-form-grid">
                <div class="field span-2">
                    <label>個人資料收集聲明確認</label>
                    <div class="checkbox-grid">
                        {_teacher_multi_checkbox_html('data_consent', _teacher_consent_options(), data_consent)}
                    </div>
                </div>
                <div class="field">
                    <label>電郵地址</label>
                    <input type="email" name="email" value="{html.escape(email, quote=True)}">
                </div>
                <div class="field">
                    <label>中文姓名 (必須與身份證相同)</label>
                    <input name="name" value="{html.escape(name or '', quote=True)}">
                </div>
                <div class="field">
                    <label>英文姓名 (必須與身份證相同)</label>
                    <input name="english_name" value="{html.escape(english_name, quote=True)}">
                </div>
                <div class="field">
                    <label>藝名 / 常用名</label>
                    <input name="stage_name" value="{html.escape(stage_name, quote=True)}">
                </div>
                <div class="field">
                    <label>您的 Instagram</label>
                    <input name="instagram" value="{html.escape(instagram, quote=True)}">
                </div>
                <div class="field">
                    <label>聯絡電話 (只限數字、+、-、空格:8-20字元)</label>
                    <input name="phone" value="{html.escape(phone, quote=True)}">
                </div>
                <div class="field">
                    <label>居住區域</label>
                    <select name="area">
                        {_teacher_area_options_html(area)}
                    </select>
                </div>
                <div class="field">
                    <label>銀行名稱</label>
                    <select name="bank_name">
                        {_teacher_bank_options_html(bank_name)}
                    </select>
                </div>
                <div class="field">
                    <label>銀行戶口號碼</label>
                    <input name="bank_account_number" value="{html.escape(bank_account_number, quote=True)}">
                </div>
                <div class="field">
                    <label>銀行戶口持有人姓名</label>
                    <input name="bank_holder_name" value="{html.escape(bank_holder_name, quote=True)}">
                </div>
                <div class="field">
                    <label>轉數快 / PAYME</label>
                    <input name="fps_id" value="{html.escape(fps_id, quote=True)}">
                </div>
                <div class="field">
                    <label>教學經驗(年) (請輸入數字，例如:3。)</label>
                    <input type="number" min="0" name="experience" value="{html.escape(experience, quote=True)}">
                </div>
                <div class="field span-2">
                    <label>擅長舞種 (可多選)</label>
                    <div class="checkbox-grid">
                        {_teacher_multi_checkbox_html('dance_styles', _teacher_dance_style_options(), dance_styles)}
                    </div>
                </div>
                <div class="field span-2">
                    <label>擅長教授對象 (可多選)</label>
                    <div class="checkbox-grid">
                        {_teacher_multi_checkbox_html('teaching_targets', _teacher_target_options(), teaching_targets)}
                    </div>
                </div>
                <div class="field span-2">
                    <label>除了常規課堂您是否有興趣參與以下工作?</label>
                    <div class="checkbox-grid">
                        {_teacher_multi_checkbox_html('extra_work', _teacher_extra_work_options(), extra_work)}
                    </div>
                </div>
                <div class="field span-2">
                    <label>您目前是否持有有效的性罪行定罪紀錄查核結果？</label>
                    <div class="checkbox-grid">
                        {_teacher_radio_html('scnc_result', _teacher_scnc_options(), scnc_result)}
                    </div>
                </div>
                <div class="field span-2">
                    <label>個人簡介(Short Bio)</label>
                    <textarea name="bio" rows="3">{html.escape(bio)}</textarea>
                </div>
                <div class="field">
                    <label>車牌 (如有)</label>
                    <input name="car_plate" value="{html.escape(car_plate, quote=True)}">
                </div>
                <div class="field">
                    <label><input type="checkbox" name="is_active" value="1" {'checked' if is_active else ''}> 啟用</label>
                </div>
            </div>
            <div class="flex">
                <button type="submit" class="btn btn-primary">儲存</button>
                <a href="/salary/teachers" class="btn btn-outline btn-small">返回</a>
            </div>
        </form>
    </div>
    """


def _weekday_options_html(selected_value: str = ""):
    weekdays = ["星期一", "星期二", "星期三", "星期四", "星期五", "星期六", "星期日"]
    selected_value = str(selected_value or "").strip()
    pieces = ['<option value="">請選擇星期</option>']
    seen = set()
    for weekday in weekdays:
        seen.add(weekday)
        selected = " selected" if weekday == selected_value else ""
        pieces.append(f'<option value="{html.escape(weekday, quote=True)}"{selected}>{html.escape(weekday)}</option>')
    if selected_value and selected_value not in seen:
        pieces.append(f'<option value="{html.escape(selected_value, quote=True)}" selected>{html.escape(selected_value)}</option>')
    return "".join(pieces)


def _teacher_options_html(selected_value: str = ""):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM teachers ORDER BY name COLLATE NOCASE")
    teacher_rows = cursor.fetchall()
    conn.close()
    selected_value = str(selected_value or "").strip()
    pieces = ['<option value="">請選擇導師</option>']
    seen = set()
    for (teacher_name,) in teacher_rows:
        teacher_name = str(teacher_name or "").strip()
        if not teacher_name or teacher_name in seen:
            continue
        seen.add(teacher_name)
        selected = " selected" if teacher_name == selected_value else ""
        pieces.append(f'<option value="{html.escape(teacher_name, quote=True)}"{selected}>{html.escape(teacher_name)}</option>')
    if selected_value and selected_value not in seen:
        pieces.append(f'<option value="{html.escape(selected_value, quote=True)}" selected>{html.escape(selected_value)}</option>')
    return "".join(pieces)


def _salary_teacher_options_html(selected_value: str = ""):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM teachers WHERE is_active=1 ORDER BY name COLLATE NOCASE")
    teacher_rows = cursor.fetchall()
    conn.close()
    selected_value = str(selected_value or "").strip()
    pieces = ['<option value="">請選擇導師</option>']
    seen = set()
    for teacher_id, teacher_name in teacher_rows:
        teacher_name = str(teacher_name or "").strip()
        if not teacher_name or teacher_name in seen:
            continue
        seen.add(teacher_name)
        selected = " selected" if selected_value and selected_value == str(teacher_id) else ""
        pieces.append(
            f'<option value="{int(teacher_id)}"{selected}>{html.escape(teacher_name)}</option>'
        )
    return "".join(pieces)


def _teacher_get_extra(teacher, key: str, default=""):
    if not teacher:
        return default
    if isinstance(teacher, dict):
        return teacher.get(key, default)
    mapping = {
        "email": 2,
        "data_consent": 3,
        "english_name": 5,
        "stage_name": 6,
        "phone": 7,
        "area": 8,
        "bank_name": 9,
        "bank_account_number": 10,
        "bank_holder_name": 11,
        "fps_id": 12,
        "dance_styles": 13,
        "teaching_targets": 14,
        "experience": 15,
        "bio": 16,
        "car_plate": 17,
        "teaching_availability": 18,
        "extra_work": 19,
        "scnc_result": 20,
        "instagram": 21,
        "remarks": 22,
    }
    idx = mapping.get(key)
    if idx is None or len(teacher) <= idx:
        return default
    return teacher[idx] if teacher[idx] is not None else default


def _teacher_csv_list(value):
    text = str(value or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return [str(item).strip() for item in data if str(item).strip()]
    except Exception:
        pass
    return [item.strip() for item in re.split(r"[,\n;|]+", text) if item.strip()]


def _teacher_csv_text(values):
    if not values:
        return ""
    return json.dumps([str(item).strip() for item in values if str(item).strip()], ensure_ascii=False)


def _teacher_area_options_html(selected_value: str = ""):
    options = [
        "中西區", "東區", "南區", "灣仔區", "九龍城區", "觀塘區", "深水埗區", "黃大仙區",
        "油尖旺區", "離島區", "葵青區", "北區", "西貢區", "沙田區", "大埔區", "荃灣區",
        "屯門區", "元朗區", "其他",
    ]
    selected_value = str(selected_value or "").strip()
    pieces = ['<option value="">請選擇居住區域</option>']
    for option in options:
        selected = " selected" if option == selected_value else ""
        pieces.append(f'<option value="{html.escape(option, quote=True)}"{selected}>{html.escape(option)}</option>')
    return "".join(pieces)


def _teacher_bank_options_html(selected_value: str = ""):
    options = ["中國銀行(香港)", "恒生銀行", "匯豐銀行", "渣打銀行", "東亞銀行", "其他"]
    selected_value = str(selected_value or "").strip()
    pieces = ['<option value="">請選擇銀行名稱</option>']
    for option in options:
        selected = " selected" if option == selected_value else ""
        pieces.append(f'<option value="{html.escape(option, quote=True)}"{selected}>{html.escape(option)}</option>')
    if selected_value and selected_value not in options:
        pieces.append(f'<option value="{html.escape(selected_value, quote=True)}" selected>{html.escape(selected_value)}</option>')
    return "".join(pieces)


def _teacher_dance_style_options():
    return ["Hip Hop", "K-Pop", "Breaking", "Jazz Funk", "Popping", "Locking", "Waacking", "Contemporary", "Ballet", "兒童舞蹈", "其他"]


def _teacher_target_options():
    return ["幼兒", "小學", "初中", "高中", "成人", "親子", "SEN/融合教育支援", "其他"]


def _teacher_experience_options_html(selected_value: str = ""):
    options = ["1年以下", "1-3年", "3-5年", "5-10年", "10年以上"]
    selected_value = str(selected_value or "").strip()
    pieces = ['<option value="">請選擇教學經驗</option>']
    for option in options:
        selected = " selected" if option == selected_value else ""
        pieces.append(f'<option value="{html.escape(option, quote=True)}"{selected}>{html.escape(option)}</option>')
    if selected_value and selected_value not in options:
        pieces.append(f'<option value="{html.escape(selected_value, quote=True)}" selected>{html.escape(selected_value)}</option>')
    return "".join(pieces)


def _teacher_extra_work_options():
    return ["私人一對一教學", "舞台表演/編舞", "評審工作", "商演/活動表演", "舞台製作/後期製作"]


def _teacher_consent_options():
    return [
        "我確認以上資料只供導師聯絡、合規文件、保險、排課及出程用途。",
        "我承諾入校工作時唔講粗口，抽煙會遠離學校一公里",
        "我記得入校會遮蓋紋身",
    ]


def _teacher_scnc_options():
    return ["是", "否", "申請中"]


def _teacher_multi_checkbox_html(name: str, options, selected_values):
    selected = {str(item).strip() for item in (selected_values or []) if str(item).strip()}
    pieces = []
    for option in options:
        checked = " checked" if option in selected else ""
        pieces.append(
            f'<label class="multi-check"><input type="checkbox" name="{name}" value="{html.escape(option, quote=True)}"{checked}><span class="multi-check-text">{html.escape(option)}</span></label>'
        )
    return "".join(pieces)


def _teacher_radio_html(name: str, options, selected_value: str = ""):
    selected_value = str(selected_value or "").strip()
    pieces = []
    for option in options:
        checked = " checked" if option == selected_value else ""
        pieces.append(
            f'<label class="multi-check"><input type="radio" name="{name}" value="{html.escape(option, quote=True)}"{checked}><span class="multi-check-text">{html.escape(option)}</span></label>'
        )
    return "".join(pieces)


def _teacher_schedule_grid_html(selected_values):
    days = ["星期一", "星期二", "星期三", "星期四", "星期五", "星期六", "星期日"]
    slots = ["日間", "晚間"]
    selected = {str(item).strip() for item in (selected_values or []) if str(item).strip()}
    pieces = ['<div class="schedule-table">', '<div class="schedule-head"><span>星期</span><span>日間</span><span>晚間</span></div>']
    for day in days:
        row = [f'<div class="schedule-row"><strong>{html.escape(day)}</strong>']
        for slot in slots:
            key = f"{day}|{slot}"
            checked = " checked" if key in selected else ""
            row.append(
                f'<label class="multi-check"><input type="checkbox" name="teaching_availability" value="{html.escape(key, quote=True)}"{checked}><span class="multi-check-text">{html.escape(slot)}</span></label>'
            )
        row.append("</div>")
        pieces.append("".join(row))
    pieces.append("</div>")
    return "".join(pieces)


def _school_schedule_form_html(request: Request, row=None, school_year_default="2026-27"):
    row = row or ("", school_year_default, "", "", "", "", "", "", 0, 1)
    sid = row[0] if len(row) > 0 else ""
    school_year = row[1] if len(row) > 1 else school_year_default
    weekday = row[2] if len(row) > 2 else ""
    school_name = row[3] if len(row) > 3 else ""
    teacher_name = row[4] if len(row) > 4 else ""
    semester1 = row[5] if len(row) > 5 else ""
    semester2 = row[6] if len(row) > 6 else ""
    note = row[7] if len(row) > 7 else ""
    sort_order = row[8] if len(row) > 8 else 0
    is_active = int(row[9] if len(row) > 9 else 1)
    action = f"/salary/schools/{sid}/save" if sid else "/salary/schools/new/save"
    csrf_html = _csrf_input_html(request)
    return f"""
    <div class="card">
        <h3>{'編輯學校資料' if sid else '新增學校資料'}</h3>
        <form method="post" action="{action}" class="stack">
            {csrf_html}
            <div class="field">
                <label>學年</label>
                <input name="school_year" value="{html.escape(school_year or '', quote=True)}" placeholder="2026-27">
            </div>
            <div class="field">
                <label>星期</label>
                <select name="weekday">
                    {_weekday_options_html(weekday)}
                </select>
            </div>
            <div class="field">
                <label>學校</label>
                <input name="school_name" value="{html.escape(school_name or '', quote=True)}" required>
            </div>
            <div class="field">
                <label>負責導師</label>
                <select name="teacher_name">
                    {_teacher_options_html(teacher_name)}
                </select>
            </div>
            <div class="field">
                <label>上學期</label>
                <textarea name="semester1" rows="3" placeholder="可換行輸入上學期資料">{html.escape(semester1 or '')}</textarea>
            </div>
            <div class="field">
                <label>下學期</label>
                <textarea name="semester2" rows="3" placeholder="可換行輸入下學期資料">{html.escape(semester2 or '')}</textarea>
            </div>
            <div class="field">
                <label>備註</label>
                <textarea name="note" rows="4" placeholder="可換行輸入備註">{html.escape(note or '')}</textarea>
            </div>
            <div class="field">
                <label>排序</label>
                <input name="sort_order" type="number" value="{int(sort_order or 0)}">
            </div>
            <div class="field">
                <label><input type="checkbox" name="is_active" value="1" {'checked' if is_active else ''}> 啟用</label>
            </div>
            <div class="flex">
                <button type="submit" class="btn btn-primary">儲存</button>
                <a href="/salary/schools" class="btn btn-outline btn-small">返回</a>
            </div>
        </form>
    </div>
    """

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
async def salary_import_page(request: Request, user: tuple = Depends(require_roles("admin", "finance"))):
    csrf_html = _csrf_input_html(request)
    body = f"""
    <div class="alert-info">📥 支援 CSV 匯入導師同班別。建議先匯入導師，再匯入班別。匯入前可先用重置按鈕清空舊資料。</div>
    <div class="alert-info">📌 每月薪金可以直接匯入 Google Sheets 匯出 CSV，系統會自動寫入 `salary_records`，之後可按月份翻查。</div>
    <div class="stack" style="margin-bottom:18px;">
        <form action="/salary/import/schools-csv" method="post" enctype="multipart/form-data">
            {csrf_html}
            <div class="stack">
                <strong>學校資料匯入</strong>
                <div class="muted">欄位建議：學校, 上學期, 下學期, 負責導師, 上學期堂數, 下學期堂數, 備註</div>
                <div class="flex">
                    <div>
                        <label style="display:block;margin-bottom:4px;">學年</label>
                        <input type="text" name="school_year" value="2026-27" style="width:120px;padding:8px 10px;border:1px solid #ccc;border-radius:4px;">
                    </div>
                </div>
                <input type="file" name="file" accept=".csv,text/csv">
                <input type="url" name="sheet_url" placeholder="https://docs.google.com/spreadsheets/d/..." style="width:100%;padding:8px 10px;border:1px solid #ccc;border-radius:4px;">
                <label><input type="checkbox" name="replace" value="1"> 覆蓋同學年學校資料</label>
                <button type="submit" class="btn btn-primary">匯入學校資料</button>
                <a href="/salary/schools" class="btn btn-outline btn-small">前往學校資料頁</a>
            </div>
        </form>
        <form action="/salary/import/payroll-csv" method="post" enctype="multipart/form-data">
            {csrf_html}
            <div class="stack">
                <strong>每月薪金 CSV / Google Sheet 匯入</strong>
                <div class="muted">欄位建議：Name, Account Number, BANK NAME, June $$$, Amount in Words, Status</div>
                <div class="flex">
                    <div>
                        <label style="display:block;margin-bottom:4px;">年份</label>
                        <input type="number" name="year" value="{datetime.now().year}" min="2000" max="2100" style="width:110px;padding:8px 10px;border:1px solid #ccc;border-radius:4px;">
                    </div>
                    <div>
                        <label style="display:block;margin-bottom:4px;">月份</label>
                        <input type="number" name="month" value="{datetime.now().month}" min="1" max="12" style="width:90px;padding:8px 10px;border:1px solid #ccc;border-radius:4px;">
                    </div>
                </div>
                <div class="muted">可以上載 Google Sheets 匯出嘅 CSV，或者直接貼入 sheet URL。</div>
                <input type="file" name="file" accept=".csv,text/csv">
                <input type="url" name="sheet_url" placeholder="https://docs.google.com/spreadsheets/d/..." style="width:100%;padding:8px 10px;border:1px solid #ccc;border-radius:4px;">
                <label><input type="checkbox" name="replace" value="1"> 覆蓋同年月已有薪金紀錄</label>
                <button type="submit" class="btn btn-primary">匯入每月薪金</button>
            </div>
        </form>
        <form action="/salary/import/teachers-csv" method="post" enctype="multipart/form-data">
            {csrf_html}
            <div class="stack">
                <strong>導師 CSV 匯入</strong>
                <div class="muted">欄位建議：name, bank_name, bank_account_number, fps_id, is_active</div>
                <input type="file" name="file" accept=".csv,text/csv" required>
                <label><input type="checkbox" name="replace" value="1"> 覆蓋現有導師資料</label>
                <button type="submit" class="btn btn-primary">匯入導師 CSV</button>
            </div>
        </form>
        <form action="/salary/import/classes-csv" method="post" enctype="multipart/form-data">
            {csrf_html}
            <div class="stack">
                <strong>班別 CSV 匯入</strong>
                <div class="muted">欄位建議：teacher_name, area, school_name, weekday, lesson_time, salary_per_hour, total_lessons, completed_lessons, lessons_this_month, is_active</div>
                <input type="file" name="file" accept=".csv,text/csv" required>
                <label><input type="checkbox" name="replace" value="1"> 覆蓋現有班別資料</label>
                <button type="submit" class="btn btn-primary">匯入班別 CSV</button>
            </div>
        </form>
        <form action="/salary/reset-data" method="post" onsubmit="return confirm('確定清空導師、班別同薪酬記錄？');">
            {csrf_html}
            <button type="submit" class="btn btn-outline">清空導師 / 班別 / 薪酬</button>
        </form>
    </div>
    <div class="alert-info">手動匯入仍然保留，適合少量臨時補資料。</div>
    <form action="/salary/import" method="post">
    {csrf_html}
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


@app.get("/salary/payroll")
async def salary_payroll_page(
    request: Request,
    year: int = Query(default=datetime.now().year, ge=2000, le=2100),
    month: int = Query(default=datetime.now().month, ge=1, le=12),
    notice: str = Query(default=""),
    user: tuple = Depends(require_roles("admin", "finance")),
):
    rows = _salary_month_records(year, month)
    csrf_html = _csrf_input_html(request)
    month_label = _format_salary_month_label(year, month)
    options = "".join([f"<option value='{y}'{' selected' if y == year else ''}>{y}</option>" for y in range(datetime.now().year - 2, datetime.now().year + 2)])
    month_opts = "".join([f"<option value='{m}'{' selected' if m == month else ''}>{m:02d}</option>" for m in range(1, 13)])
    notice_html = ""
    if notice == "saved":
        notice_html = f"<div class=\"alert-info\">✅ 已儲存本月薪金，上一輪共保存 {int(request.query_params.get('count') or 0)} 位導師記錄。</div>"

    body = f"""
    {notice_html}
    <div class="alert-info">🧾 這個頁面用嚟每月填寫導師薪金。你可以直接見到銀行名稱、戶口號碼、FPS，同時可儲存同匯出 Excel。</div>
    <div class="stats">
        <div class="stat-card"><div class="num">{len(rows)}</div><div class="label">導師數量</div></div>
        <div class="stat-card"><div class="num">{month_label}</div><div class="label">目前月份</div></div>
    </div>
    <form method="get" action="/salary/payroll" class="flex mt-2">
        <div>
            <label style="display:block;margin-bottom:4px;">年份</label>
            <select name="year" style="padding:8px 10px;border:1px solid #d1d5db;border-radius:8px;">{options}</select>
        </div>
        <div>
            <label style="display:block;margin-bottom:4px;">月份</label>
            <select name="month" style="padding:8px 10px;border:1px solid #d1d5db;border-radius:8px;">{month_opts}</select>
        </div>
        <div style="align-self:end;">
            <button type="submit" class="btn btn-primary btn-small">切換月份</button>
        </div>
        <div style="align-self:end;">
            <a class="btn btn-outline btn-small" href="/salary/payroll/export.xlsx?year={year}&month={month}">匯出 Excel</a>
        </div>
    </form>
    <form method="post" action="/salary/payroll/save" class="stack" style="margin-top:14px;">
        {csrf_html}
        <input type="hidden" name="year" value="{year}">
        <input type="hidden" name="month" value="{month}">
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>導師</th>
                        <th>銀行名稱</th>
                        <th>戶口號碼</th>
                        <th>FPS</th>
                        <th>月份</th>
                        <th>薪金</th>
                        <th>狀態</th>
                    </tr>
                </thead>
                <tbody>
    """
    for tid, name, bank_name, account_no, fps_id, amount, status in rows:
        amount_val = float(amount or 0)
        status = status or "pending"
        body += f"""
                    <tr>
                        <td>
                            <strong>{html.escape(name)}</strong>
                            <input type="hidden" name="teacher_id" value="{tid}">
                        </td>
                        <td>{html.escape(bank_name or '-')}</td>
                        <td>{html.escape(account_no or '-')}</td>
                        <td>{html.escape(fps_id or '-')}</td>
                        <td>{month_label}</td>
                        <td><input name="amount" type="number" step="0.01" min="0" value="{amount_val:.2f}" style="width:140px;padding:8px;border:1px solid #d1d5db;border-radius:8px;"></td>
                        <td>
                            <select name="status" style="padding:8px;border:1px solid #d1d5db;border-radius:8px;">
                                <option value="pending"{' selected' if status == 'pending' else ''}>待處理</option>
                                <option value="paid"{' selected' if status == 'paid' else ''}>已支付</option>
                            </select>
                        </td>
                    </tr>
        """
    body += """
                </tbody>
            </table>
        </div>
        <div class="flex mt-2">
            <button type="submit" class="btn btn-primary">儲存本月薪金</button>
        </div>
    </form>
    """
    return render_salary_page(f"🧾 {month_label} 導師薪金", body)


@app.post("/salary/payroll/save")
async def salary_payroll_save(
    request: Request,
    year: int = Form(..., ge=2000, le=2100),
    month: int = Form(..., ge=1, le=12),
    user: tuple = Depends(require_roles("admin", "finance")),
):
    form = await request.form()

    def _collect_values(*keys: str) -> List[str]:
        values: List[str] = []
        for key in keys:
            values.extend([str(v) for v in form.getlist(key)])
            if not values:
                value = form.get(key)
                if value is not None:
                    values.append(str(value))
        return [v for v in values if str(v).strip() != ""]

    teacher_id = _collect_values("teacher_id", "teacher_id[]")
    amount = _collect_values("amount", "amount[]")
    status = _collect_values("status", "status[]")

    if not teacher_id or not amount or not status:
        return HTMLResponse(
            f"{SALARY_HEADER}<div class='container'><div class='card'><h3>⚠️ 儲存失敗</h3><p>未搵到薪金表單資料，請重新整理頁面再試。</p><br><a href='/salary/payroll?year={year}&month={month}' class='btn btn-primary'>返回薪金頁</a></div></div>{SALARY_FOOTER}",
            status_code=400,
        )

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    saved = 0
    for i in range(min(len(teacher_id), len(amount), len(status))):
        try:
            tid = int(teacher_id[i])
            amt = float(str(amount[i] or 0).replace(",", "").strip() or 0)
            st = "paid" if str(status[i]).strip().lower() == "paid" else "pending"
            cursor.execute(
                """
                INSERT INTO salary_records (teacher_id, month, year, total_classes, total_amount, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(teacher_id, year, month) DO UPDATE SET
                    total_amount=excluded.total_amount,
                    status=excluded.status,
                    created_at=CURRENT_TIMESTAMP
                """,
                (tid, int(month), int(year), 0, amt, st),
            )
            saved += 1
        except Exception:
            continue
    conn.commit()
    conn.close()
    _audit_action_request(request, "salary_payroll_save", target_type="salary_batch", target_id=f"{year}-{month:02d}", actor=user, after={"saved": saved})
    return RedirectResponse(f"/salary/payroll?year={year}&month={month}&notice=saved&count={saved}", status_code=303)


@app.get("/salary/payroll/export.xlsx")
async def salary_payroll_export_xlsx(
    year: int = Query(default=datetime.now().year, ge=2000, le=2100),
    month: int = Query(default=datetime.now().month, ge=1, le=12),
    user: tuple = Depends(require_roles("admin", "finance")),
):
    rows = _salary_month_records(year, month)
    xlsx_bytes = _build_salary_xlsx_bytes(year, month, rows)
    label = _format_salary_month_label(year, month)
    headers = {
        "Content-Disposition": f'attachment; filename="salary_{year}_{month:02d}.xlsx"'
    }
    return Response(content=xlsx_bytes, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", headers=headers)


@app.post("/salary/import/teachers-csv")
async def salary_import_teachers_csv(
    request: Request,
    file: UploadFile = File(...),
    replace: str = Form("0"),
    user: tuple = Depends(require_roles("admin", "finance")),
):
    imported = _import_teachers_csv_text(_csv_text_from_upload(file), replace=str(replace) == "1")
    _audit_action_request(request, "salary_import", target_type="teachers", target_id="csv", actor=user, after={"imported": imported, "replace": str(replace) == "1"})
    return HTMLResponse(
        f"{SALARY_HEADER}<div class='container'><div class='card'><h3>✅ 導師 CSV 匯入完成</h3><p>成功匯入 {imported} 筆導師記錄。</p><br><a href='/salary/import' class='btn btn-primary'>返回</a></div></div>{SALARY_FOOTER}"
    )


@app.post("/salary/import/classes-csv")
async def salary_import_classes_csv(
    request: Request,
    file: UploadFile = File(...),
    replace: str = Form("0"),
    user: tuple = Depends(require_roles("admin", "finance")),
):
    imported = _import_classes_csv_text(_csv_text_from_upload(file), replace=str(replace) == "1")
    _audit_action_request(request, "salary_import", target_type="classes", target_id="csv", actor=user, after={"imported": imported, "replace": str(replace) == "1"})
    return HTMLResponse(
        f"{SALARY_HEADER}<div class='container'><div class='card'><h3>✅ 班別 CSV 匯入完成</h3><p>成功匯入 {imported} 筆班別記錄。</p><br><a href='/salary/import' class='btn btn-primary'>返回</a></div></div>{SALARY_FOOTER}"
    )


@app.post("/salary/import/payroll-csv")
async def salary_import_payroll_csv(
    request: Request,
    file: Optional[UploadFile] = File(None),
    sheet_url: str = Form(""),
    year: int = Form(..., ge=2000, le=2100),
    month: int = Form(..., ge=1, le=12),
    replace: str = Form("0"),
    user: tuple = Depends(require_roles("admin", "finance")),
):
    csv_text = ""
    if file and getattr(file, "filename", ""):
        csv_text = _csv_text_from_upload(file)
    elif sheet_url.strip():
        csv_text = _download_text_from_url(_normalize_payroll_sheet_url(sheet_url))
    if not csv_text.strip():
        return HTMLResponse(
            f"{SALARY_HEADER}<div class='container'><div class='card'><h3>❌ 未有可匯入內容</h3><p>請提供 CSV 檔案或 Google Sheets URL。</p><br><a href='/salary/import' class='btn btn-primary'>返回</a></div></div>{SALARY_FOOTER}",
            status_code=400,
        )
    result = _import_payroll_csv_text(csv_text, year=year, month=month, replace=str(replace) == "1")
    label = _format_salary_month_label(year, month)
    _audit_action_request(
        request,
        "salary_import",
        target_type="payroll",
        target_id=f"{year}-{month:02d}",
        actor=user,
        after={"year": year, "month": month, **result, "replace": str(replace) == "1"},
    )
    return HTMLResponse(
        f"{SALARY_HEADER}<div class='container'><div class='card'><h3>✅ {label} 薪金匯入完成</h3><p>成功寫入 {result['records']} 筆薪金記錄，新增 {result['teachers']} 位導師資料，跳過 {result['skipped']} 筆金額為 0 的資料。總金額：${result['total_amount']:,.0f}</p><br><a href='/salary/records?year={year}&month={month}' class='btn btn-primary'>查看 {label} 記錄</a> <a href='/salary/import' class='btn btn-outline'>返回</a></div></div>{SALARY_FOOTER}"
    )


@app.post("/salary/import/schools-csv")
async def salary_import_schools_csv(
    request: Request,
    file: Optional[UploadFile] = File(None),
    sheet_url: str = Form(""),
    school_year: str = Form("2026-27"),
    replace: str = Form("0"),
    user: tuple = Depends(require_roles("admin", "finance")),
):
    csv_text = ""
    if file and getattr(file, "filename", ""):
        csv_text = _csv_text_from_upload(file)
    elif sheet_url.strip():
        csv_text = _download_text_from_url(_normalize_payroll_sheet_url(sheet_url))
    if not csv_text.strip():
        return HTMLResponse(
            f"{SALARY_HEADER}<div class='container'><div class='card'><h3>❌ 未有可匯入內容</h3><p>請提供 CSV 檔案或 Google Sheets URL。</p><br><a href='/salary/import' class='btn btn-primary'>返回</a></div></div>{SALARY_FOOTER}",
            status_code=400,
        )
    result = _import_school_schedule_csv_text(csv_text, school_year=school_year.strip(), replace=str(replace) == "1")
    _audit_action_request(
        request,
        "school_schedule_import",
        target_type="school_schedule",
        target_id=school_year.strip() or "all",
        actor=user,
        after=result,
    )
    return HTMLResponse(
        f"{SALARY_HEADER}<div class='container'><div class='card'><h3>✅ 學校資料匯入完成</h3><p>成功寫入 {result['imported']} 筆學校資料。</p><br><a href='/salary/schools?school_year={school_year.strip()}' class='btn btn-primary'>查看學校資料</a> <a href='/salary/import' class='btn btn-outline'>返回</a></div></div>{SALARY_FOOTER}"
    )


@app.post("/salary/reset-data")
async def salary_reset_data(request: Request, user: tuple = Depends(require_roles("admin", "finance"))):
    _clear_salary_data(clear_teachers=True)
    _audit_action_request(request, "salary_reset", target_type="salary", target_id="all", actor=user)
    return HTMLResponse(
        f"{SALARY_HEADER}<div class='container'><div class='card'><h3>✅ 已清空導師 / 班別 / 薪酬記錄</h3><p>你可以重新上載新學年資料。</p><br><a href='/salary/import' class='btn btn-primary'>返回</a></div></div>{SALARY_FOOTER}"
    )

@app.post("/salary/import")
async def salary_import_post(
    request: Request,
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
            _ensure_school_entry(conn, "2026-27", school[i].strip())
            imported += 1
        except Exception as e:
            print(f"Import error row {i}: {e}")
    conn.commit()
    _sync_school_class_counts(conn)
    conn.close()
    _audit_action_request(request, "salary_import", target_type="classes", target_id="manual", actor=user, after={"imported": imported})
    return HTMLResponse(f"{SALARY_HEADER}<div class='container'><div class='card'><h3>✅ 匯入完成</h3><p>成功匯入 {imported} 筆記錄。</p><br><a href='/salary' class='btn btn-primary'>返回 Dashboard</a></div></div>{SALARY_FOOTER}")

@app.get("/salary/teachers")
async def salary_teachers(
    request: Request,
    q: str = Query(default=""),
    status: str = Query(default="active"),
    class_state: str = Query(default="all"),
    user: tuple = Depends(require_roles("admin", "finance")),
):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    filters = []
    params: list = []
    q_norm = q.strip()
    status_norm = status.strip().lower()
    class_state_norm = class_state.strip().lower()

    if status_norm == "active":
        filters.append("t.is_active=1")
    elif status_norm == "inactive":
        filters.append("t.is_active=0")

    if q_norm:
        like = f"%{q_norm}%"
        filters.append("""
            (
                t.name LIKE ?
                OR COALESCE(t.email, '') LIKE ?
                OR COALESCE(t.english_name, '') LIKE ?
                OR COALESCE(t.stage_name, '') LIKE ?
                OR COALESCE(t.phone, '') LIKE ?
                OR COALESCE(t.area, '') LIKE ?
                OR COALESCE(t.bank_name, '') LIKE ?
                OR COALESCE(t.bank_account_number, '') LIKE ?
                OR COALESCE(t.bank_holder_name, '') LIKE ?
                OR COALESCE(t.fps_id, '') LIKE ?
                OR COALESCE(t.experience, '') LIKE ?
                OR COALESCE(t.instagram, '') LIKE ?
                OR EXISTS (
                    SELECT 1
                    FROM school_classes sc2
                    WHERE sc2.teacher_id = t.id
                      AND sc2.is_active = 1
                      AND (
                          COALESCE(sc2.area, '') LIKE ?
                          OR COALESCE(sc2.school_name, '') LIKE ?
                          OR COALESCE(sc2.weekday, '') LIKE ?
                          OR COALESCE(sc2.lesson_time, '') LIKE ?
                      )
                )
            )
        """)
        params.extend([like, like, like, like, like, like, like, like, like, like, like, like, like, like, like, like])

    if class_state_norm == "with_classes":
        filters.append("EXISTS (SELECT 1 FROM school_classes sc3 WHERE sc3.teacher_id = t.id AND sc3.is_active = 1)")
    elif class_state_norm == "without_classes":
        filters.append("NOT EXISTS (SELECT 1 FROM school_classes sc3 WHERE sc3.teacher_id = t.id AND sc3.is_active = 1)")

    where_sql = " WHERE " + " AND ".join(filters) if filters else ""
    c.execute(f"""
        SELECT
            t.id,
            t.name,
            t.email,
            t.data_consent,
            t.english_name,
            t.stage_name,
            t.instagram,
            t.phone,
            t.area,
            t.bank_name,
            t.bank_account_number,
            t.bank_holder_name,
            t.fps_id,
            t.dance_styles,
            t.teaching_targets,
            t.experience,
            t.bio,
            t.car_plate,
            t.extra_work,
            t.scnc_result,
            t.teaching_availability,
            t.remarks,
            t.is_active,
            COUNT(sc.id) AS class_count,
            COALESCE(SUM(sc.total_lessons), 0) AS total_lessons,
            COALESCE(SUM(sc.completed_lessons * sc.salary_per_hour), 0) AS amount
        FROM teachers t
        LEFT JOIN school_classes sc ON sc.teacher_id = t.id AND sc.is_active=1
        {where_sql}
        GROUP BY t.id
        ORDER BY t.is_active DESC, t.name
    """, params)
    rows = c.fetchall()
    conn.close()

    total_teachers = len(rows)
    active_teachers = sum(1 for r in rows if int(r[22] or 0) == 1)
    total_classes = sum(int(r[23] or 0) for r in rows)
    total_lessons = sum(int(r[24] or 0) for r in rows)
    total_amount = sum(float(r[25] or 0) for r in rows)

    q_value = html.escape(q_norm, quote=True)
    active_selected = "selected" if status_norm == "active" else ""
    inactive_selected = "selected" if status_norm == "inactive" else ""
    all_selected = "selected" if status_norm not in {"active", "inactive"} else ""
    with_classes_selected = "selected" if class_state_norm == "with_classes" else ""
    without_classes_selected = "selected" if class_state_norm == "without_classes" else ""
    all_classes_selected = "selected" if class_state_norm == "all" else ""
    active_with_selected = "active" if status_norm == "active" and class_state_norm == "with_classes" else ""
    active_without_selected = "active" if status_norm == "active" and class_state_norm == "without_classes" else ""
    active_all_selected = "active" if status_norm == "active" and class_state_norm == "all" else ""
    all_all_selected = "active" if status_norm == "all" and class_state_norm == "all" else ""

    body_html = f"""
    <div class="flex" style="margin-bottom:12px;">
        <a href="/salary/teachers/new" class="btn btn-primary btn-small">＋ 新增導師</a>
        <a href="/salary/import" class="btn btn-outline btn-small">匯入 / 管理資料</a>
    </div>
    <div class="quick-links">
        <a class="{active_with_selected}" href="/salary/teachers?status=active&class_state=with_classes">只顯示有班</a>
        <a class="{active_without_selected}" href="/salary/teachers?status=active&class_state=without_classes">只顯示無班</a>
        <a class="{active_all_selected}" href="/salary/teachers?status=active&class_state=all">活躍全部</a>
        <a class="{all_all_selected}" href="/salary/teachers?status=all&class_state=all">全部導師</a>
        <a class="reset" href="/salary/teachers">清除所有條件</a>
    </div>
    <form class="filter-bar" method="get" action="/salary/teachers">
        <div class="field">
            <label>搜尋</label>
            <input type="text" name="q" value="{q_value}" placeholder="導師名、學校、地區、FPS">
        </div>
        <div class="field">
            <label>導師狀態</label>
            <select name="status">
                <option value="active" {active_selected}>活躍</option>
                <option value="inactive" {inactive_selected}>停用</option>
                <option value="all" {all_selected}>全部</option>
            </select>
        </div>
        <div class="field">
            <label>班別</label>
            <select name="class_state">
                <option value="all" {all_classes_selected}>全部</option>
                <option value="with_classes" {with_classes_selected}>有班別</option>
                <option value="without_classes" {without_classes_selected}>無班別</option>
            </select>
        </div>
        <div class="field">
            <button type="submit" class="btn btn-primary">篩選</button>
        </div>
    </form>
    <div class="stats">
        <div class="stat-card"><div class="num">{total_teachers}</div><div class="label">顯示導師</div></div>
        <div class="stat-card"><div class="num">{active_teachers}</div><div class="label">活躍</div></div>
        <div class="stat-card"><div class="num">{total_classes}</div><div class="label">班數</div></div>
        <div class="stat-card"><div class="num">{total_lessons}</div><div class="label">總堂數</div></div>
        <div class="stat-card"><div class="num">${total_amount:,.0f}</div><div class="label">應付薪酬</div></div>
    </div>
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>導師</th>
                    <th>銀行資料</th>
                    <th>FPS</th>
                    <th>班數</th>
                    <th>總堂數</th>
                    <th>應付薪酬</th>
                    <th></th>
                </tr>
            </thead>
    <tbody>"""
    if rows:
        for tid, name, email, data_consent, english_name, stage_name, instagram, phone, area, bank_name, bank_account_number, bank_holder_name, fps_value, dance_styles, teaching_targets, experience, bio, car_plate, extra_work, scnc_result, teaching_availability, remarks, is_active, count, total_lessons, amt in rows:
            account_display = _mask_bank_account(bank_account_number)
            bank_display = bank_name or "-"
            fps_display = fps_value or "-"
            status_badge = "<span class='badge badge-teal'>活躍</span>" if int(is_active or 0) == 1 else "<span class='badge badge-rose'>停用</span>"
            bank_badge = "<span class='badge badge-amber'>已填</span>" if (bank_name or bank_account_number or fps_value) else "<span class='badge badge-slate'>未填</span>"
            body_html += f"""
                <tr>
                    <td>
                        <strong>{name}</strong>
                        <div class="muted-cell">{html.escape(stage_name or english_name or '-')}{' · ' + html.escape(email) if email else ''}</div>
                        <div class="teacher-badges">{status_badge}{bank_badge}</div>
                    </td>
                    <td>
                        <div>{html.escape(bank_display)}</div>
                        <div class="muted-cell">{html.escape(account_display) if account_display else '-'}</div>
                    </td>
                    <td>{html.escape(fps_display) if fps_display else '-'}</td>
                    <td>{count} 班</td>
                    <td>{total_lessons} 堂</td>
                    <td><strong>${amt:,.0f}</strong></td>
                    <td class="flex">
                        <a href='/salary/teacher/{tid}' class='btn btn-outline btn-small'>詳情</a>
                        <a href='/salary/teacher/{tid}/edit' class='btn btn-primary btn-small'>編輯</a>
                    </td>
                </tr>"""
    else:
        body_html += "<tr><td colspan='7' style='text-align:center;color:#6b7280;padding:22px;'>未有符合條件的導師</td></tr>"
    body_html += "</tbody></table></div>"

    cards_html = "<div class='teacher-cards'>"
    if rows:
        for tid, name, email, data_consent, english_name, stage_name, instagram, phone, area, bank_name, bank_account_number, bank_holder_name, fps_value, dance_styles, teaching_targets, experience, bio, car_plate, extra_work, scnc_result, teaching_availability, remarks, is_active, count, total_lessons, amt in rows:
            account_display = _mask_bank_account(bank_account_number)
            bank_display = bank_name or "-"
            fps_display = fps_value or "-"
            status_badge = "<span class='badge badge-teal'>活躍</span>" if int(is_active or 0) == 1 else "<span class='badge badge-rose'>停用</span>"
            bank_badge = "<span class='badge badge-amber'>已填資料</span>" if (bank_name or bank_account_number or fps_value) else "<span class='badge badge-slate'>未填資料</span>"
            cards_html += f"""
            <div class="teacher-card">
                <div class="teacher-card-top">
                    <div>
                        <div class="teacher-name">{html.escape(name)}</div>
                        <div class="muted-cell">{html.escape(stage_name or english_name or '-')}{' · ' + html.escape(email) if email else ''}</div>
                        <div class="teacher-badges">{status_badge}{bank_badge}</div>
                    </div>
                    <div class="flex">
                        <a href="/salary/teacher/{tid}" class="btn btn-outline btn-small">詳情</a>
                        <a href="/salary/teacher/{tid}/edit" class="btn btn-primary btn-small">編輯</a>
                    </div>
                </div>
                <div class="teacher-metrics">
                    <div class="metric"><span>銀行 / 戶口</span><strong>{html.escape(bank_display)} {html.escape(account_display) if account_display else '-'}</strong></div>
                    <div class="metric fps"><span>FPS</span><strong>{html.escape(fps_display) if fps_display else '-'}</strong></div>
                    <div class="metric"><span>班數</span><strong>{count} 班</strong></div>
                    <div class="metric"><span>總堂數</span><strong>{total_lessons} 堂</strong></div>
                    <div class="metric"><span>應付薪酬</span><strong>${amt:,.0f}</strong></div>
                </div>
                <div class="teacher-meta-line">手機版會收窄為精簡卡片，銀行資料已遮罩。</div>
            </div>"""
    else:
        cards_html += "<div class='teacher-card'><div class='muted-cell' style='padding:8px 2px;'>未有符合條件的導師</div></div>"
    cards_html += "</div>"

    body_html += cards_html
    return render_salary_page("👨‍🏫 導師列表", body_html)


@app.get("/salary/teachers/new")
async def salary_teacher_new(request: Request, user: tuple = Depends(require_roles("admin", "finance"))):
    body = """
    <div class="alert-info">新增導師後，可以直接喺導師列表再補銀行資料同 FPS。</div>
    """
    body += _teacher_form_html(request)
    return render_salary_page("➕ 新增導師", body)


@app.post("/salary/teachers/new")
async def salary_teacher_new_save(
    request: Request,
    name: str = Form(""),
    email: str = Form(""),
    data_consent: List[str] = Form(default=[]),
    english_name: str = Form(""),
    stage_name: str = Form(""),
    phone: str = Form(""),
    area: str = Form(""),
    bank_name: str = Form(""),
    bank_account_number: str = Form(""),
    bank_holder_name: str = Form(""),
    fps_id: str = Form(""),
    dance_styles: List[str] = Form(default=[]),
    teaching_targets: List[str] = Form(default=[]),
    experience: str = Form(""),
    bio: str = Form(""),
    car_plate: str = Form(""),
    teaching_availability: List[str] = Form(default=[]),
    extra_work: List[str] = Form(default=[]),
    scnc_result: str = Form(""),
    instagram: str = Form(""),
    remarks: str = Form(""),
    is_active: Optional[str] = Form(None),
    user: tuple = Depends(require_roles("admin", "finance")),
):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO teachers (
            name, email, data_consent, english_name, stage_name, instagram, phone, area, bank_name, bank_account_number,
            bank_holder_name, fps_id, dance_styles, teaching_targets, experience, bio, car_plate, teaching_availability,
            extra_work, scnc_result, remarks, is_active
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            name.strip(),
            email.strip(),
            _teacher_csv_text(data_consent),
            english_name.strip(),
            stage_name.strip(),
            instagram.strip(),
            phone.strip(),
            area.strip(),
            bank_name.strip(),
            bank_account_number.strip(),
            bank_holder_name.strip(),
            fps_id.strip(),
            _teacher_csv_text(dance_styles),
            _teacher_csv_text(teaching_targets),
            experience.strip(),
            bio.strip(),
            car_plate.strip(),
            _teacher_csv_text(teaching_availability),
            _teacher_csv_text(extra_work),
            scnc_result.strip(),
            remarks.strip(),
            1 if is_active else 0,
        ),
    )
    conn.commit()
    tid = cursor.lastrowid
    conn.close()
    _audit_action_request(request, "teacher_create", target_type="teacher", target_id=str(tid), actor=user, after={"name": name.strip(), "email": email.strip(), "english_name": english_name.strip(), "stage_name": stage_name.strip()})
    return HTMLResponse(
        f"{SALARY_HEADER}<div class='container'><div class='card'><h3>✅ 已新增導師</h3><p>{html.escape(name.strip())}</p><br><a href='/salary/teachers' class='btn btn-primary'>返回導師列表</a></div></div>{SALARY_FOOTER}"
    )


@app.get("/salary/teacher/{tid}/edit")
async def salary_teacher_edit(tid: int, request: Request, user: tuple = Depends(require_roles("admin", "finance"))):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, name, email, data_consent, english_name, stage_name, instagram, phone, area, bank_name, bank_account_number, bank_holder_name, fps_id,
               dance_styles, teaching_targets, experience, bio, car_plate, teaching_availability, extra_work, scnc_result, remarks, is_active
        FROM teachers WHERE id=?
        """,
        (tid,),
    )
    teacher = cursor.fetchone()
    conn.close()
    if not teacher:
        return HTMLResponse("導師不存在", status_code=404)
    body = """
    <div class="alert-info">你可以隨時手動修改導師銀行資料，之後薪金頁會即刻反映。</div>
    """
    body += _teacher_form_html(request, teacher)
    return render_salary_page("✏️ 編輯導師", body)


@app.post("/salary/teacher/{tid}/edit")
async def salary_teacher_edit_save(
    tid: int,
    request: Request,
    name: str = Form(""),
    email: str = Form(""),
    data_consent: List[str] = Form(default=[]),
    english_name: str = Form(""),
    stage_name: str = Form(""),
    phone: str = Form(""),
    area: str = Form(""),
    bank_name: str = Form(""),
    bank_account_number: str = Form(""),
    bank_holder_name: str = Form(""),
    fps_id: str = Form(""),
    dance_styles: List[str] = Form(default=[]),
    teaching_targets: List[str] = Form(default=[]),
    experience: str = Form(""),
    bio: str = Form(""),
    car_plate: str = Form(""),
    teaching_availability: List[str] = Form(default=[]),
    extra_work: List[str] = Form(default=[]),
    scnc_result: str = Form(""),
    instagram: str = Form(""),
    remarks: str = Form(""),
    is_active: Optional[str] = Form(None),
    user: tuple = Depends(require_roles("admin", "finance")),
):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE teachers
        SET name=?, email=?, data_consent=?, english_name=?, stage_name=?, instagram=?, phone=?, area=?, bank_name=?, bank_account_number=?, bank_holder_name=?, fps_id=?,
            dance_styles=?, teaching_targets=?, experience=?, bio=?, car_plate=?, teaching_availability=?, extra_work=?, scnc_result=?, remarks=?, is_active=?
        WHERE id=?
        """,
        (
            name.strip(),
            email.strip(),
            _teacher_csv_text(data_consent),
            english_name.strip(),
            stage_name.strip(),
            instagram.strip(),
            phone.strip(),
            area.strip(),
            bank_name.strip(),
            bank_account_number.strip(),
            bank_holder_name.strip(),
            fps_id.strip(),
            _teacher_csv_text(dance_styles),
            _teacher_csv_text(teaching_targets),
            experience.strip(),
            bio.strip(),
            car_plate.strip(),
            _teacher_csv_text(teaching_availability),
            _teacher_csv_text(extra_work),
            scnc_result.strip(),
            remarks.strip(),
            1 if is_active else 0,
            tid,
        ),
    )
    conn.commit()
    conn.close()
    _audit_action_request(request, "teacher_update", target_type="teacher", target_id=str(tid), actor=user, after={"name": name.strip(), "email": email.strip(), "english_name": english_name.strip(), "stage_name": stage_name.strip()})
    return HTMLResponse(
        f"{SALARY_HEADER}<div class='container'><div class='card'><h3>✅ 已更新導師資料</h3><p>{html.escape(name.strip())}</p><br><a href='/salary/teachers' class='btn btn-primary'>返回導師列表</a></div></div>{SALARY_FOOTER}"
    )


@app.get("/salary/schools")
async def salary_schools(
    request: Request,
    school_year: str = Query(default="2026-27"),
    q: str = Query(default=""),
    area: str = Query(default=""),
    status: str = Query(default=""),
    owner: str = Query(default=""),
    risk: str = Query(default=""),
    followup_only: str = Query(default="0"),
    user: tuple = Depends(require_roles("admin", "finance")),
):
    followup_flag = str(followup_only).strip().lower() in {"1", "true", "yes", "on"}
    rows = _fetch_school_overview_rows(
        school_year=school_year.strip(),
        search=q,
        area=area,
        status=status,
        owner=owner,
        risk=risk,
        followup_only=followup_flag,
    )
    areas = []
    owners = []
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        year_params = (school_year.strip(),)
        cursor.execute("SELECT DISTINCT COALESCE(area, '') FROM schools WHERE is_active=1 AND COALESCE(school_year, '')=? AND COALESCE(area, '')<>'' ORDER BY COALESCE(area, '')", year_params)
        areas = [r[0] for r in cursor.fetchall()]
        cursor.execute("SELECT DISTINCT COALESCE(internal_owner, '') FROM schools WHERE is_active=1 AND COALESCE(school_year, '')=? AND COALESCE(internal_owner, '')<>'' ORDER BY COALESCE(internal_owner, '')", year_params)
        owners = [r[0] for r in cursor.fetchall()]
        conn.close()
    except sqlite3.OperationalError as exc:
        if not _is_sqlite_locked_error(exc):
            raise
    total_all = len(rows)
    total_followup = sum(1 for r in rows if int(r[15] or 0) == 1)
    total_active = sum(1 for r in rows if int(r[14] or 0) == 1)
    total_classes = sum(int(r[6] or 0) for r in rows)
    conn.close()

    school_year_value = html.escape(school_year or "", quote=True)
    q_value = html.escape(q or "", quote=True)
    area_opts = "".join([f'<option value="{html.escape(item, quote=True)}"' + (" selected" if item == area else "") + f'>{html.escape(item)}</option>' for item in areas])
    owner_opts = "".join([f'<option value="{html.escape(item, quote=True)}"' + (" selected" if item == owner else "") + f'>{html.escape(item)}</option>' for item in owners])
    status_opts = "".join([f'<option value="{html.escape(item, quote=True)}"' + (" selected" if item == status else "") + f'>{html.escape(item)}</option>' for item in SCHOOL_STATUS_CHOICES])
    risk_opts = "".join([f'<option value="{html.escape(item, quote=True)}"' + (" selected" if item == risk else "") + f'>{html.escape(item)}</option>' for item in SCHOOL_RISK_CHOICES])
    body = f"""
    <div class="flex" style="margin-bottom:12px;">
        <a href="/salary/schools/new" class="btn btn-primary btn-small">＋ 新增學校資料</a>
        <a href="/salary/import" class="btn btn-outline btn-small">匯入資料</a>
    </div>
    <div class="alert-info">學校資料已改成「合作管理中心」模式。列表只保留營運判斷重點，詳情頁再查看聯絡人、班別、跟進與財務分區。</div>
    <form method="get" action="/salary/schools" class="school-filter-bar">
        <div class="field">
            <label>學年</label>
            <input name="school_year" value="{school_year_value}">
        </div>
        <div class="field">
            <label>搜尋學校名稱</label>
            <input name="q" value="{q_value}" placeholder="輸入學校 / 機構名稱">
        </div>
        <div class="field">
            <label>地區</label>
            <select name="area"><option value="">全部</option>{area_opts}</select>
        </div>
        <div class="field">
            <label>合作狀態</label>
            <select name="status"><option value="">全部</option>{status_opts}</select>
        </div>
        <div class="field">
            <label>負責人</label>
            <select name="owner"><option value="">全部</option>{owner_opts}</select>
        </div>
        <div class="field">
            <label>風險標籤</label>
            <select name="risk"><option value="">全部</option>{risk_opts}</select>
        </div>
        <div class="field">
            <label><input type="checkbox" name="followup_only" value="1"{' checked' if followup_flag else ''}> 只看需要跟進</label>
        </div>
        <div class="field" style="align-self:end;">
            <button type="submit" class="btn btn-primary btn-small">篩選</button>
        </div>
    </form>
    <div class="stats">
        <div class="stat-card"><div class="num">{total_all}</div><div class="label">顯示學校</div></div>
        <div class="stat-card"><div class="num">{total_active}</div><div class="label">啟用中</div></div>
        <div class="stat-card"><div class="num">{total_followup}</div><div class="label">需要跟進</div></div>
        <div class="stat-card"><div class="num">{total_classes}</div><div class="label">目前班數</div></div>
    </div>
    """
    if rows:
        body += """
        <div class="school-table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>學校 / 機構名稱</th>
                        <th>地區</th>
                        <th>合作狀態</th>
                        <th>合作類型</th>
                        <th>目前班數</th>
                        <th>內部負責人</th>
                        <th>下次跟進日期</th>
                        <th>風險標籤</th>
                        <th></th>
                    </tr>
                </thead>
                <tbody>
        """
        for row in rows:
            sid, sy, name, row_area, cooperation_type, cooperation_status, current_class_count, internal_owner, next_followup_date, next_followup_task, followup_owner, last_followup_note, risk_tags, note, is_active, needs_followup, schedule_count = row
            risks = _school_tags_from_text(risk_tags)
            risk_badges = " ".join([f'<span class="badge {_school_risk_badge(tag)}">{html.escape(tag)}</span>' for tag in risks]) or '<span class="badge badge-slate">無</span>'
            followup_badge = '<span class="badge badge-amber">需要跟進</span>' if int(needs_followup or 0) else '<span class="badge badge-teal">正常</span>'
            body += f"""
                    <tr>
                        <td>
                            <strong><a href="/salary/schools/{sid}" style="text-decoration:none;color:inherit;">{html.escape(name or '-')}</a></strong>
                            <div class="muted">{html.escape(sy or '-')} · {followup_badge}</div>
                        </td>
                        <td>{html.escape(row_area or '-')}</td>
                        <td><span class="badge {_school_status_badge(cooperation_status)}">{html.escape(cooperation_status or '潛在合作')}</span></td>
                        <td>{html.escape(cooperation_type or '-')}</td>
                        <td><strong>{int(current_class_count or 0)}</strong></td>
                        <td>{html.escape(internal_owner or '-')}</td>
                        <td>{html.escape(next_followup_date or '-')}</td>
                        <td>{risk_badges}</td>
                        <td class="flex">
                            <a class="btn btn-outline btn-small" href="/salary/schools/{sid}">查看</a>
                            <a class="btn btn-primary btn-small" href="/salary/schools/{sid}/edit">編輯</a>
                        </td>
                    </tr>
            """
        body += "</tbody></table></div>"
        body += '<div class="school-card-view">'
        for row in rows:
            sid, sy, name, row_area, cooperation_type, cooperation_status, current_class_count, internal_owner, next_followup_date, next_followup_task, followup_owner, last_followup_note, risk_tags, note, is_active, needs_followup, schedule_count = row
            risks = _school_tags_from_text(risk_tags)
            risk_badges = " ".join([f'<span class="badge {_school_risk_badge(tag)}">{html.escape(tag)}</span>' for tag in risks]) or '<span class="badge badge-slate">無風險標籤</span>'
            body += f"""
                <article class="school-card-shell">
                    <div class="school-card-header">
                        <div>
                            <div class="school-card-title"><a href="/salary/schools/{sid}" style="text-decoration:none;color:inherit;">{html.escape(name or '-')}</a></div>
                            <div class="school-card-sub">{html.escape(row_area or '-')} · {html.escape(cooperation_type or '-')}</div>
                            <div class="school-card-badges">
                                <span class="badge {_school_status_badge(cooperation_status)}">{html.escape(cooperation_status or '潛在合作')}</span>
                                {'<span class="badge badge-amber">需要跟進</span>' if int(needs_followup or 0) else '<span class="badge badge-teal">正常</span>'}
                            </div>
                        </div>
                        <div class="flex">
                            <a class="btn btn-outline btn-small" href="/salary/schools/{sid}">查看</a>
                            <a class="btn btn-primary btn-small" href="/salary/schools/{sid}/edit">編輯</a>
                        </div>
                    </div>
                    <div class="school-metrics">
                        <div class="school-metric"><span>目前班數</span><strong>{int(current_class_count or 0)}</strong></div>
                        <div class="school-metric"><span>負責人</span><strong>{html.escape(internal_owner or '-')}</strong></div>
                        <div class="school-metric"><span>下次跟進</span><strong>{html.escape(next_followup_date or '-')}</strong></div>
                    </div>
                    <div class="school-card-badges">{risk_badges}</div>
                </article>
            """
        body += "</div>"
    else:
        body += "<div class='card'><p class='muted'>暫時未有符合條件的學校資料。</p></div>"
    return render_salary_page(f"🏫 學校合作管理中心 - {school_year or '全部學年'}", body)


@app.get("/salary/schools/new")
async def salary_school_new(request: Request, user: tuple = Depends(require_roles("admin", "finance"))):
    body = "<div class='alert-info'>新增學校主檔，之後可在詳情頁補聯絡人、跟進紀錄同財務資料。</div>"
    body += _school_form_html(request)
    return render_salary_page("➕ 新增學校資料", body)


@app.post("/salary/schools/new/save")
async def salary_school_new_save(
    request: Request,
    school_year: str = Form("2026-27"),
    name: str = Form(...),
    area: str = Form(""),
    location_address: str = Form(""),
    cooperation_type: str = Form(""),
    cooperation_status: str = Form("潛在合作"),
    internal_owner: str = Form(""),
    next_followup_date: str = Form(""),
    next_followup_task: str = Form(""),
    followup_owner: str = Form(""),
    last_followup_note: str = Form(""),
    risk_tags: List[str] = Form(default=[]),
    note: str = Form(""),
    class_date: str = Form(""),
    class_time: str = Form(""),
    teacher_name: str = Form(""),
    teacher_contact: str = Form(""),
    is_active: Optional[str] = Form(None),
    user: tuple = Depends(require_roles("admin", "finance")),
):
    try:
        inferred_area, inferred_address = _school_location_lookup(name)
        area_value = area.strip() or inferred_area
        address_value = location_address.strip() or inferred_address
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO schools (
                school_year, name, area, location_address, cooperation_type, cooperation_status, internal_owner,
                next_followup_date, next_followup_task, followup_owner, last_followup_note,
                risk_tags, note, class_date, class_time, teacher_name, teacher_contact, is_active, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(school_year, name) DO UPDATE SET
                area=excluded.area,
                location_address=excluded.location_address,
                cooperation_type=excluded.cooperation_type,
                cooperation_status=excluded.cooperation_status,
                internal_owner=excluded.internal_owner,
                next_followup_date=excluded.next_followup_date,
                next_followup_task=excluded.next_followup_task,
                followup_owner=excluded.followup_owner,
                last_followup_note=excluded.last_followup_note,
                risk_tags=excluded.risk_tags,
                note=excluded.note,
                class_date=excluded.class_date,
                class_time=excluded.class_time,
                teacher_name=excluded.teacher_name,
                teacher_contact=excluded.teacher_contact,
                is_active=excluded.is_active,
                updated_at=CURRENT_TIMESTAMP
            """,
            (
                school_year.strip(),
                name.strip(),
                area_value,
                address_value,
                cooperation_type.strip(),
                cooperation_status.strip() or "潛在合作",
                internal_owner.strip(),
                next_followup_date.strip(),
                next_followup_task.strip(),
                followup_owner.strip(),
                last_followup_note.strip(),
                _school_tags_to_text(risk_tags),
                note.strip(),
                class_date.strip(),
                class_time.strip(),
                teacher_name.strip(),
                teacher_contact.strip(),
                1 if is_active else 0,
            ),
        )
        cursor.execute("SELECT id FROM schools WHERE school_year=? AND name=?", (school_year.strip(), name.strip()))
        row = cursor.fetchone()
        school_id = int(row[0]) if row else 0
        _sync_school_class_counts(conn, school_id)
        conn.commit()
        conn.close()
    except sqlite3.OperationalError as exc:
        if _is_sqlite_locked_error(exc):
            return HTMLResponse(f"{SALARY_HEADER}<div class='container'><h2>➕ 新增學校資料</h2><div class='card'><div class='alert-info'>資料庫忙緊中，請稍後再試一次新增學校。</div></div></div>{SALARY_FOOTER}", status_code=503)
        raise
    _audit_action_request(request, "school_create", target_type="school", target_id=str(school_id), actor=user, after={"school_year": school_year.strip(), "name": name.strip()})
    return RedirectResponse(f"/salary/schools/{school_id}", status_code=303)


@app.get("/salary/schools/{sid}/edit")
async def salary_school_edit(sid: int, request: Request, user: tuple = Depends(require_roles("admin", "finance"))):
    detail = _fetch_school_detail(sid)
    if not detail:
        return HTMLResponse("學校資料不存在", status_code=404)
    body = "<div class='alert-info'>你可以更新合作狀態、風險標籤同下一步跟進，不會刪除舊資料。</div>"
    body += _school_form_html(request, detail["school"])
    return render_salary_page("✏️ 編輯學校資料", body)


@app.post("/salary/schools/{sid}/save")
async def salary_school_edit_save(
    sid: int,
    request: Request,
    school_year: str = Form("2026-27"),
    name: str = Form(...),
    area: str = Form(""),
    location_address: str = Form(""),
    cooperation_type: str = Form(""),
    cooperation_status: str = Form("潛在合作"),
    internal_owner: str = Form(""),
    next_followup_date: str = Form(""),
    next_followup_task: str = Form(""),
    followup_owner: str = Form(""),
    last_followup_note: str = Form(""),
    risk_tags: List[str] = Form(default=[]),
    note: str = Form(""),
    class_date: str = Form(""),
    class_time: str = Form(""),
    teacher_name: str = Form(""),
    teacher_contact: str = Form(""),
    is_active: Optional[str] = Form(None),
    user: tuple = Depends(require_roles("admin", "finance")),
):
    try:
        inferred_area, inferred_address = _school_location_lookup(name)
        area_value = area.strip() or inferred_area
        address_value = location_address.strip() or inferred_address
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE schools
            SET school_year=?, name=?, area=?, location_address=?, cooperation_type=?, cooperation_status=?, internal_owner=?,
                next_followup_date=?, next_followup_task=?, followup_owner=?, last_followup_note=?,
                risk_tags=?, note=?, class_date=?, class_time=?, teacher_name=?, teacher_contact=?, is_active=?, updated_at=CURRENT_TIMESTAMP
            WHERE id=?
            """,
            (
                school_year.strip(),
                name.strip(),
                area_value,
                address_value,
                cooperation_type.strip(),
                cooperation_status.strip() or "潛在合作",
                internal_owner.strip(),
                next_followup_date.strip(),
                next_followup_task.strip(),
                followup_owner.strip(),
                last_followup_note.strip(),
                _school_tags_to_text(risk_tags),
                note.strip(),
                class_date.strip(),
                class_time.strip(),
                teacher_name.strip(),
                teacher_contact.strip(),
                1 if is_active else 0,
                sid,
            ),
        )
        _sync_school_class_counts(conn, sid)
        conn.commit()
        conn.close()
    except sqlite3.OperationalError as exc:
        if _is_sqlite_locked_error(exc):
            return HTMLResponse(f"{SALARY_HEADER}<div class='container'><h2>✏️ 編輯學校資料</h2><div class='card'><div class='alert-info'>資料庫忙緊中，請稍後再試一次儲存學校資料。</div></div></div>{SALARY_FOOTER}", status_code=503)
        raise
    _audit_action_request(request, "school_update", target_type="school", target_id=str(sid), actor=user, after={"school_year": school_year.strip(), "name": name.strip()})
    return RedirectResponse(f"/salary/schools/{sid}", status_code=303)


@app.post("/salary/schools/{sid}/delete")
async def salary_school_delete(
    sid: int,
    request: Request,
    user: tuple = Depends(require_roles("admin", "finance")),
):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT school_year, name FROM schools WHERE id=?", (sid,))
    row = cursor.fetchone()
    cursor.execute("UPDATE schools SET is_active=0, updated_at=CURRENT_TIMESTAMP WHERE id=?", (sid,))
    conn.commit()
    conn.close()
    _audit_action_request(request, "school_deactivate", target_type="school", target_id=str(sid), actor=user, after={"school_year": row[0] if row else "", "name": row[1] if row else ""})
    return RedirectResponse("/salary/schools", status_code=303)


@app.get("/salary/schools/{sid}")
async def salary_school_detail(sid: int, request: Request, user: tuple = Depends(require_roles("admin", "finance"))):
    detail = _fetch_school_detail(sid)
    if not detail:
        return HTMLResponse("學校資料不存在", status_code=404)
    school = detail["school"]
    contacts = detail["contacts"]
    followups = detail["followups"]
    schedules = detail["schedules"]
    classes = detail["classes"]
    finance_rows = detail["finance"]
    tutor_rows = detail["tutor_rows"]
    school_year, name = school[1], school[2]
    risk_badges = " ".join([f'<span class="badge {_school_risk_badge(tag)}">{html.escape(tag)}</span>' for tag in _school_tags_from_text(school[13])]) or '<span class="badge badge-slate">無</span>'
    next_followup_date = (school[9] or "").strip()
    next_followup_task = (school[10] or "").strip()
    status_text = (school[6] or "").strip()
    needs_followup_flag = 1 if (
        (next_followup_date and next_followup_date <= datetime.now().strftime("%Y-%m-%d"))
        or next_followup_task
        or "需要跟進" in _school_tags_from_text(school[13])
        or status_text in {"洽談中", "等待報價", "等待確認"}
    ) else 0
    contact_cards = ""
    if contacts:
        for c in contacts:
            contact_cards += f"""
            <article class="school-contact-card">
                <div class="school-contact-top">
                    <div>
                        <strong>{html.escape(c[1] or '-')}</strong>
                        <div class="muted">{html.escape(c[2] or '-')}</div>
                    </div>
                    <div class="badge {'badge-teal' if int(c[6] or 0) == 1 else 'badge-slate'}">{'主要聯絡人' if int(c[6] or 0) == 1 else '聯絡人'}</div>
                </div>
                <div class="school-section-meta" style="margin-top:10px;">
                    <div class="school-section-line"><span>電話</span><strong>{html.escape(c[3] or '-')}</strong></div>
                    <div class="school-section-line"><span>WhatsApp</span><strong>{html.escape(c[4] or '-')}</strong></div>
                    <div class="school-section-line"><span>Email</span><strong>{html.escape(c[5] or '-')}</strong></div>
                    <div class="school-section-line"><span>備註</span><strong>{html.escape(c[7] or '-')}</strong></div>
                </div>
            </article>
            """
    else:
        contact_cards = "<div class='muted'>暫時未有聯絡人。</div>"

    followup_cards = ""
    if followups:
        for f in followups:
            followup_cards += f"""
            <article class="school-followup-card">
                <div class="school-followup-head">
                    <strong>{html.escape(f[2] or '跟進紀錄')}</strong>
                    <span class="badge badge-blue">{html.escape(f[5] or '待跟進')}</span>
                </div>
                <div class="school-section-meta">
                    <div class="school-section-line"><span>日期</span><strong>{html.escape(f[1] or '-')}</strong></div>
                    <div class="school-section-line"><span>負責人</span><strong>{html.escape(f[3] or '-')}</strong></div>
                    <div class="school-section-line"><span>限期</span><strong>{html.escape(f[4] or '-')}</strong></div>
                    <div class="school-section-line"><span>摘要</span><strong>{html.escape(f[6] or '-')}</strong></div>
                    <div class="school-section-line"><span>備註</span><strong>{html.escape(f[7] or '-')}</strong></div>
                </div>
            </article>
            """
    else:
        followup_cards = "<div class='muted'>暫時未有跟進紀錄。</div>"

    schedule_cards = ""
    if schedules:
        for s in schedules:
            schedule_cards += f"""
            <article class="school-section-card">
                <h4>{html.escape(s[3] or '-')} · {html.escape(s[2] or '-')}</h4>
                <div class="school-section-meta">
                    <div class="school-section-line"><span>導師</span><strong>{html.escape(s[4] or '-')}</strong></div>
                    <div class="school-section-line"><span>上學期</span><strong>{html.escape(s[5] or '-')}</strong></div>
                    <div class="school-section-line"><span>下學期</span><strong>{html.escape(s[6] or '-')}</strong></div>
                    <div class="school-section-line"><span>備註</span><strong>{html.escape(s[7] or '-')}</strong></div>
                </div>
            </article>
            """
    else:
        schedule_cards = "<div class='muted'>暫時未有排課資料。</div>"

    class_cards = ""
    if classes:
        for c in classes:
            class_cards += f"""
            <article class="school-section-card">
                <h4>{html.escape(c[2] or '-')} · {html.escape(c[3] or '-')}</h4>
                <div class="school-section-meta">
                    <div class="school-section-line"><span>時間</span><strong>{html.escape(c[4] or '-')}</strong></div>
                    <div class="school-section-line"><span>主導師</span><strong>{html.escape(c[10] or '-')}</strong></div>
                    <div class="school-section-line"><span>班別狀態</span><strong>{'已啟用' if int(c[9] or 0) == 1 else '停用'}</strong></div>
                    <div class="school-section-line"><span>總堂數 / 已上</span><strong>{int(c[6] or 0)} / {int(c[7] or 0)}</strong></div>
                    <div class="school-section-line"><span>本月堂數</span><strong>{int(c[8] or 0)}</strong></div>
                </div>
            </article>
            """
    else:
        class_cards = "<div class='muted'>暫時未有班別資料。</div>"

    tutor_cards = ""
    if tutor_rows:
        for t in tutor_rows:
            tutor_name = "-"
            if t[2]:
                conn = sqlite3.connect(DB_PATH)
                cur = conn.cursor()
                cur.execute("SELECT name FROM teachers WHERE id=?", (t[2],))
                teacher_row = cur.fetchone()
                conn.close()
                tutor_name = teacher_row[0] if teacher_row else "-"
            tutor_cards += f"""
            <article class="school-section-card">
                <h4>{html.escape(t[3] or '導師安排')}</h4>
                <div class="school-section-meta">
                    <div class="school-section-line"><span>導師</span><strong>{html.escape(tutor_name)}</strong></div>
                    <div class="school-section-line"><span>確認狀態</span><strong>{html.escape(t[4] or '-')}</strong></div>
                    <div class="school-section-line"><span>備註</span><strong>{html.escape(t[5] or '-')}</strong></div>
                </div>
            </article>
            """
    else:
        tutor_cards = "<div class='muted'>暫時未有導師安排記錄。</div>"

    finance_cards = ""
    if finance_rows:
        for f in finance_rows:
            finance_cards += f"""
            <article class="school-section-card">
                <h4>{html.escape(f[2] or '財務資料')}</h4>
                <div class="school-section-meta">
                    <div class="school-section-line"><span>發票號碼</span><strong>{html.escape(f[3] or '-')}</strong></div>
                    <div class="school-section-line"><span>收費</span><strong>${float(f[4] or 0):,.2f}</strong></div>
                    <div class="school-section-line"><span>已收</span><strong>${float(f[5] or 0):,.2f}</strong></div>
                    <div class="school-section-line"><span>未收</span><strong>${float(f[6] or 0):,.2f}</strong></div>
                    <div class="school-section-line"><span>狀態</span><strong>{html.escape(f[7] or '-')}</strong></div>
                    <div class="school-section-line"><span>備註</span><strong>{html.escape(f[11] or '-')}</strong></div>
                </div>
            </article>
            """
    else:
        finance_cards = "<div class='muted'>暫時未有財務資料。</div>"

    contact_form = f"""
    <form method="post" action="/salary/schools/{sid}/contacts/new" class="stack">
        {_csrf_input_html(request)}
        <div class="school-filter-bar">
            <div class="field"><label>姓名</label><input name="name" required></div>
            <div class="field"><label>職位</label><input name="position" placeholder="校長 / 主任 / 行政 / 會計"></div>
            <div class="field"><label>電話</label><input name="phone"></div>
            <div class="field"><label>WhatsApp</label><input name="whatsapp"></div>
            <div class="field"><label>Email</label><input name="email"></div>
            <div class="field"><label><input type="checkbox" name="is_primary" value="1"> 主要聯絡人</label></div>
        </div>
        <div class="field"><label>備註</label><textarea name="notes" rows="2"></textarea></div>
        <div class="flex"><button type="submit" class="btn btn-primary btn-small">新增聯絡人</button></div>
    </form>
    """
    followup_form = f"""
    <form method="post" action="/salary/schools/{sid}/followups/new" class="stack">
        {_csrf_input_html(request)}
        <div class="school-filter-bar">
            <div class="field"><label>跟進日期</label><input type="date" name="followup_date" value="{html.escape(datetime.now().strftime('%Y-%m-%d'))}"></div>
            <div class="field"><label>下一步</label><input name="next_action" placeholder="WhatsApp 主任確認 9 月開班時間"></div>
            <div class="field"><label>負責人</label><input name="owner" placeholder="Mei"></div>
            <div class="field"><label>限期</label><input type="date" name="due_date"></div>
            <div class="field"><label>狀態</label><select name="status"><option value="待跟進">待跟進</option><option value="已完成">已完成</option><option value="需回覆">需回覆</option></select></div>
        </div>
        <div class="field"><label>摘要</label><textarea name="summary" rows="2"></textarea></div>
        <div class="field"><label>備註</label><textarea name="note" rows="2"></textarea></div>
        <div class="flex"><button type="submit" class="btn btn-primary btn-small">新增跟進紀錄</button></div>
    </form>
    """
    tab_buttons = """
    <div class="school-tabs">
        <button class="school-tab-btn active" type="button" data-school-tab-btn="basic">基本資料</button>
        <button class="school-tab-btn" type="button" data-school-tab-btn="contacts">聯絡人</button>
        <button class="school-tab-btn" type="button" data-school-tab-btn="classes">課程 / 班別</button>
        <button class="school-tab-btn" type="button" data-school-tab-btn="tutors">導師安排</button>
        <button class="school-tab-btn" type="button" data-school-tab-btn="followups">跟進紀錄</button>
        <button class="school-tab-btn" type="button" data-school-tab-btn="documents">文件</button>
        <button class="school-tab-btn" type="button" data-school-tab-btn="finance">財務資料</button>
    </div>
    """
    body = f"""
    <div class="detail-shell">
        <div class="detail-header">
            <div>
                <h2>{html.escape(name or '-')}</h2>
                <div class="sub">{html.escape(school[1] or '-')} · {html.escape(school[3] or '-')} · {html.escape(school[5] or '-')}</div>
                <div class="tag-row">
                    <span class="badge {_school_status_badge(school[6])}">{html.escape(school[6] or '潛在合作')}</span>
                    <span class="badge badge-teal">{int(school[7] or 0)} 班</span>
                    <span class="badge {'badge-amber' if needs_followup_flag else 'badge-slate'}">{'需要跟進' if needs_followup_flag else '暫無緊急跟進'}</span>
                </div>
            </div>
            <div class="flex">
                <a href="/salary/schools/{sid}/edit" class="btn btn-primary btn-small">編輯</a>
                <a href="/salary/schools" class="btn btn-outline btn-small">← 返回列表</a>
            </div>
        </div>
        <div class="detail-summary">
            <div class="stat-card"><div class="num">{int(school[7] or 0)}</div><div class="label">目前班數</div></div>
            <div class="stat-card"><div class="num">{html.escape(school[9] or '-' )}</div><div class="label">下次跟進</div></div>
            <div class="stat-card"><div class="num">{len(contacts)}</div><div class="label">聯絡人</div></div>
        </div>
        {tab_buttons}
        <section class="school-section active" data-school-tab="basic">
            <div class="school-section-card">
                <h4>基本資料</h4>
                <div class="school-section-meta">
                    <div class="school-section-line"><span>學年</span><strong>{html.escape(school[1] or '-')}</strong></div>
                    <div class="school-section-line"><span>地區</span><strong>{html.escape(school[3] or '-')}</strong></div>
                    <div class="school-section-line"><span>校址</span><strong>{html.escape(school[4] or '-')}</strong></div>
                    <div class="school-section-line"><span>合作類型</span><strong>{html.escape(school[5] or '-')}</strong></div>
                    <div class="school-section-line"><span>課堂日期</span><strong>{html.escape(school[18] or '-')}</strong></div>
                    <div class="school-section-line"><span>上課時間</span><strong>{html.escape(school[19] or '-')}</strong></div>
                    <div class="school-section-line"><span>導師姓名</span><strong>{html.escape(school[20] or '-')}</strong></div>
                    <div class="school-section-line"><span>導師聯絡資料</span><strong>{html.escape(school[21] or '-')}</strong></div>
                    <div class="school-section-line"><span>內部負責人</span><strong>{html.escape(school[8] or '-')}</strong></div>
                    <div class="school-section-line"><span>下一步</span><strong>{html.escape(school[10] or '-')}</strong></div>
                    <div class="school-section-line"><span>跟進負責人</span><strong>{html.escape(school[11] or '-')}</strong></div>
                    <div class="school-section-line"><span>最近跟進</span><strong>{html.escape(school[12] or '-')}</strong></div>
                    <div class="school-section-line"><span>風險標籤</span><strong>{risk_badges}</strong></div>
                    <div class="school-section-line"><span>備註</span><strong>{html.escape(school[14] or '-')}</strong></div>
                </div>
            </div>
            <div class="school-section-card">
                <h4>近期跟進摘要</h4>
                <div class="school-section-line"><span>最近一次跟進紀錄</span><strong>{html.escape(school[12] or '-')}</strong></div>
                <div class="school-section-line"><span>下次要做甚麼</span><strong>{html.escape(school[10] or '-')}</strong></div>
                <div class="school-section-line"><span>限期</span><strong>{html.escape(school[9] or '-')}</strong></div>
            </div>
        </section>
        <section class="school-section" data-school-tab="contacts">
            <div class="school-section-card">
                <h4>新增聯絡人</h4>
                {contact_form}
            </div>
            <div class="school-contact-grid">{contact_cards}</div>
        </section>
        <section class="school-section" data-school-tab="classes">
            <div class="school-section-card">
                <h4>課程 / 班別</h4>
                <div class="school-contact-grid">{schedule_cards}</div>
            </div>
            <div class="school-section-card">
                <h4>現有班別</h4>
                <div class="school-contact-grid">{class_cards}</div>
            </div>
        </section>
        <section class="school-section" data-school-tab="tutors">
            <div class="school-section-card">
                <h4>導師安排</h4>
                <div class="school-contact-grid">{tutor_cards}</div>
            </div>
        </section>
        <section class="school-section" data-school-tab="followups">
            <div class="school-section-card">
                <h4>新增跟進紀錄</h4>
                {followup_form}
            </div>
            <div class="school-contact-grid">{followup_cards}</div>
        </section>
        <section class="school-section" data-school-tab="documents">
            <div class="school-section-card">
                <h4>文件</h4>
                <div class="muted">暫時只預留文件區塊，之後可加入合約、報價單、相片同 PDF。</div>
            </div>
        </section>
        <section class="school-section" data-school-tab="finance">
            <div class="school-section-card">
                <h4>財務資料</h4>
                <div class="muted">此區只限 admin / finance 檢視。</div>
                <div class="school-contact-grid">{finance_cards}</div>
            </div>
        </section>
    </div>
    <script>
    (() => {{
        const buttons = Array.from(document.querySelectorAll('[data-school-tab-btn]'));
        const sections = Array.from(document.querySelectorAll('[data-school-tab]'));
        function setTab(tab) {{
            buttons.forEach((btn) => btn.classList.toggle('active', btn.dataset.schoolTabBtn === tab));
            sections.forEach((section) => section.classList.toggle('active', section.dataset.schoolTab === tab));
        }}
        buttons.forEach((btn) => btn.addEventListener('click', () => setTab(btn.dataset.schoolTabBtn || 'basic')));
        setTab('basic');
    }})();
    </script>
    """
    return render_salary_page(f"🏫 {name} · 學校詳情", body)


@app.post("/salary/schools/{sid}/contacts/new")
async def salary_school_contact_new(
    sid: int,
    request: Request,
    name: str = Form(""),
    position: str = Form(""),
    phone: str = Form(""),
    whatsapp: str = Form(""),
    email: str = Form(""),
    is_primary: Optional[str] = Form(None),
    notes: str = Form(""),
    user: tuple = Depends(require_roles("admin", "finance")),
):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if is_primary:
        cursor.execute("UPDATE school_contacts SET is_primary=0 WHERE school_id=?", (sid,))
    cursor.execute(
        """
        INSERT INTO school_contacts (school_id, name, position, phone, whatsapp, email, is_primary, notes, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """,
        (sid, name.strip(), position.strip(), phone.strip(), whatsapp.strip(), email.strip(), 1 if is_primary else 0, notes.strip()),
    )
    conn.commit()
    conn.close()
    _audit_action_request(request, "school_contact_create", target_type="school_contact", target_id=str(sid), actor=user, after={"name": name.strip(), "position": position.strip()})
    return RedirectResponse(f"/salary/schools/{sid}", status_code=303)


@app.post("/salary/schools/{sid}/followups/new")
async def salary_school_followup_new(
    sid: int,
    request: Request,
    followup_date: str = Form(""),
    next_action: str = Form(""),
    owner: str = Form(""),
    due_date: str = Form(""),
    status: str = Form("待跟進"),
    summary: str = Form(""),
    note: str = Form(""),
    user: tuple = Depends(require_roles("admin", "finance")),
):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO school_followups (school_id, followup_date, next_action, owner, due_date, status, summary, note, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (sid, followup_date.strip(), next_action.strip(), owner.strip(), due_date.strip(), status.strip() or "待跟進", summary.strip(), note.strip(), user[1] if len(user) > 1 else ""),
    )
    cursor.execute(
        """
        UPDATE schools
        SET next_followup_date = CASE WHEN ? <> '' THEN ? ELSE next_followup_date END,
            next_followup_task = CASE WHEN ? <> '' THEN ? ELSE next_followup_task END,
            followup_owner = CASE WHEN ? <> '' THEN ? ELSE followup_owner END,
            last_followup_note = CASE WHEN ? <> '' THEN ? ELSE last_followup_note END,
            updated_at = CURRENT_TIMESTAMP
        WHERE id=?
        """,
        (
            due_date.strip() or followup_date.strip(),
            due_date.strip() or followup_date.strip(),
            next_action.strip(),
            next_action.strip(),
            owner.strip(),
            owner.strip(),
            summary.strip() or note.strip(),
            summary.strip() or note.strip(),
            sid,
        ),
    )
    conn.commit()
    conn.close()
    _audit_action_request(request, "school_followup_create", target_type="school_followup", target_id=str(sid), actor=user, after={"next_action": next_action.strip(), "owner": owner.strip()})
    return RedirectResponse(f"/salary/schools/{sid}", status_code=303)

@app.get("/salary/teacher/{tid}")
async def salary_teacher_detail(tid: int, request: Request, user: tuple = Depends(require_roles("admin", "finance"))):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        """
        SELECT id, name, email, data_consent, english_name, stage_name, instagram, phone, area, bank_name, bank_account_number, bank_holder_name, fps_id,
               dance_styles, teaching_targets, experience, bio, car_plate, teaching_availability, extra_work, scnc_result, remarks, is_active
        FROM teachers WHERE id=?
        """,
        (tid,),
    )
    t = c.fetchone()
    if not t:
        return HTMLResponse("導師不存在", status_code=404)
    name = t[1]
    email = t[2] or "-"
    data_consent = ", ".join(_teacher_csv_list(t[3])) or "-"
    english_name = t[4] or "-"
    stage_name = t[5] or "-"
    instagram = t[6] or "-"
    phone = t[7] or "-"
    area = t[8] or "-"
    bank_name = t[9] or "-"
    bank_account_number = t[10] or "-"
    bank_holder_name = t[11] or "-"
    fps_id = t[12] or "-"
    dance_styles = ", ".join(_teacher_csv_list(t[13])) or "-"
    teaching_targets = ", ".join(_teacher_csv_list(t[14])) or "-"
    experience = t[15] or "-"
    bio = t[16] or "-"
    car_plate = t[17] or "-"
    teaching_availability = ", ".join(_teacher_csv_list(t[18])) or "-"
    extra_work = ", ".join(_teacher_csv_list(t[19])) or "-"
    scnc_result = t[20] or "-"
    remarks = t[21] or "-"

    c.execute("""
        SELECT area, school_name, weekday, lesson_time, salary_per_hour, total_lessons, completed_lessons, lessons_this_month, id
        FROM school_classes WHERE teacher_id=? AND is_active=1 ORDER BY weekday
    """, (tid,))
    classes = c.fetchall()

    c.execute("SELECT COALESCE(SUM(completed_lessons * salary_per_hour), 0) FROM school_classes WHERE teacher_id=? AND is_active=1", (tid,))
    monthly = c.fetchone()[0]
    conn.close()
    
    body_html = f"""
    <div class="detail-shell">
        <div class="detail-header">
            <div>
                <h2>{html.escape(name)}</h2>
                <div class="sub">{html.escape(email)} · {html.escape(english_name)} · {html.escape(stage_name)}</div>
                <div class="tag-row">
                    <span class="badge {'badge-teal' if classes else 'badge-slate'}">{len(classes)} 班</span>
                    <span class="badge badge-amber">本月 ${monthly:,.0f}</span>
                </div>
            </div>
            <div class="flex">
                <a href="/salary/teacher/{tid}/edit" class="btn btn-primary btn-small">編輯</a>
                <a href="/salary/teachers" class="btn btn-outline btn-small">← 返回列表</a>
            </div>
        </div>
        <div class="detail-summary">
            <div class="stat-card"><div class="num">{len(classes)}</div><div class="label">班別</div></div>
            <div class="stat-card"><div class="num">${monthly:,.0f}</div><div class="label">本月薪酬</div></div>
            <div class="stat-card"><div class="num">{html.escape(area)}</div><div class="label">居住區域</div></div>
        </div>
        <div class="detail-panel">
            <h3>導師資料</h3>
            <div class="detail-lines">
                <div class="detail-line"><span>聲明確認</span><strong>{html.escape(data_consent)}</strong></div>
                <div class="detail-line"><span>聯絡電話</span><strong>{html.escape(phone)}</strong></div>
                <div class="detail-line"><span>銀行名稱</span><strong>{html.escape(bank_name)}</strong></div>
                <div class="detail-line"><span>戶口號碼</span><strong>{_mask_bank_account(bank_account_number) or '-'}</strong></div>
                <div class="detail-line"><span>戶口持有人</span><strong>{html.escape(bank_holder_name)}</strong></div>
                <div class="detail-line"><span>FPS / PAYME</span><strong>{html.escape(fps_id)}</strong></div>
                <div class="detail-line"><span>擅長舞種</span><strong>{html.escape(dance_styles)}</strong></div>
                <div class="detail-line"><span>教授對象</span><strong>{html.escape(teaching_targets)}</strong></div>
                <div class="detail-line"><span>教學經驗</span><strong>{html.escape(experience)}</strong></div>
                <div class="detail-line"><span>車牌</span><strong>{html.escape(car_plate)}</strong></div>
                <div class="detail-line"><span>Instagram</span><strong>{html.escape(instagram)}</strong></div>
                <div class="detail-line"><span>性罪行查核</span><strong>{html.escape(scnc_result)}</strong></div>
                <div class="detail-line"><span>額外工作</span><strong>{html.escape(extra_work)}</strong></div>
                <div class="detail-line"><span>簡介</span><strong>{html.escape(bio)}</strong></div>
                <div class="detail-line"><span>備註</span><strong>{html.escape(remarks)}</strong></div>
            </div>
        </div>
        <div class="table-wrap">
            <table><thead><tr><th>地區</th><th>學校</th><th>星期 + 時間</th><th>時薪</th><th>總堂數</th><th>已上</th><th>本月</th></tr></thead><tbody>"""
    for sc in classes:
        body_html += f"<tr><td>{sc[0] or '-'}</td><td>{sc[1]}</td><td><span class='badge badge-blue'>{sc[2]} {sc[3] or ''}</span></td><td>${sc[4]:,.0f}</td><td>{sc[5]}</td><td>{sc[6]}</td><td><strong>{sc[7]}</strong></td></tr>"
    body_html += "</tbody></table></div>"
    body_html += "<div class='teacher-cards'>"
    if classes:
        for sc in classes:
            body_html += f"""
            <div class="teacher-card">
                <div class="teacher-card-top">
                    <div>
                        <div class="teacher-name">{sc[1]}</div>
                        <div class="teacher-badges"><span class='badge badge-blue'>{sc[2]} {sc[3] or ''}</span></div>
                    </div>
                </div>
                <div class="teacher-metrics">
                    <div class="metric"><span>地區</span><strong>{sc[0] or '-'}</strong></div>
                    <div class="metric"><span>時薪</span><strong>${sc[4]:,.0f}</strong></div>
                    <div class="metric"><span>總堂數</span><strong>{sc[5]}</strong></div>
                    <div class="metric"><span>已上 / 本月</span><strong>{sc[6]} / {sc[7]}</strong></div>
                </div>
            </div>"""
    else:
        body_html += "<div class='teacher-card'><div class='muted-cell' style='padding:8px 2px;'>尚未有班別資料。</div></div>"
    body_html += "</div>"
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
    csrf_html = _csrf_input_html(request)
    body_html += f"""
    <form action='/salary/calculate/{tid}' method='post' class='flex mt-2'>
        {csrf_html}
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
    return render_salary_page(f"👤 {name} 詳細", body_html)

@app.get("/salary/records")
async def salary_records(
    request: Request,
    year: str = Query(default="all"),
    month: str = Query(default="all"),
    user: tuple = Depends(require_roles("admin", "finance")),
):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    where = []
    params = []
    if year != "all":
        where.append("sr.year=?")
        params.append(int(year))
    if month != "all":
        where.append("sr.month=?")
        params.append(int(month))
    where_sql = f"WHERE {' AND '.join(where)}" if where else ""
    c.execute("""
        SELECT sr.id, t.name, sr.month, sr.year, sr.total_classes, sr.total_amount, sr.status
        FROM salary_records sr
        JOIN teachers t ON t.id = sr.teacher_id
        {where_sql}
        ORDER BY sr.year DESC, sr.month DESC, t.name
    """.format(where_sql=where_sql), params)
    rows = c.fetchall()
    conn.close()
    available_years = sorted({r[3] for r in rows}, reverse=True)
    if not available_years and year != "all":
        available_years = [int(year)]
    if not available_years:
        available_years = [datetime.now().year]
    selected_year = str(year)
    selected_month = str(month)
    year_options = "".join([
        f"<option value='{y}'{' selected' if selected_year == str(y) else ''}>{y}</option>"
        for y in available_years
    ])
    month_options = "".join([
        f"<option value='{m}'{' selected' if selected_month == str(m) else ''}>{m:02d}</option>"
        for m in range(1, 13)
    ])
    filter_label = "全部月份"
    if year != "all" and month != "all":
        filter_label = _format_salary_month_label(int(year), int(month))
    elif year != "all":
        filter_label = f"{int(year)}年"
    manual_year = int(year) if year != "all" else datetime.now().year
    manual_month = int(month) if month != "all" else datetime.now().month
    manual_year_options = "".join([
        f"<option value='{y}'{' selected' if manual_year == y else ''}>{y}</option>"
        for y in range(datetime.now().year - 2, datetime.now().year + 2)
    ])
    manual_month_options = "".join([
        f"<option value='{m}'{' selected' if manual_month == m else ''}>{m:02d}</option>"
        for m in range(1, 13)
    ])
    manual_status_options = """
        <option value="pending" selected>待處理</option>
        <option value="paid">已支付</option>
    """
    html = f"""
    <div class="alert-info">📅 目前顯示：{filter_label}</div>
    <form method="get" action="/salary/records" class="flex mt-2">
        <div>
            <label style="display:block;margin-bottom:4px;">年份</label>
            <select name="year" style="padding:8px 10px;border:1px solid #d1d5db;border-radius:8px;">
                <option value="all"{' selected' if selected_year == 'all' else ''}>全部</option>
                {year_options}
            </select>
        </div>
        <div>
            <label style="display:block;margin-bottom:4px;">月份</label>
            <select name="month" style="padding:8px 10px;border:1px solid #d1d5db;border-radius:8px;">
                <option value="all"{' selected' if selected_month == 'all' else ''}>全部</option>
                {month_options}
            </select>
        </div>
        <div style="align-self:end;">
            <button type="submit" class="btn btn-primary btn-small">篩選</button>
        </div>
        <div style="align-self:end;">
            <a href="/salary/records" class="btn btn-outline btn-small">清除</a>
        </div>
    </form>
    <div class="report-box" style="margin-top:16px;">
        <div class="report-title">手動新增 / 更新月薪</div>
        <form method="post" action="/salary/records/manual-save" class="stack" style="margin-top:10px;">
            {_csrf_input_html(request)}
            <div class="flex">
                <div>
                    <label style="display:block;margin-bottom:4px;">導師</label>
                    <select name="teacher_id" style="min-width:220px;padding:8px 10px;border:1px solid #d1d5db;border-radius:8px;">
                        {_salary_teacher_options_html()}
                    </select>
                </div>
                <div>
                    <label style="display:block;margin-bottom:4px;">年份</label>
                    <select name="year" style="padding:8px 10px;border:1px solid #d1d5db;border-radius:8px;">{manual_year_options}</select>
                </div>
                <div>
                    <label style="display:block;margin-bottom:4px;">月份</label>
                    <select name="month" style="padding:8px 10px;border:1px solid #d1d5db;border-radius:8px;">{manual_month_options}</select>
                </div>
                <div>
                    <label style="display:block;margin-bottom:4px;">堂數</label>
                    <input name="total_classes" type="number" min="0" step="1" value="0" style="width:100px;padding:8px 10px;border:1px solid #d1d5db;border-radius:8px;">
                </div>
                <div>
                    <label style="display:block;margin-bottom:4px;">金額</label>
                    <input name="total_amount" type="number" min="0" step="0.01" value="0" style="width:140px;padding:8px 10px;border:1px solid #d1d5db;border-radius:8px;">
                </div>
                <div>
                    <label style="display:block;margin-bottom:4px;">狀態</label>
                    <select name="status" style="padding:8px 10px;border:1px solid #d1d5db;border-radius:8px;">{manual_status_options}</select>
                </div>
            </div>
            <div class="muted">適合手動補錄、改數、臨時出糧。儲存後會覆蓋同一導師同一年月的記錄。</div>
            <div class="flex">
                <button type="submit" class="btn btn-primary btn-small">儲存月薪</button>
                <a href="/salary/payroll?year={manual_year}&month={manual_month}" class="btn btn-outline btn-small">去月薪頁批量編輯</a>
            </div>
        </form>
    </div>
    """
    if rows:
        html += "<table><thead><tr><th>導師</th><th>月份</th><th>堂數</th><th>金額</th><th>狀態</th></tr></thead><tbody>"
        for r in rows:
            badge = "badge-green" if r[6] == "paid" else "badge-blue"
            s = "✅ 已支付" if r[6] == "paid" else "⏳ 待處理"
            html += f"<tr><td>{r[1]}</td><td>{_format_salary_month_label(r[3], r[2])}</td><td>{r[4]}</td><td><strong>${r[5]:,.0f}</strong></td><td><span class='badge {badge}'>{s}</span></td></tr>"
        html += "</tbody></table>"
    else:
        html += "<p style='color:#666;padding:20px;text-align:center;'>尚未有薪酬記錄，請先從 Dashboard 點選導師計算或匯入每月薪金 CSV。</p>"
    return render_salary_page("📋 薪酬記錄", html)


@app.post("/salary/records/manual-save")
async def salary_records_manual_save(
    request: Request,
    teacher_id: int = Form(..., ge=1),
    year: int = Form(..., ge=2000, le=2100),
    month: int = Form(..., ge=1, le=12),
    total_classes: int = Form(0, ge=0),
    total_amount: str = Form("0"),
    status: str = Form("pending"),
    user: tuple = Depends(require_roles("admin", "finance")),
):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM teachers WHERE id=?", (teacher_id,))
    teacher_row = cursor.fetchone()
    if not teacher_row:
        conn.close()
        return HTMLResponse("導師不存在", status_code=404)
    amount_val = float(str(total_amount or 0).replace(",", "").strip() or 0)
    status_val = "paid" if str(status).strip().lower() == "paid" else "pending"
    cursor.execute(
        """
        INSERT INTO salary_records (teacher_id, month, year, total_classes, total_amount, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(teacher_id, year, month) DO UPDATE SET
            total_classes=excluded.total_classes,
            total_amount=excluded.total_amount,
            status=excluded.status,
            created_at=CURRENT_TIMESTAMP
        """,
        (teacher_id, int(month), int(year), int(total_classes), amount_val, status_val),
    )
    conn.commit()
    conn.close()
    _audit_action_request(
        request,
        "salary_manual_save",
        target_type="salary_record",
        target_id=f"{teacher_id}:{year}-{month:02d}",
        actor=user,
        after={
            "teacher_id": teacher_id,
            "teacher_name": teacher_row[0],
            "year": year,
            "month": month,
            "total_classes": int(total_classes),
            "total_amount": amount_val,
            "status": status_val,
        },
    )
    month_label = _format_salary_month_label(year, month)
    return HTMLResponse(
        f"{SALARY_HEADER}<div class='container'><div class='card'><h3>✅ 月薪已儲存</h3><p>{html.escape(teacher_row[0])} · {month_label} · ${amount_val:,.2f}</p><br><a href='/salary/records?year={year}&month={month}' class='btn btn-primary'>返回薪酬記錄</a> <a href='/salary/records' class='btn btn-outline'>查看全部記錄</a></div></div>{SALARY_FOOTER}"
    )

@app.post("/salary/calculate/{tid}")
async def salary_calculate(
    tid: int,
    request: Request,
    month: int = Form(..., ge=1, le=12),
    year: int = Form(..., ge=2000, le=2100),
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
    _audit_action_request(request, "salary_calculate", target_type="salary_record", target_id=f"{tid}:{year}-{month:02d}", actor=user, after={"teacher_id": tid, "year": year, "month": month, "total_classes": total_classes, "total_amount": total_amount})
    
    month_label = _format_salary_month_label(year, month)
    html = f"""
    <div class="alert-info">✅ {t[1]} 的 {month_label} 薪酬已計算並儲存。</div>
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
    return render_salary_page(f"📊 {t[1]} {month_label} 薪酬計算", html)

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
async def db_query(request: Request, service_user: dict = Depends(require_service_auth)):
    payload = await request.json()
    sql = (payload.get("sql") or "").strip()
    params = payload.get("params") or []
    fetch = bool(payload.get("fetch", True))
    actor = {"id": None, "username": service_user.get("username"), "display_name": "DB Bridge", "role": "admin"}
    if not sql:
        _audit_action_request(request, "raw_sql_bridge", target_type="bridge", target_id="", result="denied", actor=actor, metadata={"reason": "missing_sql"})
        raise HTTPException(status_code=400, detail="SQL is required")
    sql_body = sql.rstrip().rstrip(";").strip()
    upper = sql_body.upper()
    if ";" in sql_body:
        _audit_action_request(request, "raw_sql_bridge", target_type="bridge", target_id="", result="denied", actor=actor, metadata={"reason": "multi_statement"})
        raise HTTPException(status_code=403, detail="Forbidden")
    if not re.match(r"^(SELECT|WITH)\b", upper):
        _audit_action_request(request, "raw_sql_bridge", target_type="bridge", target_id="", result="denied", actor=actor, metadata={"reason": "write_not_allowed"})
        raise HTTPException(status_code=403, detail="Forbidden")
    forbidden_tokens = ("ATTACH", "DETACH", "PRAGMA", "VACUUM", "DROP", "ALTER", "CREATE", "INSERT", "UPDATE", "DELETE", "REPLACE", "REINDEX", "TRIGGER")
    if any(token in upper for token in forbidden_tokens):
        _audit_action_request(request, "raw_sql_bridge", target_type="bridge", target_id="", result="denied", actor=actor, metadata={"reason": "forbidden_token"})
        raise HTTPException(status_code=403, detail="Forbidden")
    allowed_tables = {"app_users", "app_sessions", "announcements", "common_clients", "form_presets", "records", "teachers", "school_classes", "salary_records"}
    table_refs = set(re.findall(r"\b(?:FROM|JOIN)\s+([A-Z_][A-Z0-9_]*)", upper))
    if any(table.lower() not in allowed_tables for table in table_refs):
        _audit_action_request(request, "raw_sql_bridge", target_type="bridge", target_id="", result="denied", actor=actor, metadata={"reason": "table_not_allowed", "tables": sorted(table_refs)})
        raise HTTPException(status_code=403, detail="Forbidden")
    if not isinstance(params, list):
        _audit_action_request(request, "raw_sql_bridge", target_type="bridge", target_id="", result="denied", actor=actor, metadata={"reason": "params_not_list"})
        raise HTTPException(status_code=400, detail="Invalid params")

    conn = _REAL_SQLITE_CONNECT(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute(sql_body, params)
        rows = []
        columns = []
        if fetch and cursor.description:
            columns = [col[0] for col in cursor.description]
            rows = cursor.fetchall()
        response = {
            "ok": True,
            "rows": rows,
            "columns": columns,
            "rowcount": cursor.rowcount,
            "lastrowid": cursor.lastrowid,
        }
        _audit_action_request(request, "raw_sql_bridge", target_type="bridge", target_id="", result="ok", actor=actor, metadata={"fetch": fetch, "rowcount": cursor.rowcount, "columns": columns[:20], "tables": sorted(table_refs)})
        return response
    except Exception:
        _audit_action_request(request, "raw_sql_bridge", target_type="bridge", target_id="", result="error", actor=actor, metadata={"error": "sql_failed"})
        raise HTTPException(status_code=500, detail="Database query failed")
    finally:
        conn.close()

# Health check must be registered before the blocking __main__ runner in script mode.
@app.get("/healthz")
async def healthz():
    return {"ok": True, "app": APP_NAME}

# =========================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    if uvicorn is None:
        raise RuntimeError("uvicorn is not installed in this environment")
    uvicorn.run(app, host="0.0.0.0", port=port)
