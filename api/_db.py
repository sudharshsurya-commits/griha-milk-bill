import os
import json
import secrets
import hashlib
import hmac
import time
from datetime import datetime, timedelta

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False

SECRET_KEY = os.environ.get("SESSION_SECRET", "griha-production-auth-secret-key-2026")
FALLBACK_STORE_PATH = os.path.join("/tmp", "griha_auth_v2.json")

# ─── Password helpers ─────────────────────────────────────────────────────────

def hash_password(password: str, salt: str) -> str:
    """PBKDF2-SHA256 password hashing with 100,000 iterations."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100000
    ).hex()

def verify_password(stored_hash: str, salt: str, password: str) -> bool:
    """Constant-time password verification to prevent timing attacks."""
    calc = hash_password(password, salt)
    return secrets.compare_digest(stored_hash, calc)

# ─── HMAC token helpers ───────────────────────────────────────────────────────

def create_session_token(user_id: int, username: str, role: str) -> str:
    """Creates a cryptographically signed HMAC-SHA256 session token with role."""
    expires = int(time.time()) + (30 * 86400)  # 30 days
    data = f"{user_id}:{username}:{role}:{expires}"
    sig = hmac.new(SECRET_KEY.encode("utf-8"), data.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{data}:{sig}"

def verify_token_signature(token: str):
    """
    Verifies HMAC signature of a session token.
    Supports new format (id:username:role:expires:sig) and
    legacy format (id:username:expires:sig) — legacy treated as 'admin'.
    """
    if not token:
        return None
    parts = token.split(":")
    try:
        if len(parts) == 5:
            uid_s, uname, role, exp_s, sig = parts
            data = f"{uid_s}:{uname}:{role}:{exp_s}"
            expected_sig = hmac.new(SECRET_KEY.encode("utf-8"), data.encode("utf-8"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, expected_sig):
                return None
            if int(exp_s) < int(time.time()):
                return None
            return {"id": int(uid_s), "username": uname, "role": role, "token": token, "expires": int(exp_s)}
        if len(parts) == 4:
            uid_s, uname, exp_s, sig = parts
            data = f"{uid_s}:{uname}:{exp_s}"
            expected_sig = hmac.new(SECRET_KEY.encode("utf-8"), data.encode("utf-8"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, expected_sig):
                return None
            if int(exp_s) < int(time.time()):
                return None
            return {"id": int(uid_s), "username": uname, "role": "admin", "token": token, "expires": int(exp_s)}
    except Exception:
        pass
    return None

# ─── Database connection ──────────────────────────────────────────────────────

def get_db():
    """
    Returns a new PostgreSQL connection with RealDictCursor.
    Reads DATABASE_URL dynamically. Returns None if unconfigured or unreachable.
    """
    if not HAS_PSYCOPG2:
        return None
    db_url = os.environ.get("DATABASE_URL", "").strip()
    if not db_url:
        return None
    if db_url.startswith("postgres://"):
        db_url = "postgresql://" + db_url[11:]
    try:
        conn = psycopg2.connect(db_url, cursor_factory=RealDictCursor, connect_timeout=4)
        conn.autocommit = False
        return conn
    except Exception as e:
        print("[DB CONNECT ERROR]", e)
        return None

def ensure_db_initialized(conn):
    """
    Ensures all PostgreSQL tables exist.
    Auto-seeds admin (admin/admin123) and normal user (user/user123).
    """
    if not conn:
        return
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(100) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    salt VARCHAR(100) NOT NULL,
                    role VARCHAR(20) NOT NULL DEFAULT 'user',
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token VARCHAR(255) PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    role VARCHAR(20) NOT NULL DEFAULT 'user',
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
                );
                CREATE TABLE IF NOT EXISTS settings (
                    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                    brand_name VARCHAR(255) DEFAULT 'GRIHA',
                    tagline VARCHAR(255) DEFAULT 'Feel The Quality',
                    care_no VARCHAR(100) DEFAULT '+91 99999 99999',
                    default_rate NUMERIC DEFAULT 22,
                    upi_id VARCHAR(255) DEFAULT 'griha@upi',
                    qr_mode VARCHAR(50) DEFAULT 'generated',
                    logo_data TEXT,
                    qr_data TEXT,
                    layout_data TEXT,
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS bills (
                    id VARCHAR(100) PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    cust_name VARCHAR(255) NOT NULL,
                    cust_phone VARCHAR(100),
                    month VARCHAR(100),
                    bill_no VARCHAR(100),
                    bill_date VARCHAR(100),
                    total_days INTEGER,
                    hold_days INTEGER,
                    delivery_days INTEGER,
                    daily_qty NUMERIC,
                    milk_unit VARCHAR(50),
                    milk_rate NUMERIC,
                    milk_amount NUMERIC,
                    items_json TEXT,
                    items_total NUMERIC,
                    receivable NUMERIC,
                    payable NUMERIC,
                    net_total NUMERIC,
                    raw_data TEXT,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS customers (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    name VARCHAR(255) NOT NULL,
                    phone VARCHAR(100),
                    default_qty NUMERIC DEFAULT 2,
                    default_unit VARCHAR(50) DEFAULT 'Nazhi',
                    default_rate NUMERIC DEFAULT 22,
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(user_id, name)
                );
            """)

            try:
                cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) NOT NULL DEFAULT 'user'")
            except Exception:
                pass

            try:
                cur.execute("ALTER TABLE sessions ADD COLUMN IF NOT EXISTS role VARCHAR(20) NOT NULL DEFAULT 'user'")
            except Exception:
                pass

            try:
                cur.execute("ALTER TABLE sessions ALTER COLUMN token TYPE VARCHAR(255)")
            except Exception:
                pass

            # Seed admin
            cur.execute("SELECT id FROM users WHERE username = 'admin'")
            if cur.fetchone():
                cur.execute("UPDATE users SET role = 'admin' WHERE username = 'admin'")
            else:
                salt = secrets.token_hex(16)
                cur.execute(
                    "INSERT INTO users (username, password_hash, salt, role) VALUES (%s, %s, %s, 'admin')",
                    ("admin", hash_password("admin123", salt), salt)
                )

            # Seed user
            cur.execute("SELECT id FROM users WHERE username = 'user'")
            if not cur.fetchone():
                salt = secrets.token_hex(16)
                cur.execute(
                    "INSERT INTO users (username, password_hash, salt, role) VALUES (%s, %s, %s, 'user')",
                    ("user", hash_password("user123", salt), salt)
                )

            conn.commit()
    except Exception as e:
        print("[DB INIT ERROR]", e)
        try:
            conn.rollback()
        except Exception:
            pass

# ─── Fallback store (Redis-free persistence in /tmp) ─────────────────────────

def _make_default_store():
    admin_salt = "4155fcee3ff8bdbfe4233518a6cef5c7"
    user_salt = "b26c7fa6ef3b4d8a9f1e5c02d7a38491"
    return {
        "users": [
            {
                "id": 1,
                "username": "admin",
                "role": "admin",
                "password_hash": hash_password("admin123", admin_salt),
                "salt": admin_salt
            },
            {
                "id": 2,
                "username": "user",
                "role": "user",
                "password_hash": hash_password("user123", user_salt),
                "salt": user_salt
            }
        ],
        "revoked_tokens": [],
        "bills": {},
        "settings": {},
        "customers": {}
    }

def _load_fallback_store():
    """Loads credentials, bills, settings & revoked token list from /tmp."""
    if os.path.exists(FALLBACK_STORE_PATH):
        try:
            with open(FALLBACK_STORE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            users = data.get("users", [])
            has_admin = any(u.get("role") == "admin" for u in users)
            has_user = any(u.get("role") == "user" for u in users)
            if has_admin and has_user:
                return data
        except Exception:
            pass
    data = _make_default_store()
    _save_fallback_store(data)
    return data

def _save_fallback_store(data):
    """Saves fallback data to /tmp."""
    try:
        with open(FALLBACK_STORE_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception as e:
        print("[FALLBACK SAVE ERROR]", e)

# ─── Request authentication ───────────────────────────────────────────────────

def authenticate_request(headers, required_role=None):
    """
    Extracts Bearer/cookie token, verifies authentication, and optionally checks role.
    returns user dict {id, username, role, token} or None.
    """
    auth = headers.get("authorization", headers.get("Authorization", ""))
    token = ""
    if auth.startswith("Bearer "):
        token = auth[7:].strip()
    else:
        cookie = headers.get("cookie", headers.get("Cookie", ""))
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("griha_token="):
                token = part[len("griha_token="):]
                break

    if not token:
        return None

    verified = verify_token_signature(token)

    # 1. PostgreSQL check if connected
    conn = get_db()
    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """SELECT u.id, u.username, u.role
                       FROM sessions s
                       JOIN users u ON s.user_id = u.id
                       WHERE s.token = %s AND s.expires_at > CURRENT_TIMESTAMP""",
                    (token,)
                )
                row = cur.fetchone()
                if row:
                    user_data = {"id": row["id"], "username": row["username"], "role": row["role"], "token": token}
                    if required_role and user_data["role"] != required_role:
                        return None
                    return user_data
                elif verified:
                    return None
        except Exception as e:
            print("[AUTH DB ERROR]", e)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    # 2. Resilient fallback check
    if verified:
        store = _load_fallback_store()
        if token in store.get("revoked_tokens", []):
            return None
        role = verified.get("role", "user")
        user_data = {"id": verified["id"], "username": verified["username"], "role": role, "token": token}
        if required_role and user_data["role"] != required_role:
            return None
        return user_data

    return None
