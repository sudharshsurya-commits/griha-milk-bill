import os
import json
import secrets
import hashlib
from datetime import datetime, timedelta
import psycopg2
from psycopg2.extras import RealDictCursor

FALLBACK_STORE_PATH = os.path.join("/tmp", "griha_auth.json")

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

def get_db():
    """
    Returns a new PostgreSQL connection with RealDictCursor.
    Reads DATABASE_URL dynamically. Returns None if unconfigured or unreachable.
    """
    db_url = os.environ.get("DATABASE_URL", "").strip()
    if not db_url:
        return None
    if db_url.startswith("postgres://"):
        db_url = "postgresql://" + db_url[11:]
    try:
        conn = psycopg2.connect(db_url, cursor_factory=RealDictCursor, connect_timeout=5)
        conn.autocommit = False
        return conn
    except Exception as e:
        print("[DB CONNECT ERROR]", e)
        return None

def ensure_db_initialized(conn):
    """
    Ensures all PostgreSQL tables and performance indexes exist.
    Auto-seeds default admin ('admin' / 'admin123') if missing.
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
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token VARCHAR(100) PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
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
            # Check if any user exists or admin exists
            cur.execute("SELECT id, username, password_hash, salt FROM users WHERE username = 'admin'")
            admin_row = cur.fetchone()
            if not admin_row:
                cur.execute("SELECT COUNT(*) as cnt FROM users")
                cnt_row = cur.fetchone()
                if not cnt_row or cnt_row["cnt"] == 0:
                    salt = secrets.token_hex(16)
                    pwd_hash = hash_password("admin123", salt)
                    cur.execute(
                        "INSERT INTO users (username, password_hash, salt) VALUES (%s, %s, %s)",
                        ("admin", pwd_hash, salt)
                    )
            conn.commit()
    except Exception as e:
        print("[DB INIT ERROR]", e)
        try:
            conn.rollback()
        except Exception:
            pass

def _load_fallback_store():
    """Loads fallback credentials & session store from /tmp."""
    if os.path.exists(FALLBACK_STORE_PATH):
        try:
            with open(FALLBACK_STORE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    # Default seeded user
    default_salt = "4155fcee3ff8bdbfe4233518a6cef5c7"
    default_hash = hash_password("admin123", default_salt)
    data = {
        "users": [
            {
                "id": 1,
                "username": "admin",
                "password_hash": default_hash,
                "salt": default_salt
            }
        ],
        "sessions": {}
    }
    _save_fallback_store(data)
    return data

def _save_fallback_store(data):
    """Saves fallback credentials & session store to /tmp."""
    try:
        with open(FALLBACK_STORE_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception as e:
        print("[FALLBACK SAVE ERROR]", e)

def authenticate_request(headers):
    """
    Extracts Bearer token or cookie from request headers and verifies against active sessions.
    Checks PostgreSQL primary database first; falls back to serverless session store if DB is unreachable.
    """
    auth = headers.get("authorization", headers.get("Authorization", ""))
    token = ""
    if auth.startswith("Bearer "):
        token = auth[7:].strip()
    else:
        cookie = headers.get("cookie", headers.get("Cookie", ""))
        for part in cookie.split(";"):
            if "griha_token=" in part:
                token = part.split("griha_token=")[1].strip()
                break

    if not token:
        return None

    # 1. Try PostgreSQL
    conn = get_db()
    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT u.id, u.username FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.token = %s AND s.expires_at > CURRENT_TIMESTAMP",
                    (token,)
                )
                row = cur.fetchone()
                if row:
                    return {"id": row["id"], "username": row["username"], "token": token}
        except Exception as e:
            print("[AUTH DB ERROR]", e)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    # 2. Resilient Fallback Store
    store = _load_fallback_store()
    sess = store.get("sessions", {}).get(token)
    if sess:
        exp_str = sess.get("expires_at", "")
        try:
            exp_dt = datetime.fromisoformat(exp_str)
            if exp_dt > datetime.utcnow():
                return {"id": sess["user_id"], "username": sess["username"], "token": token}
        except Exception:
            return {"id": sess["user_id"], "username": sess["username"], "token": token}

    return None
