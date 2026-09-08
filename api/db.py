import os
import json
import secrets
import hashlib
from datetime import datetime, timedelta
import psycopg2
from psycopg2.extras import RealDictCursor

DATABASE_URL = os.environ.get("DATABASE_URL", "")

def get_db():
    """Returns a new connection with RealDictCursor for dict-like column access."""
    if not DATABASE_URL:
        raise ValueError("DATABASE_URL environment variable is missing or empty. Please set it in Vercel settings.")
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    conn.autocommit = False
    return conn

def hash_password(password: str, salt: str) -> str:
    """Identical PBKDF2-SHA256 password hashing as original server.py."""
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

def authenticate_request(headers):
    """
    Extracts Bearer token or cookie from request headers and verifies against sessions table.
    Explicitly closes connection in try/finally to prevent connection leakage.
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

    conn = None
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT u.id, u.username FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.token = %s AND s.expires_at > CURRENT_TIMESTAMP",
                (token,)
            )
            row = cur.fetchone()
            if row:
                return {"id": row["id"], "username": row["username"], "token": token}
    except Exception as e:
        print("[AUTH ERROR]", e)
        return None
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

    return None
