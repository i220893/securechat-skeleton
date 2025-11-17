"""
MySQL-backed user store for SecureChat.

- Uses salted SHA-256 password hashes.
- Connection parameters are read from environment variables (via python-dotenv).

Expected .env values (create .env in project root):

    DB_HOST=127.0.0.1
    DB_PORT=3306
    DB_USER=scuser
    DB_PASSWORD=scpass
    DB_NAME=securechat

MySQL schema (created by `python -m app.storage.db --init`):

    CREATE TABLE users (
        email     VARCHAR(255) PRIMARY KEY,
        username  VARCHAR(255) UNIQUE NOT NULL,
        salt      VARBINARY(16) NOT NULL,
        pwd_hash  CHAR(64) NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

import argparse
import hmac
import os
import secrets
from typing import Optional, Dict, Any

import pymysql
from dotenv import load_dotenv

from app.common.utils import sha256_hex

# Load .env from project root
load_dotenv()

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "scuser")
DB_PASSWORD = os.getenv("DB_PASSWORD", "scpass")
DB_NAME = os.getenv("DB_NAME", "securechat")


# ---------- Low-level connection helper ----------

def get_connection() -> pymysql.connections.Connection:
    """
    Open a new connection to the SecureChat MySQL database.

    Uses credentials from environment variables. Autocommit is enabled so
    each statement is committed immediately.
    """
    return pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        autocommit=True,
        cursorclass=pymysql.cursors.DictCursor,
    )


# ---------- Password hashing helpers ----------

def generate_salt(length: int = 16) -> bytes:
    """Return a cryptographically secure random salt."""
    return secrets.token_bytes(length)


def hash_password(password: str, salt: bytes) -> str:
    """
    Compute salted SHA-256 hash of the password.

    Stored format in DB:
        salt:     raw bytes (VARBINARY(16))
        pwd_hash: lowercase hex SHA-256(salt || password)
    """
    if isinstance(password, str):
        pw_bytes = password.encode("utf-8")
    else:
        pw_bytes = password

    return sha256_hex(salt + pw_bytes)


# ---------- High-level user operations ----------

def init_db(drop_first: bool = False) -> None:
    """
    Create the `users` table if it does not exist.

    If drop_first=True, the table is dropped and recreated.
    Use this only for local development/testing.
    """
    create_table_sql = """
    CREATE TABLE IF NOT EXISTS users (
        email     VARCHAR(255) PRIMARY KEY,
        username  VARCHAR(255) UNIQUE NOT NULL,
        salt      VARBINARY(16) NOT NULL,
        pwd_hash  CHAR(64) NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """

    drop_table_sql = "DROP TABLE IF EXISTS users;"

    with get_connection() as conn:
        with conn.cursor() as cur:
            if drop_first:
                cur.execute(drop_table_sql)
            cur.execute(create_table_sql)


def create_user(email: str, username: str, password: str) -> bool:
    """
    Register a new user.

    - Generates a fresh random salt.
    - Computes salted SHA-256 hash.
    - Inserts into `users` table.

    Returns:
        True  -> user created
        False -> email or username already exists (constraint violation)
    """
    salt = generate_salt()
    pwd_hash = hash_password(password, salt)

    sql = """
        INSERT INTO users (email, username, salt, pwd_hash)
        VALUES (%s, %s, %s, %s)
    """

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (email, username, salt, pwd_hash))
        return True
    except pymysql.err.IntegrityError:
        # Duplicate email or username
        return False


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """
    Fetch a user row by email.

    Returns:
        dict with keys: email, username, salt, pwd_hash
        or None if no such user exists.
    """
    sql = "SELECT email, username, salt, pwd_hash FROM users WHERE email = %s"

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (email,))
            row = cur.fetchone()
            return row or None


def verify_user(email: str, password: str) -> bool:
    """
    Verify user credentials.

    - Looks up stored salt and pwd_hash for given email.
    - Recomputes salted SHA-256 hash from provided password.
    - Uses constant-time comparison to avoid timing attacks.

    Returns:
        True  -> credentials valid
        False -> user not found OR password mismatch
    """
    user = get_user_by_email(email)
    if not user:
        return False

    salt: bytes = user["salt"]
    stored_hash: str = user["pwd_hash"]

    candidate_hash = hash_password(password, salt)
    return hmac.compare_digest(candidate_hash, stored_hash)


# ---------- CLI entrypoint (python -m app.storage.db) ----------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SecureChat DB helper")
    parser.add_argument(
        "--init",
        action="store_true",
        help="Create the `users` table if it does not exist.",
    )
    parser.add_argument(
        "--drop",
        action="store_true",
        help="Drop the `users` table before recreating it (DANGEROUS, dev only).",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    if args.init:
        print("[db] Initializing database schema...")
        init_db(drop_first=args.drop)
        print("[db] Done.")
    else:
        print("Usage: python -m app.storage.db --init [--drop]")


if __name__ == "__main__":
    main()
