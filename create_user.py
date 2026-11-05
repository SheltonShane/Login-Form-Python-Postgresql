"""
Create (or reset) a login account.

Usage:  python create_user.py <username>
You will be asked for the password, so it never appears in your shell history.
"""

import getpass
import os
import sys

import psycopg2
from dotenv import load_dotenv

load_dotenv()

if len(sys.argv) != 2:
    sys.exit("Usage: python create_user.py <username>")

username = sys.argv[1].strip()
password = getpass.getpass("Password: ")
if len(password) < 8:
    sys.exit("Use a password of at least 8 characters.")
if password != getpass.getpass("Repeat password: "):
    sys.exit("Passwords do not match.")

conn = psycopg2.connect(
    host=os.getenv("DB_HOST", "localhost"),
    port=os.getenv("DB_PORT", "5432"),
    dbname=os.environ["DB_NAME"],
    user=os.environ["DB_USER"],
    password=os.environ["DB_PASSWORD"],
)
try:
    with conn, conn.cursor() as cur:      # "with conn" commits on success
        # gen_salt('bf') makes a fresh bcrypt salt; crypt() hashes the password.
        # If the username already exists, its password is replaced.
        cur.execute(
            """
            INSERT INTO users (username, password_hash)
            VALUES (%s, crypt(%s, gen_salt('bf')))
            ON CONFLICT (username)
            DO UPDATE SET password_hash = EXCLUDED.password_hash
            """,
            (username, password),
        )
    print(f"User '{username}' saved.")
finally:
    conn.close()
