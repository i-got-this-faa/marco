#!/usr/bin/env python3
"""
Start a local testing instance of the Marco mail server.

Creates a self-contained test environment with:
  - Temporary data directory (DB, blobs, config)
  - Pre-populated admin account, test domain, and test users
  - All services on localhost with non-privileged ports
  - Console output with connection info for polo and other tools

Usage:
  # Default: ephemeral, cleans up on Ctrl+C
  python scripts/serve-test.py

  # Keep data directory for debugging
  python scripts/serve-test.py --keep-data

  # Use a specific directory
  python scripts/serve-test.py --data-dir /tmp/marco-test

  # Custom ports (useful when running alongside other services)
  python scripts/serve-test.py --smtp-port 10025 --admin-port 18080

  # Supply your own admin password
  python scripts/serve-test.py --admin-password hunter2

  # Allow remote connections (bind 0.0.0.0 instead of 127.0.0.1)
  python scripts/serve-test.py --bind 0.0.0.0

Environment variables (overridden by flags):
  MARCO_TEST_DATA_DIR     — persistent test directory
  MARCO_ADMIN_EMAIL       — admin account email
  MARCO_ADMIN_PASSWORD    — admin account password
"""

import argparse
import atexit
import os
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from contextlib import suppress
from pathlib import Path

# Add scripts dir to path so we can import marco_api.
SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

from marco_api import MarcoAPI, MarcoError

# ------------------------------------------------------------------
# Defaults
# ------------------------------------------------------------------

DEFAULT_PORTS = {
    "smtp": 10025,
    "submission": 10587,
    "imap": 10143,
    "imaps": 10993,
    "pop3": 10110,
    "admin": 18080,
}

ADMIN_EMAIL = "admin@test.local"
ADMIN_PASSWORD = "admin1234"
TEST_DOMAIN = "test.local"
TEST_USERS = [
    ("alice@test.local", "alice1234"),
    ("bob@test.local", "bob1234"),
    ("carol@test.local", "carol1234"),
]

# Schema migration DDL (matching pkg/storage/schema.go migrations v1–v5).
# Applied in order to a fresh DB so the Go server sees a consistent schema.
SCHEMA_SQL = [
    # Migration 1 — core tables
    """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS domains (
        name TEXT PRIMARY KEY,
        is_active INTEGER NOT NULL DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS aliases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source TEXT NOT NULL,
        destination TEXT NOT NULL,
        domain TEXT NOT NULL,
        UNIQUE(source, domain)
    );

    CREATE TABLE IF NOT EXISTS mailboxes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        UNIQUE(user_id, name)
    );

    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
        uid INTEGER NOT NULL,
        blob_key TEXT NOT NULL,
        size INTEGER NOT NULL DEFAULT 0,
        flags INTEGER NOT NULL DEFAULT 0,
        internal_date INTEGER NOT NULL,
        from_addr TEXT,
        to_addr TEXT,
        subject TEXT,
        UNIQUE(mailbox_id, uid)
    );

    CREATE INDEX IF NOT EXISTS idx_messages_mailbox_uid ON messages(mailbox_id, uid);

    CREATE TABLE IF NOT EXISTS attachments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
        blob_key TEXT NOT NULL,
        filename TEXT,
        mime_type TEXT,
        size INTEGER NOT NULL DEFAULT 0,
        sha256 TEXT,
        refcount INTEGER NOT NULL DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS queue (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
        rcpt_to TEXT NOT NULL,
        next_attempt INTEGER NOT NULL,
        attempt_count INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'pending'
    );

    CREATE INDEX IF NOT EXISTS idx_queue_next_attempt ON queue(next_attempt);

    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        expires_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER NOT NULL,
        user_id INTEGER,
        event TEXT NOT NULL,
        details TEXT
    );

    CREATE TABLE IF NOT EXISTS blobs (
        key TEXT PRIMARY KEY,
        data BLOB NOT NULL,
        size INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL
    );
    """,
    # Migration 2 — greylist
    """CREATE TABLE IF NOT EXISTS greylist (
        ip TEXT NOT NULL,
        from_addr TEXT NOT NULL,
        to_addr TEXT NOT NULL,
        first_seen INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,
        passed INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (ip, from_addr, to_addr)
    );""",
    # Migration 3 — FTS5 search index
    """
    CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
        subject, from_addr, to_addr, body,
        content='',
        tokenize='porter unicode61'
    );

    CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
        INSERT INTO messages_fts(rowid, subject, from_addr, to_addr)
        VALUES (new.id, new.subject, new.from_addr, new.to_addr);
    END;

    CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
        INSERT INTO messages_fts(messages_fts, rowid, subject, from_addr, to_addr)
        VALUES('delete', old.id, old.subject, old.from_addr, old.to_addr);
    END;

    CREATE TRIGGER IF NOT EXISTS messages_au AFTER UPDATE ON messages BEGIN
        INSERT INTO messages_fts(messages_fts, rowid, subject, from_addr, to_addr)
        VALUES('delete', old.id, old.subject, old.from_addr, old.to_addr);
        INSERT INTO messages_fts(rowid, subject, from_addr, to_addr)
        VALUES (new.id, new.subject, new.from_addr, new.to_addr);
    END;
    """,
    # Migration 4 — DKIM keys table
    """CREATE TABLE IF NOT EXISTS dkim_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        selector TEXT NOT NULL,
        private_key TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        UNIQUE(domain, selector)
    );""",
    # Migration 5 — refcount on blobs (ALTER TABLE already in v1 schema above)
]

# ------------------------------------------------------------------
# Config generator
# ------------------------------------------------------------------

TEST_CONFIG_TOML = """\
hostname = "{hostname}"

[storage]
path = "{db_path}"
blob_backend = "sqlite"

[smtp]
listen_addr = "{smtp_addr}"
submission_addr = "{submission_addr}"
submissions_addr = ""
max_message_size = 26214400
max_recipients = 100

[imap]
listen_addr = "{imap_addr}"
imaps_addr = "{imaps_addr}"

[pop3]
listen_addr = "{pop3_addr}"

[admin]
listen_addr = "{admin_addr}"

[auth]
session_expiry = "24h"

[queue]
workers = 2
max_retries = 3
interval = "5s"

[dkim]
domain = "{hostname}"
selector = "default"

[tls]
cert_file = ""
key_file = ""

[logging]
level = "debug"
format = "text"
"""


def make_config(hostname: str, bind: str, ports: dict, db_path: str) -> str:
    kwargs = {
        "hostname": hostname,
        "db_path": db_path,
        "smtp_addr": f"{bind}:{ports['smtp']}",
        "submission_addr": f"{bind}:{ports['submission']}",
        "imap_addr": f"{bind}:{ports['imap']}",
        "imaps_addr": f"{bind}:{ports['imaps']}",
        "pop3_addr": f"{bind}:{ports['pop3']}",
        "admin_addr": f"{bind}:{ports['admin']}",
    }
    return TEST_CONFIG_TOML.format(**kwargs)


# ------------------------------------------------------------------
# Port availability check
# ------------------------------------------------------------------

def port_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex((host, port)) != 0


def find_free_port(host: str, preferred: int, max_attempts: int = 20) -> int:
    for port in range(preferred, preferred + max_attempts):
        if port_free(host, port):
            return port
    raise RuntimeError(f"Could not find a free port starting from {preferred}")


# ------------------------------------------------------------------
# DB bootstrap
# ------------------------------------------------------------------

def hash_password(binary: str, password: str) -> str:
    """Pre-compute a password hash using the marco binary."""
    proc = subprocess.run(
        [binary, "hash-password"],
        input=password + "\n",
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        # Fallback: try reading from the output lines
        pass
    # Output is one line with the hash.
    return proc.stdout.strip().splitlines()[-1].strip()


def create_seeded_db(db_path: Path, binary: str, admin_email: str,
                      admin_password: str, users: list, domain: str) -> None:
    """Create a pre-seeded SQLite database with users and domain."""
    # Remove any existing file.
    db_path.unlink(missing_ok=True)

    con = sqlite3.connect(str(db_path))
    try:
        cur = con.cursor()

        # Apply all schema migrations using executescript (handles multi-statement DDL).
        for ddl in SCHEMA_SQL:
            con.executescript(ddl)
        # Mark schema as at latest version so the Go server skips migrations.
        cur.execute("PRAGMA user_version = 5")

        # Pre-compute password hashes.
        pw_hash = hash_password(binary, admin_password)

        # Insert admin user (must match Marco's create flow).
        now = int(time.time())
        cur.execute(
            "INSERT INTO users (email, password_hash, created_at, is_active) VALUES (?, ?, ?, 1)",
            (admin_email, pw_hash, now),
        )
        admin_id = cur.lastrowid

        # Insert INBOX mailbox for admin.
        cur.execute(
            "INSERT OR IGNORE INTO mailboxes (user_id, name) VALUES (?, 'INBOX')",
            (admin_id,),
        )

        # Insert test domain.
        cur.execute(
            "INSERT OR IGNORE INTO domains (name, is_active) VALUES (?, 1)",
            (domain,),
        )

        # Insert test users with their INBOX mailboxes.
        for email, pw in users:
            pw_hash = hash_password(binary, pw)
            cur.execute(
                "INSERT INTO users (email, password_hash, created_at, is_active) VALUES (?, ?, ?, 1)",
                (email, pw_hash, now),
            )
            uid = cur.lastrowid
            cur.execute(
                "INSERT OR IGNORE INTO mailboxes (user_id, name) VALUES (?, 'INBOX')",
                (uid,),
            )

        con.commit()
    finally:
        con.close()


# ------------------------------------------------------------------
# Main launcher
# ------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Marco local test server")
    parser.add_argument("--data-dir", default=os.environ.get("MARCO_TEST_DATA_DIR", ""),
                        help="Directory for DB, blobs, config (default: temporary)")
    parser.add_argument("--keep-data", action="store_true",
                        help="Don't remove data directory on exit")
    parser.add_argument("--bind", default="127.0.0.1",
                        help="Bind address (default 127.0.0.1)")
    parser.add_argument("--hostname", default="test.local")
    parser.add_argument("--admin-email", default=os.environ.get("MARCO_ADMIN_EMAIL", ADMIN_EMAIL))
    parser.add_argument("--admin-password", default=os.environ.get("MARCO_ADMIN_PASSWORD", ADMIN_PASSWORD))

    for svc in ("smtp", "submission", "imap", "imaps", "pop3", "admin"):
        default = DEFAULT_PORTS[svc]
        env_key = f"MARCO_TEST_{svc.upper()}_PORT"
        parser.add_argument(f"--{svc}-port", type=int, default=int(os.environ.get(env_key, str(default))),
                            help=f"{svc.upper()} port (default {default}, env {env_key})")

    args = parser.parse_args()
    ports = {svc: getattr(args, f"{svc}_port") for svc in DEFAULT_PORTS}

    # --- Create data directory ---
    if args.data_dir:
        data_dir = Path(args.data_dir)
        data_dir.mkdir(parents=True, exist_ok=True)
    else:
        data_dir = Path(tempfile.mkdtemp(prefix="marco-test-"))
        if args.keep_data:
            print(f"Data directory: {data_dir}", file=sys.stderr)

    def cleanup():
        if not args.keep_data and not args.data_dir:
            shutil.rmtree(data_dir, ignore_errors=True)

    if not args.data_dir:
        atexit.register(cleanup)

    db_path = data_dir / "marco.db"
    config_path = data_dir / "config.toml"

    # --- Find free ports ---
    bind = args.bind
    for svc in ports:
        ports[svc] = find_free_port(bind, ports[svc])

    # --- Build binary ---
    print("Building marco ...", file=sys.stderr)
    build_proc = subprocess.run(
        ["go", "build", "-o", str(data_dir / "marco"), "./cmd/marco"],
        cwd=SCRIPTS_DIR.parent,
        capture_output=True, text=True,
    )
    if build_proc.returncode != 0:
        print("Build failed:", file=sys.stderr)
        print(build_proc.stderr, file=sys.stderr)
        sys.exit(1)

    binary = str(data_dir / "marco")

    # --- Write config ---
    config_toml = make_config(args.hostname, bind, ports, str(db_path))
    config_path.write_text(config_toml)

    # --- Pre-seed database with users ---
    print("Seeding database ...", file=sys.stderr)
    create_seeded_db(
        db_path, binary,
        args.admin_email, args.admin_password,
        TEST_USERS, args.hostname,
    )

    # --- Start server ---
    env = os.environ.copy()
    env["MARCO_CONFIG"] = str(config_path)

    print(f"Starting Marco mail server ...", file=sys.stderr)
    print(f"  Config:  {config_path}", file=sys.stderr)
    print(f"  Data:    {data_dir}", file=sys.stderr)

    server_proc = subprocess.Popen(
        [binary, "run"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    def stop_server():
        if server_proc.poll() is None:
            server_proc.terminate()
            with suppress(Exception):
                server_proc.wait(timeout=5)
            if server_proc.poll() is None:
                server_proc.kill()
                server_proc.wait()

    atexit.register(stop_server)
    signal.signal(signal.SIGINT, lambda *_: (stop_server(), sys.exit(0)))
    signal.signal(signal.SIGTERM, lambda *_: (stop_server(), sys.exit(0)))

    # --- Wait for server to be ready ---
    api = MarcoAPI(base_url=f"http://{bind}:{ports['admin']}")

    deadline = time.monotonic() + 15
    ready = False
    while time.monotonic() < deadline:
        if server_proc.poll() is not None:
            print("Server exited prematurely. Output:", file=sys.stderr)
            print(server_proc.stdout.read().decode() if server_proc.stdout else "", file=sys.stderr)
            sys.exit(1)
        try:
            api.health()
            ready = True
            break
        except Exception:
            time.sleep(0.2)

    if not ready:
        print("Server did not become ready within 15 seconds.", file=sys.stderr)
        stop_server()
        sys.exit(1)

    # --- Authenticate to get a session token ---
    api.login(args.admin_email, args.admin_password)
    api.save_session(data_dir / ".marco_token")

    # --- Print connection info ---
    print("\n" + "=" * 62, file=sys.stderr)
    print("  Marco mail server is RUNNING", file=sys.stderr)
    print("=" * 62, file=sys.stderr)
    print(file=sys.stderr)
    print("  Admin API:", file=sys.stderr)
    print(f"    URL:      http://{bind}:{ports['admin']}", file=sys.stderr)
    print(f"    Token:    {api.token}", file=sys.stderr)
    print(file=sys.stderr)
    print("  Protocols:", file=sys.stderr)
    print(f"    SMTP:         {bind}:{ports['smtp']}", file=sys.stderr)
    print(f"    Submission:   {bind}:{ports['submission']}", file=sys.stderr)
    print(f"    IMAP:         {bind}:{ports['imap']}", file=sys.stderr)
    print(f"    IMAPS:        {bind}:{ports['imaps']}", file=sys.stderr)
    print(f"    POP3:         {bind}:{ports['pop3']}", file=sys.stderr)
    print(file=sys.stderr)
    print("  Test accounts:", file=sys.stderr)
    print(f"    Admin:       {args.admin_email} / {args.admin_password}", file=sys.stderr)
    for email, pw in TEST_USERS:
        print(f"    User:        {email} / {pw}", file=sys.stderr)
    print(file=sys.stderr)
    print("  Quick commands:", file=sys.stderr)
    print(f"    MARCO_API_URL=http://{bind}:{ports['admin']} \\", file=sys.stderr)
    print(f"      MARCO_API_TOKEN={api.token} python scripts/manage.py info", file=sys.stderr)
    print(f"    MARCO_API_URL=http://{bind}:{ports['admin']} python scripts/benchmark.py smtp", file=sys.stderr)
    print(file=sys.stderr)
    print("  To test polo UI:", file=sys.stderr)
    print(f"    cd ~/projects/polo && MARCO_API_URL=http://{bind}:{ports['admin']} \\", file=sys.stderr)
    print(f"      MARCO_API_TOKEN={api.token} bun run dev -- --port 3000", file=sys.stderr)
    print(file=sys.stderr)
    print("  Press Ctrl+C to stop the server.", file=sys.stderr)
    print("=" * 62, file=sys.stderr)

    # Stream server logs to stderr.
    try:
        for line in server_proc.stdout:
            sys.stderr.buffer.write(line)
            sys.stderr.buffer.flush()
    except (BrokenPipeError, OSError):
        pass
    finally:
        stop_server()


if __name__ == "__main__":
    main()
