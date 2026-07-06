#!/usr/bin/env python3
"""Seed the Marco database with rich mock data for UI testing.

Usage: python3 seed.py [--db PATH]

Connects to the Marco SQLite database, clears existing data (except
the admin user), and inserts realistic test data.
"""

import argparse
import os
import secrets
import sqlite3
import sys
import time

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "marco.db")

# ── Password hashes (argon2id) ──────────────────────────────────────────
# Generated via: echo '<plain>' | ./bin/marco hash-password
# admin123  → admin@example.com
# user123   → alice@test.org, bob@test.org
ADMIN_HASH = "$argon2id$v=19$m=65536,t=1,p=4$XiBWJ3ComviFRPB5ZnEZWQ$fiqknu8WyXek+niEuFPB0v6qjtdBZfIUsXJtPEDKD6I"
USER_HASH   = "$argon2id$v=19$m=65536,t=1,p=4$FweeRc6pHzRUHwXCCmR49A$2JQiE24rwwCYP4C6OFqFSPuOmxwIEKMrve81Ssxvq8c"


# ── Mock data ───────────────────────────────────────────────────────────

DOMAINS = [
    "example.com",
    "test.org",
    "mail.net",
]

USERS = [
    ("admin@example.com", ADMIN_HASH, True),
    ("alice@test.org", USER_HASH, True),
    ("bob@test.org", USER_HASH, True),
    ("carol@mail.net", USER_HASH, True),
]

# (source, destination, domain)
ALIASES = [
    ("info", "admin@example.com", "example.com"),
    ("support", "alice@test.org", "test.org"),
    ("help", "admin@example.com", "example.com"),
    ("sales", "bob@test.org", "test.org"),
    ("postmaster", "admin@example.com", "example.com"),
    ("abuse", "admin@example.com", "example.com"),
    ("noreply", "devnull@example.com", "example.com"),
    ("contact", "carol@mail.net", "mail.net"),
    ("webmaster", "admin@example.com", "example.com"),
    ("admin", "bob@test.org", "test.org"),
]

# (user_id, mailbox_name)
MAILBOXES = [
    (1, "INBOX"),
    (1, "Sent"),
    (1, "Drafts"),
    (1, "Trash"),
    (2, "INBOX"),
    (2, "Sent"),
    (2, "Drafts"),
    (3, "INBOX"),
    (3, "Sent"),
    (4, "INBOX"),
    (4, "Sent"),
    (4, "Trash"),
]

# (mailbox_id, from_addr, to_addr, subject, text_body, html_body)
# mailbox_id is 1-indexed into MAILBOXES list
MESSAGES = [
    (
        1,
        "alice@test.org",
        "admin@example.com",
        "Weekly report — Q3 planning",
        "Hey,\n\nHere's the weekly summary. We hit 12k new signups this week and the new SMTP relay is holding steady.\n\nLet me know if you want to adjust the rate limits.\n\n— Alice",
        "<p>Hey,</p><p>Here's the weekly summary. We hit 12k new signups this week and the new SMTP relay is holding steady.</p><p>Let me know if you want to adjust the rate limits.</p><p>— Alice</p>",
    ),
    (
        1,
        "bob@test.org",
        "admin@example.com",
        "Re: DNS records for mail.net migration",
        "Hey,\n\nI've updated the SPF and DKIM records for mail.net. Can you verify on your end?\n\nNew SPF: v=spf1 mx include:_spf.mail.net ~all\n\n— Bob",
        "<p>Hey,</p><p>I've updated the SPF and DKIM records for mail.net. Can you verify on your end?</p><p>New SPF: <code>v=spf1 mx include:_spf.mail.net ~all</code></p><p>— Bob</p>",
    ),
    (
        1,
        "carol@mail.net",
        "admin@example.com",
        "Queue alert — 45 messages deferred",
        "Hi,\n\nWe're seeing a spike in deferred messages to gmail.com. Looks like their rate limiting kicked in again. Current queue: 45 items, oldest is ~3h old.\n\nMight want to throttle outgoing mail for the next hour.\n\n— Carol",
        "<p>Hi,</p><p>We're seeing a spike in deferred messages to gmail.com. Looks like their rate limiting kicked in again. Current queue: 45 items, oldest is ~3h old.</p><p>Might want to throttle outgoing mail for the next hour.</p><p>— Carol</p>",
    ),
    (
        1,
        "noreply@github.com",
        "admin@example.com",
        "[marco] PR #127: Add rate limiting to SMTP listener",
        "Merged — PR #127\n\nAuthor: @alice\nBranch: feat/rate-limit\n\n3 approvals, all checks passed.\n\nView on GitHub: https://github.com/i-got-this-faa/marco/pull/127",
        "<p><strong>Merged — PR #127</strong></p><p>Author: @alice<br>Branch: feat/rate-limit</p><p>3 approvals, all checks passed.</p><p><a href='https://github.com/i-got-this-faa/marco/pull/127'>View on GitHub</a></p>",
    ),
    (
        1,
        "uptime@ping.example",
        "admin@example.com",
        "✅ Server recovery — mx1.example.com is back online",
        "Service: SMTP (port 25)\nHost: mx1.example.com\nDowntime: 3m 42s\nCurrent status: OK (200ms response)\n\nThis is an automated alert from PingBot.",
        "<p><strong>Service:</strong> SMTP (port 25)<br><strong>Host:</strong> mx1.example.com<br><strong>Downtime:</strong> 3m 42s<br><strong>Current status:</strong> OK (200ms response)</p><p><em>This is an automated alert from PingBot.</em></p>",
    ),
    (
        1,
        "spam@phish.org",
        "admin@example.com",
        "URGENT: Verify your account now!",
        "Dear user,\n\nYour email account has been compromised. Click here to verify your password immediately:\n\nhttps://evil.phish.org/reset\n\n— Security Team",
        "<p><strong>Dear user,</strong></p><p>Your email account has been compromised. Click here to verify your password immediately:</p><p><a href='https://evil.phish.org/reset'>Verify Now</a></p><p>— Security Team</p>",
    ),
    (
        5,
        "admin@example.com",
        "alice@test.org",
        "Re: Weekly report — looks good",
        "Alice,\n\nGreat work on the report. The numbers look solid. Let's talk about the rate limits in tomorrow's standup.\n\nI'm thinking we bump them by 20% and monitor.\n\n— Admin",
        "<p>Alice,</p><p>Great work on the report. The numbers look solid. Let's talk about the rate limits in tomorrow's standup.</p><p>I'm thinking we bump them by 20% and monitor.</p><p>— Admin</p>",
    ),
    (
        5,
        "carol@mail.net",
        "alice@test.org",
        "Mail.net setup complete",
        "Hey Alice,\n\nThe mail.net infrastructure is fully migrated. Here are the key stats:\n\n- Domains: 3\n- Users: 1,240\n- Daily volume: ~85k messages\n- Spam rate: 2.3%\n\nCheers,\nCarol",
        "<p>Hey Alice,</p><p>The mail.net infrastructure is fully migrated. Here are the key stats:</p><ul><li>Domains: 3</li><li>Users: 1,240</li><li>Daily volume: ~85k messages</li><li>Spam rate: 2.3%</li></ul><p>Cheers,<br>Carol</p>",
    ),
    (
        5,
        "notifications@cloudwatch.aws",
        "alice@test.org",
        "[ALARM] CPU utilization > 80% on smtp-03",
        "Alarm Name: HighCPU-smtp-03\nMetric: CPUUtilization\nThreshold: 80%\nCurrent Value: 87.3%\nRegion: us-east-1\nInstance: i-0abcd1234efgh5678\n\nView in console: https://console.aws.amazon.com/cloudwatch",
        "<p><strong>Alarm Name:</strong> HighCPU-smtp-03<br><strong>Metric:</strong> CPUUtilization<br><strong>Threshold:</strong> 80%<br><strong>Current Value:</strong> 87.3%<br><strong>Region:</strong> us-east-1<br><strong>Instance:</strong> i-0abcd1234efgh5678</p>",
    ),
    (
        9,
        "admin@example.com",
        "bob@test.org",
        "DNS update confirmation",
        "Bob,\n\nThe DNS changes look correct on our end. SPF and DKIM verified.\n\nPropagation should complete within the hour.\n\n— Admin",
        "<p>Bob,</p><p>The DNS changes look correct on our end. SPF and DKIM verified.</p><p>Propagation should complete within the hour.</p><p>— Admin</p>",
    ),
    (
        9,
        "noreply@dns.example",
        "bob@test.org",
        "DNS propagation status: 100% complete",
        "Domain: mail.net\nRecords checked: A, MX, TXT (SPF), TXT (DKIM), CNAME\nStatus: 5/5 — All propagated\nCompletion time: 47m\n\n— DNS Checker Bot",
        "<p><strong>Domain:</strong> mail.net</p><p><strong>Records checked:</strong> A, MX, TXT (SPF), TXT (DKIM), CNAME</p><p><strong>Status:</strong> 5/5 — All propagated</p><p><strong>Completion time:</strong> 47m</p><p>— DNS Checker Bot</p>",
    ),
    (
        11,
        "admin@example.com",
        "carol@mail.net",
        "Welcome to the team!",
        "Carol,\n\nWelcome aboard! Your mail.net account is set up.\n\nLogin: carol@mail.net\nDashboard: http://localhost:3000\n\nLet me know if you need anything.\n\n— Admin",
        "<p>Carol,</p><p>Welcome aboard! Your mail.net account is set up.</p><p><strong>Login:</strong> carol@mail.net<br><strong>Dashboard:</strong> <a href='http://localhost:3000'>http://localhost:3000</a></p><p>Let me know if you need anything.</p><p>— Admin</p>",
    ),
    (
        11,
        "bob@test.org",
        "carol@mail.net",
        "Re: Migration complete",
        "Carol,\n\nCongrats on getting the migration done! Let's sync up next week to review the first-week metrics.\n\n— Bob",
        "<p>Carol,</p><p>Congrats on getting the migration done! Let's sync up next week to review the first-week metrics.</p><p>— Bob</p>",
    ),
    (
        11,
        "newsletter@stripe.com",
        "carol@mail.net",
        "Your Stripe payout summary — June 2026",
        "Hi Carol,\n\nYour Stripe payout of $12,847.00 has been sent to your bank account.\n\nTotal transactions: 3,421\nFees: $342.10\nNet: $12,504.90\n\nView full report: https://dashboard.stripe.com/payouts\n\n— Stripe",
        "<p>Hi Carol,</p><p>Your Stripe payout of <strong>$12,847.00</strong> has been sent to your bank account.</p><p>Total transactions: 3,421<br>Fees: $342.10<br>Net: $12,504.90</p><p><a href='https://dashboard.stripe.com/payouts'>View full report</a></p><p>— Stripe</p>",
    ),
]

# (mailbox_id, rcpt_to, status, attempt_count)
QUEUE_ITEMS = [
    (1, "user@gmail.com", "pending", 0),
    (1, "friend@yahoo.com", "pending", 0),
    (1, "test@outlook.com", "retrying", 2),
    (5, "customer@company.com", "pending", 0),
    (5, "slow-server@legacy.org", "retrying", 4),
    (9, "archive@backup.net", "pending", 0),
    (9, "undeliverable@baddomain.example", "failed", 6),
]

CONTACTS = [
    (1, "Alice Johnson", "alice@test.org"),
    (1, "Bob Williams", "bob@test.org"),
    (1, "Carol Davis", "carol@mail.net"),
    (1, "Stripe Billing", "billing@stripe.com"),
    (1, "GitHub Notifications", "noreply@github.com"),
    (1, "AWS CloudWatch", "notifications@cloudwatch.aws"),
    (2, "Admin User", "admin@example.com"),
    (2, "Carol Davis", "carol@mail.net"),
    (2, "Dave Support", "dave@support.example"),
    (3, "Admin User", "admin@example.com"),
    (3, "Alice Johnson", "alice@test.org"),
    (4, "Admin User", "admin@example.com"),
    (4, "Bob Williams", "bob@test.org"),
]


def make_blob(from_addr: str, to_addr: str, subject: str, text_body: str, html_body: str = "") -> str:
    """Build a minimal RFC 5322 message and return blob content."""
    import email.utils
    now = int(time.time())
    msg_id = f"<{secrets.token_hex(8)}@marco.test>"
    lines = [
        f"From: {from_addr}",
        f"To: {to_addr}",
        f"Subject: {subject}",
        f"Date: {email.utils.formatdate(now, localtime=True)}",
        f"Message-ID: {msg_id}",
        "MIME-Version: 1.0",
    ]
    if html_body:
        boundary = f"----{secrets.token_hex(16)}"
        lines.append(f'Content-Type: multipart/alternative; boundary="{boundary}"')
        lines.append("")
        lines.append(f"--{boundary}")
        lines.append("Content-Type: text/plain; charset=UTF-8")
        lines.append("Content-Transfer-Encoding: 7bit")
        lines.append("")
        lines.append(text_body)
        lines.append(f"--{boundary}")
        lines.append("Content-Type: text/html; charset=UTF-8")
        lines.append("Content-Transfer-Encoding: 7bit")
        lines.append("")
        lines.append(html_body)
        lines.append(f"--{boundary}--")
    else:
        lines.append("Content-Type: text/plain; charset=UTF-8")
        lines.append("Content-Transfer-Encoding: 7bit")
        lines.append("")
        lines.append(text_body)
    return "\r\n".join(lines)


def seed(db_path: str) -> None:
    """Seed the Marco database with mock data."""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    cur = conn.cursor()

    print("🧹 Clearing existing mock data (keeping admin user)…")
    cur.execute("DELETE FROM aliases")
    cur.execute("DELETE FROM attachments")
    cur.execute("DELETE FROM queue")
    cur.execute("DELETE FROM sessions")
    cur.execute("DELETE FROM messages")
    cur.execute("DELETE FROM mailboxes")
    cur.execute("DELETE FROM blobs")
    cur.execute("DELETE FROM domains")
    # Keep existing admin user, delete other users
    cur.execute("DELETE FROM users WHERE id != 1")

    now = int(time.time())

    # ── Domains ──────────────────────────────────────────────────────────
    print("🌐 Seeding domains…")
    for name in DOMAINS:
        cur.execute("INSERT OR IGNORE INTO domains (name, is_active) VALUES (?, 1)", (name,))

    # ── Users ─────────────────────────────────────────────────────────────
    print("👤 Seeding users…")
    user_ids = [1]  # admin@example.com already exists
    for email, pwhash, is_active in USERS:
        if email == "admin@example.com":
            continue  # already exists
        cur.execute(
            "INSERT INTO users (email, password_hash, created_at, is_active) VALUES (?, ?, ?, ?)",
            (email, pwhash, now - 3600, 1 if is_active else 0),
        )
        user_ids.append(cur.lastrowid)
    conn.commit()

    # Re-fetch all user IDs by email
    cur.execute("SELECT id, email FROM users")
    user_by_email = {r[1]: r[0] for r in cur.fetchall()}
    print(f"   → {len(user_by_email)} users")

    # ── Mailboxes ─────────────────────────────────────────────────────────
    print("📁 Seeding mailboxes…")
    mailbox_ids = []
    for uid, name in MAILBOXES:
        cur.execute(
            "INSERT INTO mailboxes (user_id, name) VALUES (?, ?)",
            (uid, name),
        )
        mailbox_ids.append(cur.lastrowid)
    conn.commit()

    # ── Messages ──────────────────────────────────────────────────────────
    print("📧 Seeding messages…")
    for i, (mb_idx, from_addr, to_addr, subject, text_body, html_body) in enumerate(MESSAGES):
        mailbox_id = mailbox_ids[mb_idx - 1]  # 1-indexed in MESSAGES
        blob_content = make_blob(from_addr, to_addr, subject, text_body, html_body)
        blob_key = f"seed-msg-{i + 1}"

        # Insert blob
        cur.execute(
            "INSERT INTO blobs (key, data, size, created_at) VALUES (?, ?, ?, ?)",
            (blob_key, blob_content.encode("utf-8"), len(blob_content), now - (len(MESSAGES) - i) * 120),
        )

        uid = i + 1
        flags = 0 if i < 3 else 1  # first 3 unseen, rest seen
        cur.execute(
            "INSERT INTO messages (mailbox_id, uid, blob_key, size, flags, internal_date, from_addr, to_addr, subject) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (mailbox_id, uid, blob_key, len(blob_content), flags, now - (len(MESSAGES) - i) * 120, from_addr, to_addr, subject),
        )
    conn.commit()
    cur.execute("SELECT COUNT(*) FROM messages")
    print(f"   → {cur.fetchone()[0]} messages")

    # ── Aliases ───────────────────────────────────────────────────────────
    print("📬 Seeding aliases…")
    for src, dst, domain in ALIASES:
        cur.execute(
            "INSERT OR IGNORE INTO aliases (source, destination, domain) VALUES (?, ?, ?)",
            (src, dst, domain),
        )
    conn.commit()

    cur.execute("SELECT COUNT(*) FROM aliases")
    print(f"   → {cur.fetchone()[0]} aliases")

    # ── Queue ─────────────────────────────────────────────────────────────
    print("⏳ Seeding queue…")
    for mb_idx, rcpt_to, status, attempts in QUEUE_ITEMS:
        mailbox_id = mailbox_ids[mb_idx - 1]
        # Pick first message in this mailbox as the message_id reference
        cur.execute("SELECT id FROM messages WHERE mailbox_id = ? LIMIT 1", (mailbox_id,))
        msg_row = cur.fetchone()
        msg_id = msg_row[0] if msg_row else 1

        next_attempt = now + 300  # 5 minutes from now
        if status == "retrying":
            next_attempt = now - 60  # overdue (should have retried already)
        elif status == "failed":
            next_attempt = now + 86400  # far future

        cur.execute(
            "INSERT INTO queue (message_id, rcpt_to, next_attempt, attempt_count, status) VALUES (?, ?, ?, ?, ?)",
            (msg_id, rcpt_to, next_attempt, attempts, status),
        )
    conn.commit()

    cur.execute("SELECT COUNT(*) FROM queue")
    print(f"   → {cur.fetchone()[0]} queue items")

    # ── Contacts ─────────────────────────────────────────────────────────
    print("📇 Seeding contacts…")
    for uid, name, email in CONTACTS:
        cur.execute(
            "INSERT INTO contacts (user_id, name, email, created_at) VALUES (?, ?, ?, ?)",
            (uid, name, email, now),
        )
    conn.commit()

    cur.execute("SELECT COUNT(*) FROM contacts")
    print(f"   → {cur.fetchone()[0]} contacts")

    # ── Session token for admin ──────────────────────────────────────────
    print("🔑 Creating session token for admin@example.com…")
    admin_id = user_by_email["admin@example.com"]
    # 64-char hex (32 random bytes) — same format Marco uses
    session_token = secrets.token_hex(32)
    expires_at = now + 86400 * 7  # 7 days
    cur.execute(
        "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
        (session_token, admin_id, expires_at),
    )
    conn.commit()
    print(f"\n✅ Session token (valid 7 days):")
    print(f"   {session_token}")
    print()
    print(f"   Add to .env:")
    print(f'   MARCO_API_TOKEN="{session_token}"')

    # ── Summary ──────────────────────────────────────────────────────────
    cur.execute("SELECT COUNT(*) FROM users")
    user_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM domains")
    domain_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM aliases")
    alias_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM queue")
    queue_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM mailboxes")
    mailbox_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM messages")
    message_count = cur.fetchone()[0]

    print(f"\n📊 Database summary:")
    print(f"   Users:    {user_count}")
    print(f"   Domains:  {domain_count}")
    print(f"   Aliases:  {alias_count}")
    print(f"   Mailboxes: {mailbox_count}")
    print(f"   Messages: {message_count}")
    print(f"   Queue:    {queue_count}")

    conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Marco database with mock data")
    parser.add_argument("--db", default=DB_PATH, help=f"Path to marco.db (default: {DB_PATH})")
    args = parser.parse_args()

    if not os.path.exists(args.db):
        print(f"❌ Database not found: {args.db}", file=sys.stderr)
        sys.exit(1)

    print(f"📦 Using database: {args.db}")
    seed(args.db)


if __name__ == "__main__":
    main()
