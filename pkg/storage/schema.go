package storage

// DDL statements for all tables. These are applied in order by Migrate.
var migrations = []struct {
	version int
	ddl     string
}{
	{
		version: 1,
		ddl: `
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
`,
	},
	{
		version: 2,
		ddl: `CREATE TABLE IF NOT EXISTS greylist (
    ip TEXT NOT NULL,
    from_addr TEXT NOT NULL,
    to_addr TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    passed INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (ip, from_addr, to_addr)
);`,
	},
	{
		version: 3,
		ddl: `
CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
    subject, from_addr, to_addr, body,
    content='',
    tokenize='porter unicode61'
);

CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
    INSERT INTO messages_fts(rowid, subject, from_addr, to_addr) VALUES (new.id, new.subject, new.from_addr, new.to_addr);
END;

CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
    INSERT INTO messages_fts(messages_fts, rowid, subject, from_addr, to_addr) VALUES('delete', old.id, old.subject, old.from_addr, old.to_addr);
END;

CREATE TRIGGER IF NOT EXISTS messages_au AFTER UPDATE ON messages BEGIN
    INSERT INTO messages_fts(messages_fts, rowid, subject, from_addr, to_addr) VALUES('delete', old.id, old.subject, old.from_addr, old.to_addr);
    INSERT INTO messages_fts(rowid, subject, from_addr, to_addr) VALUES (new.id, new.subject, new.from_addr, new.to_addr);
END;
`,
	},
	{
		version: 4,
		ddl: `
CREATE TABLE IF NOT EXISTS dmarc_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip TEXT NOT NULL,
    from_domain TEXT NOT NULL,
    spf_result TEXT NOT NULL DEFAULT 'none',
    dkim_result TEXT NOT NULL DEFAULT 'none',
    disposition TEXT NOT NULL DEFAULT 'none',
    timestamp INTEGER NOT NULL,
    report_sent INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_dmarc_results_domain_unsent ON dmarc_results(from_domain, report_sent);
`,
	},
	{
		version: 5,
		ddl: `ALTER TABLE blobs ADD COLUMN refcount INTEGER NOT NULL DEFAULT 1;`,
	},
	{
		version: 6,
		ddl: `
ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0;
UPDATE users SET is_admin = 1;
`,
	},
	{
		version: 7,
		ddl: `
CREATE TABLE IF NOT EXISTS contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT,
    email TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE(user_id, email)
);

CREATE INDEX IF NOT EXISTS idx_contacts_user ON contacts(user_id);
`,
	},
}
