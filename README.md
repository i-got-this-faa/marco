# Marco

Marco is a single-binary mail server for your homelab or VPS, written in Go. It implements SMTP (inbound + outbound), IMAP, and an admin HTTP API backed by SQLite.

## Quick start

```bash
# Start with Docker Compose (production-like)
cp marco.example.toml marco.toml
# edit marco.toml with your settings
docker compose up -d

# Or run directly (needs Go 1.21+)
go run ./cmd/marco run
```

## Configuration

Marco uses a single TOML config file, defaulting to `/etc/marco/config.toml` (overridable via `$MARCO_CONFIG`). See `marco.example.toml` for all options.

### IPv6-only deployment

If your ISP blocks port forwarding on IPv4, set `ip_version = "ipv6"` and use AAAA DNS records. All listeners and outbound delivery use IPv6 exclusively:

```toml
ip_version = "ipv6"
```

Values: `"any"` (dual-stack, default), `"ipv4"`, `"ipv6"`.

### Gmail SMTP relay

If your ISP blocks outbound port 25 (common for residential connections),
route Marco's outbound mail through Gmail's SMTP server:

```toml
[relay]
host = "smtp.gmail.com"
port = 587
username = "your@gmail.com"
password = "app-password"
```

You'll need a [Google App Password](https://myaccount.google.com/apppasswords)
(requires 2-factor authentication on your Google account). Regular account
passwords are rejected by Google's SMTP server.

When `[relay]` is configured, the queue worker sends all outbound mail
through the relay (STARTTLS + AUTH PLAIN) instead of doing direct MX
delivery. When `host` is empty (the default), direct MX delivery is used.

## Features

### Core
- SMTP server (RFC 5321) — port 25, submission 587, SMTPS 465
- IMAP server (RFC 3501) — port 143, IMAPS 993
- SQLite storage with incremental migrations
- TLS via file-based certs or automatic ACME (Let's Encrypt)
- Argon2id password hashing, bearer token sessions
- SPF checking (RFC 7208), DKIM signing, DMARC policy evaluation
- Queue-based outbound delivery with MX lookup, retry and backoff
- Blob store abstraction — filesystem, SQLite, or S3-compatible backends

### Administration
- HTTP JSON API for managing users, domains, aliases, queue, and stats
- CLI subcommands: `run`, `hash-password`, `gen-key`, `audit`, `backup`, `restore`
- Prometheus metrics on `/metrics`
- Audit command checks config, DNS records, database health, and blob integrity:
  ```bash
  marco audit
  ```

### Anti-abuse
- Per-IP token bucket rate limiting (configurable burst/rate)
- Greylisting with configurable delay (default 5 minutes)
- NDR bounce generation for failed deliveries

### Search & discovery
- FTS5 full-text search across messages, wired into IMAP SEARCH
- DMARC aggregate report (RUA) generation and delivery

## CLI

```
Usage: marco <command> [options]

Commands:
  run               Start the mail server (default)
  hash-password     Hash a password for config or database
  gen-key           Generate a DKIM RSA private key
  audit             Check configuration, DNS, database, and blobs
  backup <file>     Create a backup tarball of database and blobs
  restore <file>    Restore database and blobs from a tarball
  help              Show this help
```

## Audit

The `audit` command performs comprehensive checks:

- Configuration validation (ports, paths, TLS, DKIM, queue settings)
- DNS records (A/AAAA, MX, PTR, SPF, DKIM, DMARC)
- Database connectivity, schema version, user/message/queue counts
- Blob storage integrity (orphaned references)
- Storage health (expired sessions, stuck queue items, missing blobs)

```bash
$ marco audit
Marco Mail Server - Audit
========================
  [PASS] hostname: mail.example.com
  [PASS] ip-version: Dual-stack (IPv4 + IPv6)
  [PASS] dns-mx: mx.example.com (priority 10)
  [PASS] dns-spf: v=spf1 mx -all
  [PASS] dns-dmarc: Policy=pct=100 rua=mailto:dmarc@example.com
  [PASS] db-connect: Database opened successfully
  [PASS] blob-orphans: No orphaned blob references

3 passed, 0 failed, 0 warnings
```

## Design

See `root-info.md` for the full design document and package map.

## License

MIT
