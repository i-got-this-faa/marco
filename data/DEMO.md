# Marco Mail Server — Demo Guide

This directory contains a pre-seeded SQLite database for local development
and testing. The server is configured to run on localhost with non-privileged
ports so it won't interfere with any running mail services.

## Quick Start

```bash
MARCO_CONFIG=marco.toml ./data/marco run
```

## Accounts

| Role      | Email               | Password   | Access                      |
|-----------|---------------------|------------|-----------------------------|
| Admin     | admin@test.local    | admin1234  | Dashboard (users, stats)    |
| User      | alice@test.local    | alice1234  | Mail page (inbox, compose)  |
| User      | bob@test.local      | bob1234    | Mail page (inbox, compose)  |
| User      | carol@test.local    | carol1234  | Mail page (inbox, compose)  |

## Admin: admin@test.local

Full access to the admin API and dashboard:

- **Users** — list, create, update, delete user accounts
- **Domains** — manage hosted domains
- **Stats** — server-wide metrics (users, domains, queue, aliases, messages)
- **Queue** — view and manage pending delivery queue
- **Aliases** — manage email aliases

Admin endpoints:

```
GET  /api/health
GET  /api/stats
GET  /api/users
POST /api/users
GET  /api/domains
POST /api/domains
GET  /api/aliases
GET  /api/queue
```

## Regular Users (alice, bob, carol)

Each user has a full set of mailboxes:

| Mailbox | Description              |
|---------|--------------------------|
| INBOX   | Received messages        |
| Sent    | Sent messages            |
| Drafts  | Saved drafts             |
| Trash   | Deleted messages         |
| Spam    | Flagged spam             |

Sample data is pre-loaded so each mailbox has realistic content.

### Mail API

```
GET  /api/me
GET  /api/mailboxes
GET  /api/mailboxes/{id}/messages
GET  /api/messages/{id}
GET  /api/messages/{id}/raw
GET  /api/messages/{id}/parts
GET  /api/messages/{id}/parts/{part}
GET  /api/contacts
POST /api/contacts
PUT  /api/contacts/{id}
DEL  /api/contacts/{id}
```

### Example: Bob's Inbox (alice@ → bob@ email)

```bash
# Login as bob
curl -s -X POST http://localhost:18080/api/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"bob@test.local","password":"bob1234"}'

# Save the token and list mailboxes
TOKEN="<token-from-login>"
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:18080/api/mailboxes

# Read inbox messages (bob's mailbox id is 12)
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:18080/api/mailboxes/12/messages
```

## Ports

| Service      | Port  | Notes                         |
|--------------|-------|-------------------------------|
| Admin API    | 18080 | REST API + dashboard          |
| SMTP         | 10025 | Plain/STARTTLS relay          |
| Submission   | 10587 | STARTTLS + AUTH required      |
| IMAP         | 10143 | STARTTLS                      |
| IMAPS        | 10993 | Implicit TLS                  |
| POP3         | 10110 | Retrieval                     |
