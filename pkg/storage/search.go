package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// SearchMessages searches messages within a specific mailbox using FTS5 full-text
// search. The query string uses FTS5 syntax (Porter + unicode61 tokenizer).
// Results are ordered by relevance (rank). Returns at most limit results.
func SearchMessages(ctx context.Context, db *sql.DB, mailboxID int64, query string, limit int) ([]*Message, error) {
	if query == "" {
		return nil, nil
	}
	q := `SELECT messages.id, messages.mailbox_id, messages.uid, messages.blob_key,
		messages.size, messages.flags, messages.internal_date,
		messages.from_addr, messages.to_addr, messages.subject
		FROM messages
		JOIN messages_fts ON messages.id = messages_fts.rowid
		WHERE messages_fts MATCH ? AND messages.mailbox_id = ?
		ORDER BY rank`
	args := []interface{}{fts5Query(query), mailboxID}
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("storage: search messages: %w", err)
	}
	defer rows.Close()

	var msgs []*Message
	for rows.Next() {
		m := &Message{}
		if err := rows.Scan(&m.ID, &m.MailboxID, &m.UID, &m.BlobKey,
			&m.Size, &m.Flags, &m.InternalDate,
			&m.FromAddr, &m.ToAddr, &m.Subject); err != nil {
			return nil, fmt.Errorf("storage: search messages scan: %w", err)
		}
		msgs = append(msgs, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: search messages rows: %w", err)
	}
	return msgs, nil
}

// SearchMessagesAll searches messages across all mailboxes using FTS5 full-text
// search. Results are ordered by relevance (rank). Returns at most limit results.
func SearchMessagesAll(ctx context.Context, db *sql.DB, query string, limit int) ([]*Message, error) {
	if query == "" {
		return nil, nil
	}
	q := `SELECT messages.id, messages.mailbox_id, messages.uid, messages.blob_key,
		messages.size, messages.flags, messages.internal_date,
		messages.from_addr, messages.to_addr, messages.subject
		FROM messages
		JOIN messages_fts ON messages.id = messages_fts.rowid
		WHERE messages_fts MATCH ?
		ORDER BY rank`
	args := []interface{}{fts5Query(query)}
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("storage: search all messages: %w", err)
	}
	defer rows.Close()

	var msgs []*Message
	for rows.Next() {
		m := &Message{}
		if err := rows.Scan(&m.ID, &m.MailboxID, &m.UID, &m.BlobKey,
			&m.Size, &m.Flags, &m.InternalDate,
			&m.FromAddr, &m.ToAddr, &m.Subject); err != nil {
			return nil, fmt.Errorf("storage: search all messages scan: %w", err)
		}
		msgs = append(msgs, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: search all messages rows: %w", err)
	}
	return msgs, nil
}

// fts5Query converts a user-provided search string into a safe FTS5 query.
// Unquoted words are wrapped in double quotes to escape special FTS5 characters.
// Already-quoted phrases are preserved. Terms are joined with spaces (implicit AND).
func fts5Query(q string) string {
	if q == "" {
		return q
	}

	var terms []string
	for _, tok := range tokenizeQuery(q) {
		if strings.HasPrefix(tok, `"`) && strings.HasSuffix(tok, `"`) && len(tok) >= 2 {
			// Already a quoted phrase — pass through as-is with internal quotes escaped.
			inner := tok[1 : len(tok)-1]
			inner = escapeFTS5Quotes(inner)
			terms = append(terms, `"`+inner+`"`)
		} else {
			// Unquoted word — wrap in quotes to escape special FTS5 syntax.
			terms = append(terms, `"`+escapeFTS5Quotes(tok)+`"`)
		}
	}
	return strings.Join(terms, " ")
}

// tokenizeQuery splits a query into terms, respecting double-quoted phrases.
func tokenizeQuery(q string) []string {
	var terms []string
	var buf strings.Builder
	inQuote := false

	for _, r := range q {
		switch {
		case r == '"':
			inQuote = !inQuote
			buf.WriteRune(r)
		case r == ' ' && !inQuote:
			if buf.Len() > 0 {
				terms = append(terms, buf.String())
				buf.Reset()
			}
		default:
			buf.WriteRune(r)
		}
	}
	if buf.Len() > 0 {
		terms = append(terms, buf.String())
	}
	return terms
}

// escapeFTS5Quotes escapes double quotes in FTS5 query terms by doubling them.
func escapeFTS5Quotes(s string) string {
	return strings.ReplaceAll(s, `"`, `""`)
}
