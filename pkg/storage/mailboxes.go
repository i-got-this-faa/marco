package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/i-got-this-faa/marco/pkg/cache"
)

// mailboxCacheKey is the composite key for the mailbox cache.
type mailboxCacheKey struct {
	userID int64
	name   string
}

// mailboxCache caches mailbox lookups with a 30s TTL.
var mailboxCache = cache.New[mailboxCacheKey, *Mailbox](30*time.Second, 5000)

// DefaultMailboxes is the set of mailboxes created for every new user.
var DefaultMailboxes = []string{"INBOX", "Sent", "Trash", "Spam", "Drafts"}

// EnsureDefaultMailboxes creates the default mailbox set for a user if
// they don't already exist.
func EnsureDefaultMailboxes(ctx context.Context, db *sql.DB, userID int64) error {
	for _, name := range DefaultMailboxes {
		_, err := CreateMailbox(ctx, db, userID, name)
		if err != nil && !errors.Is(err, ErrAlreadyExists) {
			return fmt.Errorf("storage: create mailbox %s: %w", name, err)
		}
	}
	return nil
}

// CreateMailbox creates a new mailbox for a user.
func CreateMailbox(ctx context.Context, db *sql.DB, userID int64, name string) (int64, error) {
	res, err := db.ExecContext(ctx,
		`INSERT INTO mailboxes (user_id, name) VALUES (?, ?)`,
		userID, name,
	)
	if err != nil {
		if isConstraintError(err) {
			return 0, fmt.Errorf("storage: create mailbox: %w", ErrAlreadyExists)
		}
		return 0, fmt.Errorf("storage: create mailbox: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("storage: create mailbox lastid: %w", err)
	}
	mailboxCache.Delete(mailboxCacheKey{userID: userID, name: name})
	return id, nil
}

// GetMailbox looks up a mailbox by user ID and name.
func GetMailbox(ctx context.Context, db *sql.DB, userID int64, name string) (*Mailbox, error) {
	key := mailboxCacheKey{userID: userID, name: name}
	if m, ok := mailboxCache.Get(key); ok {
		return m, nil
	}

	m := &Mailbox{}
	err := db.QueryRowContext(ctx,
		`SELECT id, user_id, name FROM mailboxes WHERE user_id = ? AND name = ?`,
		userID, name,
	).Scan(&m.ID, &m.UserID, &m.Name)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("storage: mailbox not found: %w", ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("storage: get mailbox: %w", err)
	}
	mailboxCache.Set(key, m)
	return m, nil
}

// GetMailboxByID looks up a mailbox by ID.
func GetMailboxByID(ctx context.Context, db *sql.DB, mailboxID int64) (*Mailbox, error) {
	m := &Mailbox{}
	err := db.QueryRowContext(ctx,
		`SELECT id, user_id, name FROM mailboxes WHERE id = ?`,
		mailboxID,
	).Scan(&m.ID, &m.UserID, &m.Name)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("storage: mailbox not found: %w", ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("storage: get mailbox by id: %w", err)
	}
	return m, nil
}

// ListMailboxes returns all mailboxes for a user.
func ListMailboxes(ctx context.Context, db *sql.DB, userID int64) ([]*Mailbox, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, user_id, name FROM mailboxes WHERE user_id = ? ORDER BY name`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("storage: list mailboxes: %w", err)
	}
	defer rows.Close()

	var boxes []*Mailbox
	for rows.Next() {
		m := &Mailbox{}
		if err := rows.Scan(&m.ID, &m.UserID, &m.Name); err != nil {
			return nil, fmt.Errorf("storage: list mailboxes scan: %w", err)
		}
		boxes = append(boxes, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: list mailboxes rows: %w", err)
	}
	return boxes, nil
}

// DeleteMailbox removes a mailbox by ID.
func DeleteMailbox(ctx context.Context, db *sql.DB, mailboxID int64) error {
	// Fetch mailbox before deletion to invalidate the cache.
	m, err := GetMailboxByID(ctx, db, mailboxID)
	if err != nil {
		return fmt.Errorf("storage: delete mailbox: %w", err)
	}

	_, err = db.ExecContext(ctx, `DELETE FROM mailboxes WHERE id = ?`, mailboxID)
	if err != nil {
		return fmt.Errorf("storage: delete mailbox: %w", err)
	}

	mailboxCache.Delete(mailboxCacheKey{userID: m.UserID, name: m.Name})
	return nil
}

// RenameMailbox renames a mailbox.
func RenameMailbox(ctx context.Context, db *sql.DB, mailboxID int64, newName string) error {
	res, err := db.ExecContext(ctx, `UPDATE mailboxes SET name = ? WHERE id = ?`, newName, mailboxID)
	if err != nil {
		return fmt.Errorf("storage: rename mailbox: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("storage: rename mailbox: %w", ErrNotFound)
	}
	// Invalidate cache.
	mailboxCache.Clear()
	return nil
}
