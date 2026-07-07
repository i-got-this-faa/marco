package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Flag bits for message flags (matching IMAP flag semantics).
const (
	FlagSeen     = 1 << iota
	FlagAnswered
	FlagFlagged
	FlagDeleted
	FlagDraft
)

// InsertMessage stores a new message in a mailbox. It returns the
// message ID and the assigned UID.
func InsertMessage(ctx context.Context, db *sql.DB, mailboxID int64, blobKey string, size int64,
	fromAddr, toAddr, subject string, flags int) (msgID int64, uid uint32, err error) {

	err = withTx(ctx, db, func(tx *sql.Tx) error {
		// Assign next UID for this mailbox.
		var maxUID sql.NullInt64
		err := tx.QueryRowContext(ctx,
			`SELECT MAX(uid) FROM messages WHERE mailbox_id = ?`, mailboxID,
		).Scan(&maxUID)
		if err != nil {
			return fmt.Errorf("storage: max uid: %w", err)
		}
		uid = uint32(maxUID.Int64) + 1

		res, err := tx.ExecContext(ctx,
			`INSERT INTO messages (mailbox_id, uid, blob_key, size, flags, internal_date, from_addr, to_addr, subject)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			mailboxID, uid, blobKey, size, flags, time.Now().Unix(),
			fromAddr, toAddr, subject,
		)
		if err != nil {
			return fmt.Errorf("storage: insert message: %w", err)
		}
		msgID, err = res.LastInsertId()
		return err
	})
	return
}

// GetMessageByUID retrieves a message by mailbox and UID.
func GetMessageByUID(ctx context.Context, db *sql.DB, mailboxID int64, uid uint32) (*Message, error) {
	m := &Message{}
	err := db.QueryRowContext(ctx,
		`SELECT id, mailbox_id, uid, blob_key, size, flags, internal_date, from_addr, to_addr, subject
		 FROM messages WHERE mailbox_id = ? AND uid = ?`,
		mailboxID, uid,
	).Scan(&m.ID, &m.MailboxID, &m.UID, &m.BlobKey, &m.Size, &m.Flags,
		&m.InternalDate, &m.FromAddr, &m.ToAddr, &m.Subject)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("storage: message not found: %w", ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("storage: get message by uid: %w", err)
	}
	return m, nil
}

// GetMessageByID retrieves a message by its primary key.
func GetMessageByID(ctx context.Context, db *sql.DB, msgID int64) (*Message, error) {
	m := &Message{}
	err := db.QueryRowContext(ctx,
		`SELECT id, mailbox_id, uid, blob_key, size, flags, internal_date, from_addr, to_addr, subject
		 FROM messages WHERE id = ?`,
		msgID,
	).Scan(&m.ID, &m.MailboxID, &m.UID, &m.BlobKey, &m.Size, &m.Flags,
		&m.InternalDate, &m.FromAddr, &m.ToAddr, &m.Subject)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("storage: message not found: %w", ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("storage: get message by id: %w", err)
	}
	return m, nil
}

// ListMessages returns messages in a mailbox, newest first, with optional
// pagination via sinceUID (exclusive lower bound).
func ListMessages(ctx context.Context, db *sql.DB, mailboxID int64, limit int, sinceUID uint32) ([]*Message, error) {
	q := `SELECT id, mailbox_id, uid, blob_key, size, flags, internal_date, from_addr, to_addr, subject
		  FROM messages WHERE mailbox_id = ?`
	args := []interface{}{mailboxID}
	if sinceUID > 0 {
		q += ` AND uid > ?`
		args = append(args, sinceUID)
	}
	q += ` ORDER BY uid DESC`
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("storage: list messages: %w", err)
	}
	defer rows.Close()

	var msgs []*Message
	for rows.Next() {
		m := &Message{}
		if err := rows.Scan(&m.ID, &m.MailboxID, &m.UID, &m.BlobKey, &m.Size, &m.Flags,
			&m.InternalDate, &m.FromAddr, &m.ToAddr, &m.Subject); err != nil {
			return nil, fmt.Errorf("storage: list messages scan: %w", err)
		}
		msgs = append(msgs, m)
	}
	return msgs, rows.Err()
}

// UpdateFlags sets or clears message flags using a bitmask. Bits set in
// flagsMask are set to the corresponding bit in flags on the stored value.
func UpdateFlags(ctx context.Context, db *sql.DB, messageID int64, flags, flagsMask int) error {
	res, err := db.ExecContext(ctx,
		`UPDATE messages SET flags = ((flags & ~?) | (? & ?)) WHERE id = ?`,
		flagsMask, flags, flagsMask, messageID,
	)
	if err != nil {
		return fmt.Errorf("storage: update flags: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("storage: update flags: %w", ErrNotFound)
	}
	return nil
}

// MoveMessage moves a message to a different mailbox.
func MoveMessage(ctx context.Context, db *sql.DB, messageID, destMailboxID int64) error {
	res, err := db.ExecContext(ctx,
		`UPDATE messages SET mailbox_id = ? WHERE id = ?`,
		destMailboxID, messageID,
	)
	if err != nil {
		return fmt.Errorf("storage: move message: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("storage: move message: %w", ErrNotFound)
	}
	return nil
}

// DeleteMessage removes a message by ID.
func DeleteMessage(ctx context.Context, db *sql.DB, messageID int64) error {
	res, err := db.ExecContext(ctx,
		`DELETE FROM messages WHERE id = ?`, messageID,
	)
	if err != nil {
		return fmt.Errorf("storage: delete message: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("storage: delete message: %w", ErrNotFound)
	}
	return nil
}

// CountMessages returns the total number of messages in a mailbox.
func CountMessages(ctx context.Context, db *sql.DB, mailboxID int64) (int, error) {
	var count int
	err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM messages WHERE mailbox_id = ?`, mailboxID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("storage: count messages: %w", err)
	}
	return count, nil
}

// withTx runs fn inside a transaction. If fn returns an error, the
// transaction is rolled back; otherwise it is committed.
func withTx(ctx context.Context, db *sql.DB, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// ListMessageUIDs returns the UIDs of all messages in a mailbox, ordered ascending.
// This is a lighter alternative to ListMessages when only UIDs are needed.
func ListMessageUIDs(ctx context.Context, db *sql.DB, mailboxID int64) ([]uint32, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT uid FROM messages WHERE mailbox_id = ? ORDER BY uid ASC`,
		mailboxID,
	)
	if err != nil {
		return nil, fmt.Errorf("storage: list uids: %w", err)
	}
	defer rows.Close()

	var uids []uint32
	for rows.Next() {
		var uid uint32
		if err := rows.Scan(&uid); err != nil {
			return nil, fmt.Errorf("storage: list uids scan: %w", err)
		}
		uids = append(uids, uid)
	}
	return uids, rows.Err()
}

// ExpungeMailbox deletes all messages in a mailbox that have the FlagDeleted
// bit set. Returns the number of messages deleted.
func ExpungeMailbox(ctx context.Context, db *sql.DB, mailboxID int64) (int, error) {
	res, err := db.ExecContext(ctx,
		`DELETE FROM messages WHERE mailbox_id = ? AND (flags & ?) != 0`,
		mailboxID, FlagDeleted,
	)
	if err != nil {
		return 0, fmt.Errorf("storage: expunge mailbox: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
