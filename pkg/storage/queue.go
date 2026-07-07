package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Enqueue inserts a pending delivery for a message recipient.
func Enqueue(ctx context.Context, db *sql.DB, messageID int64, rcptTo string) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO queue (message_id, rcpt_to, next_attempt, status) VALUES (?, ?, ?, 'pending')`,
		messageID, rcptTo, time.Now().Unix(),
	)
	if err != nil {
		return fmt.Errorf("storage: enqueue: %w", err)
	}
	return nil
}

// ClaimNext attempts to claim one pending queue item for a worker.
// It uses an atomic UPDATE with WHERE status='pending' so that only
// one worker claims each item. Returns nil if nothing to claim.
func ClaimNext(ctx context.Context, db *sql.DB) (*QueueItem, error) {
	// SQLite doesn't support SKIP LOCKED, so we use a transaction with
	// a subquery to atomically select-then-update.
	var item QueueItem
	err := withTx(ctx, db, func(tx *sql.Tx) error {
		// Pick the oldest pending item.
		row := tx.QueryRowContext(ctx,
			`SELECT id, message_id, rcpt_to, next_attempt, attempt_count, status
			 FROM queue WHERE status = 'pending' AND next_attempt <= ?
			 ORDER BY next_attempt LIMIT 1`,
			time.Now().Unix(),
		)
		if err := row.Scan(&item.ID, &item.MessageID, &item.RcptTo,
			&item.NextAttempt, &item.AttemptCount, &item.Status); err != nil {
			if err == sql.ErrNoRows {
				return sql.ErrNoRows // sentinel to skip update
			}
			return err
		}

		res, err := tx.ExecContext(ctx,
			`UPDATE queue SET status = 'active' WHERE id = ? AND status = 'pending'`,
			item.ID,
		)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return sql.ErrNoRows // another worker got it
		}
		return nil
	})
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("storage: claim next: %w", err)
	}
	return &item, nil
}

// Complete removes a queue item after successful delivery.
func Complete(ctx context.Context, db *sql.DB, queueID int64) error {
	res, err := db.ExecContext(ctx, `DELETE FROM queue WHERE id = ?`, queueID)
	if err != nil {
		return fmt.Errorf("storage: complete: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("storage: complete: %w", ErrNotFound)
	}
	return nil
}

// Fail updates a queue item after a transient failure, incrementing the
// attempt count and setting the next attempt time. If max retries have
// been exceeded, the item is removed and Fail returns ErrMaxRetries.
func Fail(ctx context.Context, db *sql.DB, queueID int64, nextAttempt time.Time, maxRetries int) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var attemptCount int
	if err := tx.QueryRowContext(ctx,
		`SELECT attempt_count FROM queue WHERE id = ?`, queueID,
	).Scan(&attemptCount); err != nil {
		return err
	}

	if attemptCount >= maxRetries {
		if _, err := tx.ExecContext(ctx, `DELETE FROM queue WHERE id = ?`, queueID); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		return ErrMaxRetries
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE queue SET status = 'pending', attempt_count = attempt_count + 1, next_attempt = ? WHERE id = ?`,
		nextAttempt.Unix(), queueID,
	); err != nil {
		return err
	}
	return tx.Commit()
}

// ListPending returns queue items that are pending or active, for
// monitoring/admin purposes.
func ListPending(ctx context.Context, db *sql.DB) ([]*QueueItem, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, message_id, rcpt_to, next_attempt, attempt_count, status
		 FROM queue ORDER BY next_attempt`)
	if err != nil {
		return nil, fmt.Errorf("storage: list pending: %w", err)
	}
	defer rows.Close()

	var items []*QueueItem
	for rows.Next() {
		item := &QueueItem{}
		if err := rows.Scan(&item.ID, &item.MessageID, &item.RcptTo,
			&item.NextAttempt, &item.AttemptCount, &item.Status); err != nil {
			return nil, fmt.Errorf("storage: list pending scan: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: list pending rows: %w", err)
	}
	return items, nil
}

// QueueSize returns the number of items currently in the queue.
func QueueSize(ctx context.Context, db *sql.DB) (int, error) {
	var count int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM queue`).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("storage: queue size: %w", err)
	}
	return count, nil
}
