package storage

import (
	"context"
	"database/sql"
	"time"
)

// RecordAttempt upserts a greylist triplet, updating last_seen.
func RecordAttempt(ctx context.Context, db *sql.DB, ip, from, to string) error {
	now := time.Now().Unix()
	_, err := db.ExecContext(ctx, `
		INSERT INTO greylist (ip, from_addr, to_addr, first_seen, last_seen, passed)
		VALUES (?, ?, ?, ?, ?, 0)
		ON CONFLICT(ip, from_addr, to_addr) DO UPDATE SET last_seen = ?
	`, ip, from, to, now, now, now)
	return err
}

// IsWhitelisted returns true if the triplet has passed greylisting.
func IsWhitelisted(ctx context.Context, db *sql.DB, ip, from, to string) (bool, error) {
	var passed int
	err := db.QueryRowContext(ctx,
		`SELECT passed FROM greylist WHERE ip = ? AND from_addr = ? AND to_addr = ?`,
		ip, from, to,
	).Scan(&passed)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return passed == 1, nil
}

// MarkPassed marks a greylist triplet as passed.
func MarkPassed(ctx context.Context, db *sql.DB, ip, from, to string) error {
	_, err := db.ExecContext(ctx,
		`UPDATE greylist SET passed = 1 WHERE ip = ? AND from_addr = ? AND to_addr = ?`,
		ip, from, to,
	)
	return err
}
