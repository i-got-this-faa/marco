package blobstore

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"time"
)

// SQLiteStore stores blobs in a SQLite database, using the SHA-256 digest as
// the content-addressed key for automatic deduplication.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore creates a SQLiteStore backed by the given database.
func NewSQLiteStore(db *sql.DB) *SQLiteStore {
	return &SQLiteStore{db: db}
}

// Put inserts a blob into the database. The key is the SHA-256 digest of the
// content; duplicate content returns the existing key and increments the
// reference count.
func (s *SQLiteStore) Put(ctx context.Context, r io.Reader, metadata map[string]string) (string, int64, error) {
	key, data, size, err := sha256Key(r)
	if err != nil {
		return "", 0, err
	}

	// Upsert: insert with refcount=1, or increment refcount on duplicate.
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO blobs (key, data, size, created_at, refcount)
		VALUES (?, ?, ?, ?, 1)
		ON CONFLICT(key) DO UPDATE SET refcount = refcount + 1
	`, key, data, len(data), time.Now().Unix())
	if err != nil {
		return "", 0, fmt.Errorf("blobstore: upsert: %w", err)
	}

	return key, size, nil
}

// Get retrieves a blob from the database.
func (s *SQLiteStore) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	var data []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT data FROM blobs WHERE key = ?`, key,
	).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("blobstore: not found: %w", err)
	}
	if err != nil {
		return nil, fmt.Errorf("blobstore: get: %w", err)
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

// Delete decrements the reference count and removes the blob when the count
// reaches zero.
func (s *SQLiteStore) Delete(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE blobs SET refcount = refcount - 1 WHERE key = ?`, key,
	)
	if err != nil {
		return fmt.Errorf("blobstore: decrement refcount: %w", err)
	}

	// Remove rows with refcount <= 0.
	_, err = s.db.ExecContext(ctx,
		`DELETE FROM blobs WHERE key = ? AND refcount <= 0`, key,
	)
	if err != nil {
		return fmt.Errorf("blobstore: delete: %w", err)
	}
	return nil
}

// Exists checks whether a blob exists in the database.
func (s *SQLiteStore) Exists(ctx context.Context, key string) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM blobs WHERE key = ?`, key,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("blobstore: exists: %w", err)
	}
	return count > 0, nil
}

// Capabilities returns the store's capabilities.
func (s *SQLiteStore) Capabilities() Capabilities {
	return Capabilities{
		Streaming: false,
		RangeRead: false,
		Checksums: true,
	}
}

// uuidV4 is defined in fs.go (same package).
