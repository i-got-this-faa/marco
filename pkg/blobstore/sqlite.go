package blobstore

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"time"
)
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore creates a SQLiteStore backed by the given database.
func NewSQLiteStore(db *sql.DB) *SQLiteStore {
	return &SQLiteStore{db: db}
}

// Put inserts a blob into the database.
func (s *SQLiteStore) Put(ctx context.Context, r io.Reader, metadata map[string]string) (string, int64, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return "", 0, fmt.Errorf("blobstore: read: %w", err)
	}

	key := uuidV4()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO blobs (key, data, size, created_at) VALUES (?, ?, ?, ?)`,
		key, data, len(data), time.Now().Unix(),
	)
	if err != nil {
		return "", 0, fmt.Errorf("blobstore: insert: %w", err)
	}
	return key, int64(len(data)), nil
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

// Delete removes a blob from the database.
func (s *SQLiteStore) Delete(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM blobs WHERE key = ?`, key)
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
		Checksums: false,
	}
}

// uuidV4 is defined in fs.go (same package).
