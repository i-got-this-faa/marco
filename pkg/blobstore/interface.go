package blobstore

import (
	"context"
	"io"
)

// Capabilities describes what a blob store implementation supports.
type Capabilities struct {
	Streaming bool
	RangeRead bool
	Checksums bool
}

// Store is the interface for storing and retrieving raw message blobs.
type Store interface {
	Put(ctx context.Context, r io.Reader, metadata map[string]string) (key string, size int64, err error)
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	Delete(ctx context.Context, key string) error
	Exists(ctx context.Context, key string) (bool, error)
	Capabilities() Capabilities
}
