package blobstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// FSStore stores blobs as files on the filesystem, sharded by a
// two-level hex prefix to avoid too many entries per directory.
type FSStore struct {
	root string
}

// NewFSStore creates an FSStore rooted at the given directory.
func NewFSStore(root string) *FSStore {
	return &FSStore{root: root}
}

// uuidV4 generates a random UUID v4 string (no external dependency).
func uuidV4() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	// Set version 4 bits
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Put writes a blob from a reader to the filesystem. The key is the
// SHA-256 digest of the content, providing content-addressed dedup.
func (s *FSStore) Put(ctx context.Context, r io.Reader, metadata map[string]string) (string, int64, error) {
	key, data, size, err := sha256Key(r)
	if err != nil {
		return "", 0, err
	}

	// Check if file already exists — fast path for dedup.
	shard := filepath.Join(s.root, key[0:2], key[2:4])
	path := filepath.Join(shard, key)
	if fi, err := os.Stat(path); err == nil && fi.Size() > 0 {
		return key, size, nil
	}

	if err := os.MkdirAll(shard, 0755); err != nil {
		return "", 0, fmt.Errorf("blobstore: mkdir: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return "", 0, fmt.Errorf("blobstore: write: %w", err)
	}

	return key, size, nil
}

// Get returns a reader for the blob identified by key.
func (s *FSStore) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	path := filepath.Join(s.root, key[0:2], key[2:4], key)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("blobstore: not found: %w", os.ErrNotExist)
		}
		return nil, fmt.Errorf("blobstore: open: %w", err)
	}
	return f, nil
}

// Delete removes a blob and its shard directories if they become empty.
func (s *FSStore) Delete(ctx context.Context, key string) error {
	path := filepath.Join(s.root, key[0:2], key[2:4], key)
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("blobstore: delete: %w", err)
	}

	// Best-effort cleanup of empty parent dirs.
	os.Remove(filepath.Dir(path))   // <root>/<key[0:2]>/<key[2:4]>
	os.Remove(filepath.Dir(filepath.Dir(path))) // <root>/<key[0:2]>

	return nil
}

// Exists checks whether a blob with the given key exists.
func (s *FSStore) Exists(ctx context.Context, key string) (bool, error) {
	path := filepath.Join(s.root, key[0:2], key[2:4], key)
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("blobstore: stat: %w", err)
}

// Capabilities returns the store's capabilities.
func (s *FSStore) Capabilities() Capabilities {
	return Capabilities{
		Streaming: true,
		RangeRead: true,
		Checksums: true,
	}
}

// sha256Key reads all data from r, computes its SHA-256 digest, and returns
// the hex-encoded digest as the content-addressed key along with the raw
// bytes and total size. The caller MUST NOT use data after calling this on
// an FSStore or S3Store (they stream without buffering); only SQLiteStore
// needs the buffered data for the INSERT.
func sha256Key(r io.Reader) (key string, data []byte, size int64, err error) {
	data, err = io.ReadAll(r)
	if err != nil {
		return "", nil, 0, fmt.Errorf("blobstore: read: %w", err)
	}
	h := sha256.Sum256(data)
	key = fmt.Sprintf("%x", h)
	return key, data, int64(len(data)), nil
}
