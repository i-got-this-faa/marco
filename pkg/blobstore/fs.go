package blobstore

import (
	"context"
	"crypto/rand"
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

// Put writes a blob from a reader to the filesystem. It returns a
// UUID v4 key that can be used to retrieve the blob later.
func (s *FSStore) Put(ctx context.Context, r io.Reader, metadata map[string]string) (string, int64, error) {
	key := uuidV4()
	shard := filepath.Join(s.root, key[0:2], key[2:4])
	path := filepath.Join(shard, key)

	if err := os.MkdirAll(shard, 0755); err != nil {
		return "", 0, fmt.Errorf("blobstore: mkdir: %w", err)
	}

	f, err := os.Create(path)
	if err != nil {
		return "", 0, fmt.Errorf("blobstore: create: %w", err)
	}
	defer f.Close()

	written, err := io.Copy(f, r)
	if err != nil {
		return "", 0, fmt.Errorf("blobstore: write: %w", err)
	}

	return key, written, nil
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
		Checksums: false,
	}
}
