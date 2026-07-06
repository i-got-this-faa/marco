package blobstore

import (
	"context"
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func TestFSStorePutGet(t *testing.T) {
	dir := t.TempDir()
	s := NewFSStore(dir)

	ctx := context.Background()
	content := "hello world"
	key, _, err := s.Put(ctx, strings.NewReader(content), nil)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	if key == "" {
		t.Fatal("Put returned empty key")
	}

	rc, err := s.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if string(data) != content {
		t.Errorf("got %q, want %q", string(data), content)
	}
}

func TestFSStoreExists(t *testing.T) {
	dir := t.TempDir()
	s := NewFSStore(dir)
	ctx := context.Background()

	key, _, _ := s.Put(ctx, strings.NewReader("data"), nil)

	exists, err := s.Exists(ctx, key)
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if !exists {
		t.Error("expected blob to exist")
	}

	exists, err = s.Exists(ctx, "nonexistent-key")
	if err != nil {
		t.Fatalf("Exists on missing: %v", err)
	}
	if exists {
		t.Error("expected blob to NOT exist")
	}
}

func TestFSStoreDelete(t *testing.T) {
	dir := t.TempDir()
	s := NewFSStore(dir)
	ctx := context.Background()

	key, _, _ := s.Put(ctx, strings.NewReader("data"), nil)

	if err := s.Delete(ctx, key); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	exists, _ := s.Exists(ctx, key)
	if exists {
		t.Error("blob should not exist after delete")
	}

	// Deleting non-existent blob should not error.
	if err := s.Delete(ctx, "nonexistent"); err != nil {
		t.Errorf("Delete nonexistent: %v", err)
	}
}

func TestFSStoreLargeBlob(t *testing.T) {
	dir := t.TempDir()
	s := NewFSStore(dir)
	ctx := context.Background()

	large := strings.Repeat("A", 1024*1024) // 1 MB
	key, _, err := s.Put(ctx, strings.NewReader(large), nil)
	if err != nil {
		t.Fatalf("Put large failed: %v", err)
	}

	rc, _ := s.Get(ctx, key)
	data, _ := io.ReadAll(rc)
	rc.Close()

	if len(data) != len(large) {
		t.Errorf("large blob size = %d, want %d", len(data), len(large))
	}
}

func TestFSStoreCapabilities(t *testing.T) {
	s := NewFSStore(t.TempDir())
	c := s.Capabilities()
	if !c.Streaming {
		t.Error("FSStore should support streaming")
	}
	if !c.RangeRead {
		t.Error("FSStore should support range reads")
	}
	if !c.Checksums {
		t.Error("FSStore now supports checksums (content-addressed dedup)")
	}
}

func TestFSStoreShardingStructure(t *testing.T) {
	dir := t.TempDir()
	s := NewFSStore(dir)
	ctx := context.Background()

	key, _, _ := s.Put(ctx, strings.NewReader("data"), nil)
	expectedPath := filepath.Join(dir, key[0:2], key[2:4], key)

	if _, err := os.Stat(expectedPath); err != nil {
		t.Errorf("sharded path %s: %v", expectedPath, err)
	}
}

func TestSQLiteStorePutGet(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	_, err = db.Exec(`CREATE TABLE blobs (key TEXT PRIMARY KEY, data BLOB, size INTEGER, created_at INTEGER, refcount INTEGER NOT NULL DEFAULT 1)`)
	if err != nil {
		t.Fatal(err)
	}

	s := NewSQLiteStore(db)
	ctx := context.Background()

	key, _, err := s.Put(ctx, strings.NewReader("sqlite blob data"), nil)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	rc, _ := s.Get(ctx, key)
	data, _ := io.ReadAll(rc)
	rc.Close()

	if string(data) != "sqlite blob data" {
		t.Errorf("got %q, want %q", string(data), "sqlite blob data")
	}
}

func TestSQLiteStoreExists(t *testing.T) {
	db, _ := sql.Open("sqlite", ":memory:")
	db.Exec(`CREATE TABLE blobs (key TEXT PRIMARY KEY, data BLOB, size INTEGER, created_at INTEGER, refcount INTEGER NOT NULL DEFAULT 1)`)
	defer db.Close()

	s := NewSQLiteStore(db)
	ctx := context.Background()

	key, _, _ := s.Put(ctx, strings.NewReader("x"), nil)

	ok, _ := s.Exists(ctx, key)
	if !ok {
		t.Error("expected blob to exist")
	}

	ok, _ = s.Exists(ctx, "missing")
	if ok {
		t.Error("expected blob to NOT exist")
	}
}

func TestSQLiteStoreDelete(t *testing.T) {
	db, _ := sql.Open("sqlite", ":memory:")
	db.Exec(`CREATE TABLE blobs (key TEXT PRIMARY KEY, data BLOB, size INTEGER, created_at INTEGER, refcount INTEGER NOT NULL DEFAULT 1)`)
	defer db.Close()

	s := NewSQLiteStore(db)
	ctx := context.Background()

	key, _, _ := s.Put(ctx, strings.NewReader("x"), nil)
	s.Delete(ctx, key)

	rc, err := s.Get(ctx, key)
	if err == nil {
		rc.Close()
		t.Error("expected error after delete")
	}
}

func TestSQLiteStoreCapabilities(t *testing.T) {
	db, _ := sql.Open("sqlite", ":memory:")
	db.Exec(`CREATE TABLE blobs (key TEXT PRIMARY KEY, data BLOB, size INTEGER, created_at INTEGER, refcount INTEGER NOT NULL DEFAULT 1)`)
	defer db.Close()

	s := NewSQLiteStore(db)
	c := s.Capabilities()
	if c.Streaming {
		t.Error("SQLiteStore should NOT support streaming")
	}
}

func TestUUIDV4Format(t *testing.T) {
	u := uuidV4()
	if len(u) != 36 {
		t.Errorf("UUID length = %d, want 36", len(u))
	}
	if u[14] != '4' {
		t.Errorf("UUID version byte = %c, want '4'", u[14])
	}
}

func TestNewFSStore(t *testing.T) {
	s := NewFSStore("/tmp")
	if s.root != "/tmp" {
		t.Errorf("root = %q, want /tmp", s.root)
	}
}

func TestNewSQLiteStore(t *testing.T) {
	db, _ := sql.Open("sqlite", ":memory:")
	defer db.Close()
	s := NewSQLiteStore(db)
	if s == nil {
		t.Fatal("NewSQLiteStore returned nil")
	}
}

func TestFSStoreGetNonExistent(t *testing.T) {
	s := NewFSStore(t.TempDir())
	_, err := s.Get(context.Background(), "00000000-0000-0000-0000-000000000000")
	if err == nil {
		t.Error("expected error for non-existent blob")
	}
}
