package marco

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/i-got-this-faa/marco/pkg/config"
	"github.com/i-got-this-faa/marco/pkg/storage"
	_ "modernc.org/sqlite"
)

// Backup creates a tarball of the database and blob store at the given path.
func Backup(cfgPath, outputPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("backup: load config: %w", err)
	}

	db, err := storage.Open(cfg.Storage.Path)
	if err != nil {
		return fmt.Errorf("backup: open db: %w", err)
	}
	defer db.Close()

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("backup: create output: %w", err)
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	// Backup SQLite database.
	dbPath := cfg.Storage.Path
	if err := addFileToTar(tw, "marco.db", dbPath); err != nil {
		return fmt.Errorf("backup: db: %w", err)
	}

	// Backup blobs from SQLite backend.
	if cfg.Storage.BlobBackend == "sqlite" {
		if err := backupSQLiteBlobs(tw, db); err != nil {
			return fmt.Errorf("backup: sqlite blobs: %w", err)
		}
	}

	// Backup blobs from filesystem backend.
	if cfg.Storage.BlobBackend == "filesystem" {
		if err := backupFSBlobs(tw, cfg.Storage.BlobPath); err != nil {
			return fmt.Errorf("backup: fs blobs: %w", err)
		}
	}

	return nil
}

func addFileToTar(tw *tar.Writer, name, path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	hdr, err := tar.FileInfoHeader(fi, "")
	if err != nil {
		return err
	}
	hdr.Name = name

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}

func backupSQLiteBlobs(tw *tar.Writer, db *sql.DB) error {
	rows, err := db.Query(`SELECT key, data FROM blobs`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var key string
		var data []byte
		if err := rows.Scan(&key, &data); err != nil {
			return err
		}
		hdr := &tar.Header{
			Name: "blobs/" + key,
			Size: int64(len(data)),
			Mode: 0644,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(data); err != nil {
			return err
		}
	}
	return rows.Err()
}

func backupFSBlobs(tw *tar.Writer, root string) error {
	return filepath.Walk(root, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		// The key is the filename (last element of the path).
		key := filepath.Base(path)
		return addFileToTar(tw, "blobs/"+key, path)
	})
}

// Restore reads a backup tarball and restores the database and blobs.
func Restore(cfgPath, backupPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("restore: load config: %w", err)
	}

	f, err := os.Open(backupPath)
	if err != nil {
		return fmt.Errorf("restore: open backup: %w", err)
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("restore: gzip: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)

	var dbData []byte
	blobs := make(map[string][]byte)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("restore: tar: %w", err)
		}

		data, err := io.ReadAll(tr)
		if err != nil {
			return fmt.Errorf("restore: read %s: %w", hdr.Name, err)
		}

		switch hdr.Name {
		case "marco.db":
			dbData = data
		default:
			// Strip "blobs/" prefix to get key.
			if len(hdr.Name) > 6 && hdr.Name[:6] == "blobs/" {
				key := hdr.Name[6:]
				// Validate SHA-256 key.
				h := sha256.Sum256(data)
				if fmt.Sprintf("%x", h) != key {
					return fmt.Errorf("restore: blob %s: content hash mismatch", key)
				}
				blobs[key] = data
			}
		}
	}

	// Restore the database.
	if dbData == nil {
		return fmt.Errorf("restore: no database found in backup")
	}
	if err := os.WriteFile(cfg.Storage.Path, dbData, 0644); err != nil {
		return fmt.Errorf("restore: write db: %w", err)
	}

	// Reopen the database to run migrations.
	db, err := storage.Open(cfg.Storage.Path)
	if err != nil {
		return fmt.Errorf("restore: open restored db: %w", err)
	}
	defer db.Close()

	if err := storage.Migrate(db); err != nil {
		return fmt.Errorf("restore: migrate: %w", err)
	}

	// Restore blobs.
	if cfg.Storage.BlobBackend == "sqlite" {
		if err := restoreSQLiteBlobs(db, blobs); err != nil {
			return fmt.Errorf("restore: sqlite blobs: %w", err)
		}
	}

	if cfg.Storage.BlobBackend == "filesystem" {
		for key, data := range blobs {
			shard := filepath.Join(cfg.Storage.BlobPath, key[0:2], key[2:4])
			path := filepath.Join(shard, key)
			if err := os.MkdirAll(shard, 0755); err != nil {
				return fmt.Errorf("restore: mkdir: %w", err)
			}
			if err := os.WriteFile(path, data, 0644); err != nil {
				return fmt.Errorf("restore: write blob %s: %w", key, err)
			}
		}
	}

	return nil
}

func restoreSQLiteBlobs(db *sql.DB, blobs map[string][]byte) error {
	for key, data := range blobs {
		_, err := db.Exec(
			`INSERT OR IGNORE INTO blobs (key, data, size, created_at, refcount) VALUES (?, ?, ?, strftime('%s','now'), 1)`,
			key, data, len(data),
		)
		if err != nil {
			return fmt.Errorf("restore: insert blob %s: %w", key, err)
		}
	}
	return nil
}
