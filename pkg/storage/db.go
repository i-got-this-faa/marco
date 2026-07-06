package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"

	"modernc.org/sqlite"
)

// Open opens a SQLite database at path, configured with WAL mode
// and synchronous=NORMAL for performance. Foreign key constraints
// are enabled.
func Open(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_synchronous=NORMAL")
	if err != nil {
		return nil, fmt.Errorf("storage: open %s: %w", path, err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("storage: ping %s: %w", path, err)
	}

	// Enable foreign key constraints (DSN parameter doesn't work with modernc).
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return nil, fmt.Errorf("storage: enable foreign keys: %w", err)
	}

	return db, nil
}

// Migrate runs all pending schema migrations in order, using PRAGMA
// user_version for version tracking.
func Migrate(db *sql.DB) error {
	var currentVersion int
	if err := db.QueryRow("PRAGMA user_version").Scan(&currentVersion); err != nil {
		return fmt.Errorf("storage: read version: %w", err)
	}

	// Sort migrations by version (defensive; they should already be ordered).
	sorted := make([]struct {
		version int
		ddl     string
	}, len(migrations))
	copy(sorted, migrations)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].version < sorted[j].version
	})

	for _, m := range sorted {
		if m.version <= currentVersion {
			continue
		}
		if _, err := db.Exec(m.ddl); err != nil {
			return fmt.Errorf("storage: migration v%d: %w", m.version, err)
		}
		if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", m.version)); err != nil {
			return fmt.Errorf("storage: set version %d: %w", m.version, err)
		}
	}

	return nil
}

// isUniqueConstraint returns true if err is an SQLite UNIQUE constraint violation.
func isUniqueConstraint(err error) bool {
	var se *sqlite.Error
	if errors.As(err, &se) {
		return se.Code() == 2067 // SQLITE_CONSTRAINT_UNIQUE
	}
	return false
}
