package storage

import (
	"context"
	"database/sql"
	"fmt"
)

// ListAliases returns all email aliases.
func ListAliases(ctx context.Context, db *sql.DB) ([]*Alias, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, source, destination, domain FROM aliases ORDER BY domain, source`,
	)
	if err != nil {
		return nil, fmt.Errorf("storage: list aliases: %w", err)
	}
	defer rows.Close()

	var aliases []*Alias
	for rows.Next() {
		a := &Alias{}
		if err := rows.Scan(&a.ID, &a.Source, &a.Destination, &a.Domain); err != nil {
			return nil, fmt.Errorf("storage: list aliases scan: %w", err)
		}
		aliases = append(aliases, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: list aliases rows: %w", err)
	}
	if aliases == nil {
		aliases = []*Alias{}
	}
	return aliases, nil
}

// CreateAlias inserts a new alias and returns its ID.
func CreateAlias(ctx context.Context, db *sql.DB, source, destination, domain string) (int64, error) {
	res, err := db.ExecContext(ctx,
		`INSERT INTO aliases (source, destination, domain) VALUES (?, ?, ?)`,
		source, destination, domain,
	)
	if err != nil {
		if isUniqueConstraint(err) {
			return 0, fmt.Errorf("%w: alias %q already exists for domain %q", ErrAlreadyExists, source, domain)
		}
		return 0, fmt.Errorf("storage: create alias %q: %w", source, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("storage: create alias lastid: %w", err)
	}
	return id, nil
}

// DeleteAlias removes an alias by ID.
func DeleteAlias(ctx context.Context, db *sql.DB, id int64) error {
	res, err := db.ExecContext(ctx, `DELETE FROM aliases WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("storage: delete alias %d: %w", id, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("%w: alias %d", ErrNotFound, id)
	}
	return nil
}

// GetAlias looks up an alias by source and domain.
func GetAlias(ctx context.Context, db *sql.DB, source, domain string) (*Alias, error) {
	a := &Alias{}
	err := db.QueryRowContext(ctx,
		`SELECT id, source, destination, domain FROM aliases WHERE source = ? AND domain = ?`,
		source, domain,
	).Scan(&a.ID, &a.Source, &a.Destination, &a.Domain)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("%w: alias %q for domain %q", ErrNotFound, source, domain)
	}
	if err != nil {
		return nil, fmt.Errorf("storage: get alias: %w", err)
	}
	return a, nil
}

// GetAliasesByDomain returns all aliases for a given domain.
func GetAliasesByDomain(ctx context.Context, db *sql.DB, domain string) ([]*Alias, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, source, destination, domain FROM aliases WHERE domain = ? ORDER BY source`,
		domain,
	)
	if err != nil {
		return nil, fmt.Errorf("storage: get aliases by domain: %w", err)
	}
	defer rows.Close()

	var aliases []*Alias
	for rows.Next() {
		a := &Alias{}
		if err := rows.Scan(&a.ID, &a.Source, &a.Destination, &a.Domain); err != nil {
			return nil, fmt.Errorf("storage: get aliases by domain scan: %w", err)
		}
		aliases = append(aliases, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: get aliases by domain rows: %w", err)
	}
	if aliases == nil {
		aliases = []*Alias{}
	}
	return aliases, nil
}
