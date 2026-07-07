package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)
// ListDomains returns all domain names.
func ListDomains(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT name FROM domains ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("storage: list domains: %w", err)
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("storage: list domains scan: %w", err)
		}
		domains = append(domains, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: list domains rows: %w", err)
	}
	if domains == nil {
		domains = []string{}
	}
	return domains, nil
}

// CreateDomain inserts a new domain.
func CreateDomain(ctx context.Context, db *sql.DB, name string) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO domains (name) VALUES (?)`, strings.ToLower(name),
	)
	if err != nil {
		if isUniqueConstraint(err) {
			return fmt.Errorf("%w: domain %q already exists", ErrAlreadyExists, name)
		}
		return fmt.Errorf("storage: create domain %q: %w", name, err)
	}
	return nil
}

// DeleteDomain removes a domain by name.
func DeleteDomain(ctx context.Context, db *sql.DB, name string) error {
	res, err := db.ExecContext(ctx, `DELETE FROM domains WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("storage: delete domain %q: %w", name, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("%w: domain %q", ErrNotFound, name)
	}
	return nil
}

// IsLocalDomain checks whether a domain is registered on this server.
func IsLocalDomain(ctx context.Context, db *sql.DB, domain string) (bool, error) {
	err := db.QueryRowContext(ctx, `SELECT 1 FROM domains WHERE name = ?`, strings.ToLower(domain)).Scan(new(int))
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("storage: check domain %q: %w", domain, err)
	}
	return true, nil
}
