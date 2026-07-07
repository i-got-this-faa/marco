package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Contact represents an entry in a user's address book.
type Contact struct {
	ID        int64  `json:"id"`
	UserID    int64  `json:"user_id"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	CreatedAt int64  `json:"created_at"`
}

// CreateContact adds a new contact for a user.
func CreateContact(ctx context.Context, db *sql.DB, userID int64, name, email string) (int64, error) {
	res, err := db.ExecContext(ctx,
		`INSERT INTO contacts (user_id, name, email, created_at) VALUES (?, ?, ?, ?)`,
		userID, name, email, time.Now().Unix(),
	)
	if err != nil {
		if isConstraintError(err) {
			return 0, fmt.Errorf("storage: create contact: %w", ErrAlreadyExists)
		}
		return 0, fmt.Errorf("storage: create contact: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("storage: create contact lastid: %w", err)
	}
	return id, nil
}

// ListContacts returns all contacts for a user, ordered by name then email.
func ListContacts(ctx context.Context, db *sql.DB, userID int64) ([]*Contact, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, user_id, name, email, created_at FROM contacts WHERE user_id = ? ORDER BY name, email`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("storage: list contacts: %w", err)
	}
	defer rows.Close()

	var contacts []*Contact
	for rows.Next() {
		c := &Contact{}
		if err := rows.Scan(&c.ID, &c.UserID, &c.Name, &c.Email, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("storage: list contacts scan: %w", err)
		}
		contacts = append(contacts, c)
	}
	return contacts, rows.Err()
}

// DeleteContact removes a contact by ID if it belongs to the user.
func DeleteContact(ctx context.Context, db *sql.DB, userID, contactID int64) error {
	res, err := db.ExecContext(ctx,
		`DELETE FROM contacts WHERE id = ? AND user_id = ?`,
		contactID, userID,
	)
	if err != nil {
		return fmt.Errorf("storage: delete contact: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("storage: delete contact: %w", ErrNotFound)
	}
	return nil
}
