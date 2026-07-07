package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/i-got-this-faa/marco/pkg/cache"
)

// userByEmailCache caches user lookups with a 30s TTL.
var userByEmailCache = cache.New[string, *User](30*time.Second, 5000)

// CreateUser inserts a new user and returns its ID.
func CreateUser(ctx context.Context, db *sql.DB, email, passwordHash string, isAdmin bool) (int64, error) {
	res, err := db.ExecContext(ctx,
		`INSERT INTO users (email, password_hash, created_at, is_admin) VALUES (?, ?, ?, ?)`,
		email, passwordHash, time.Now().Unix(), isAdmin,
	)
	if err != nil {
		if isConstraintError(err) {
			return 0, fmt.Errorf("storage: create user: %w", ErrAlreadyExists)
		}
		return 0, fmt.Errorf("storage: create user: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("storage: create user lastid: %w", err)
	}
	userByEmailCache.Delete(email)
	return id, nil
}

// GetUserByEmail looks up a user by their email address.
func GetUserByEmail(ctx context.Context, db *sql.DB, email string) (*User, error) {
	if u, ok := userByEmailCache.Get(email); ok {
		return u, nil
	}

	u := &User{}
	err := db.QueryRowContext(ctx,
		`SELECT id, email, password_hash, created_at, is_active, is_admin FROM users WHERE email = ?`,
		email,
	).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt, &u.IsActive, &u.IsAdmin)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("storage: user not found: %w", ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("storage: get user by email: %w", err)
	}
	userByEmailCache.Set(email, u)
	return u, nil
}

// GetUserByID looks up a user by their ID.
func GetUserByID(ctx context.Context, db *sql.DB, id int64) (*User, error) {
	u := &User{}
	err := db.QueryRowContext(ctx,
		`SELECT id, email, password_hash, created_at, is_active, is_admin FROM users WHERE id = ?`,
		id,
	).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt, &u.IsActive, &u.IsAdmin)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("storage: user not found: %w", ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("storage: get user by id: %w", err)
	}
	return u, nil
}

// ListUsers returns all users.
func ListUsers(ctx context.Context, db *sql.DB) ([]*User, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, email, password_hash, created_at, is_active, is_admin FROM users ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("storage: list users: %w", err)
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		u := &User{}
		if err := rows.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt, &u.IsActive, &u.IsAdmin); err != nil {
			return nil, fmt.Errorf("storage: list users scan: %w", err)
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: list users rows: %w", err)
	}
	return users, nil
}

// UpdateUser selectively updates user fields. Pass nil to leave a field unchanged.
func UpdateUser(ctx context.Context, db *sql.DB, id int64, email, passwordHash *string, isActive, isAdmin *bool) error {
	type setClause struct {
		expr string
		val  interface{}
	}
	var sets []setClause
	if email != nil {
		sets = append(sets, setClause{"email = ?", *email})
	}
	if passwordHash != nil {
		sets = append(sets, setClause{"password_hash = ?", *passwordHash})
	}
	if isActive != nil {
		sets = append(sets, setClause{"is_active = ?", *isActive})
	}
	if isAdmin != nil {
		sets = append(sets, setClause{"is_admin = ?", *isAdmin})
	}
	if len(sets) == 0 {
		return nil
	}

	q := "UPDATE users SET "
	args := make([]interface{}, 0, len(sets)+1)
	for i, s := range sets {
		if i > 0 {
			q += ", "
		}
		q += s.expr
		args = append(args, s.val)
	}
	q += " WHERE id = ?"
	args = append(args, id)

	res, err := db.ExecContext(ctx, q, args...)
	if err != nil {
		return fmt.Errorf("storage: update user: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("storage: update user: %w", ErrNotFound)
	}
	return nil
}

// DeleteUser removes a user by ID.
func DeleteUser(ctx context.Context, db *sql.DB, id int64) error {
	res, err := db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("storage: delete user: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("storage: delete user: %w", ErrNotFound)
	}
	return nil
}

// CountUsers returns the total number of users.
func CountUsers(ctx context.Context, db *sql.DB) (int, error) {
	var count int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("storage: count users: %w", err)
	}
	return count, nil
}

// GetUsersByEmail returns users matching any of the given emails (batch).
// The returned map has an entry for each email that was found; emails not
// found in the database are absent from the map.
func GetUsersByEmail(ctx context.Context, db *sql.DB, emails []string) (map[string]*User, error) {
	if len(emails) == 0 {
		return make(map[string]*User), nil
	}

	placeholders := make([]string, len(emails))
	args := make([]any, len(emails))
	for i, e := range emails {
		placeholders[i] = "?"
		args[i] = e
	}

	query := fmt.Sprintf(
		`SELECT id, email, password_hash, created_at, is_active, is_admin FROM users WHERE email IN (%s)`,
		strings.Join(placeholders, ","),
	)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("storage: get users by email: %w", err)
	}
	defer rows.Close()

	result := make(map[string]*User, len(emails))
	for rows.Next() {
		u := &User{}
		if err := rows.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt, &u.IsActive, &u.IsAdmin); err != nil {
			return nil, fmt.Errorf("storage: get users by email scan: %w", err)
		}
		result[u.Email] = u
	}
	return result, rows.Err()
}
