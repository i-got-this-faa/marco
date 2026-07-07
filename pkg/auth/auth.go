package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/i-got-this-faa/marco/pkg/storage"
)

// Sentinel errors returned by the auth manager.
var (
	ErrInvalidCredentials = errors.New("auth: invalid credentials")
	ErrUserInactive       = errors.New("auth: user is inactive")
)

// Manager handles user authentication and creation.
type Manager struct {
	db *sql.DB
}

// NewManager creates an auth manager backed by the given database.
func NewManager(db *sql.DB) *Manager {
	return &Manager{db: db}
}

// Authenticate verifies a username/password pair against the stored
// Argon2id hash. Returns the user ID on success.
func (m *Manager) Authenticate(ctx context.Context, username, password string) (int64, error) {
	user, err := storage.GetUserByEmail(ctx, m.db, username)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return 0, fmt.Errorf("%w: user not found", ErrInvalidCredentials)
		}
		return 0, fmt.Errorf("auth: get user: %w", err)
	}

	if !user.IsActive {
		return 0, fmt.Errorf("%w: %s", ErrUserInactive, user.Email)
	}

	ok, err := VerifyPassword(password, user.PasswordHash)
	if err != nil {
		return 0, fmt.Errorf("auth: verify password: %w", err)
	}
	if !ok {
		return 0, fmt.Errorf("%w: wrong password", ErrInvalidCredentials)
	}

	return user.ID, nil
}

// CreateUser hashes the password and creates a new user in storage.
// It also provisions the default set of mailboxes.
func (m *Manager) CreateUser(ctx context.Context, email, password string, isAdmin bool) (int64, error) {
	if err := ValidatePasswordStrength(password); err != nil {
		return 0, err
	}

	hash, err := HashPassword(password)
	if err != nil {
		return 0, err
	}

	userID, err := storage.CreateUser(ctx, m.db, email, hash, isAdmin)
	if err != nil {
		return 0, fmt.Errorf("auth: create user: %w", err)
	}

	if err := storage.EnsureDefaultMailboxes(ctx, m.db, userID); err != nil {
		return 0, fmt.Errorf("auth: create mailboxes: %w", err)
	}

	return userID, nil
}
