package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/i-got-this-faa/marco/pkg/cache"
)

// sessionCache caches validated session tokens with a 60s TTL.
var sessionCache = cache.New[string, int64](60*time.Second, 10000)

// CreateSession generates a session token for a user and stores it.
func CreateSession(ctx context.Context, db *sql.DB, userID int64, expiry time.Duration) (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("auth: create session: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)
	expiresAt := time.Now().Add(expiry).Unix()

	_, err := db.ExecContext(ctx,
		`INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)`,
		token, userID, expiresAt,
	)
	if err != nil {
		return "", fmt.Errorf("auth: insert session: %w", err)
	}
	return token, nil
}

// ValidateSession checks a session token and returns the associated user ID.
func ValidateSession(ctx context.Context, db *sql.DB, token string) (int64, error) {
	if userID, ok := sessionCache.Get(token); ok {
		return userID, nil
	}

	var userID int64
	var expiresAt int64
	err := db.QueryRowContext(ctx,
		`SELECT user_id, expires_at FROM sessions WHERE token = ?`, token,
	).Scan(&userID, &expiresAt)
	if err == sql.ErrNoRows {
		return 0, fmt.Errorf("auth: invalid session")
	}
	if err != nil {
		return 0, fmt.Errorf("auth: validate session: %w", err)
	}

	if time.Now().Unix() > expiresAt {
		// Clean up expired token.
		sessionCache.Delete(token)
		_, _ = db.ExecContext(ctx, `DELETE FROM sessions WHERE token = ?`, token)
		return 0, fmt.Errorf("auth: session expired")
	}
	sessionCache.Set(token, userID)
	return userID, nil
}

// RevokeSession deletes a session token.
func RevokeSession(ctx context.Context, db *sql.DB, token string) error {
	sessionCache.Delete(token)
	_, err := db.ExecContext(ctx, `DELETE FROM sessions WHERE token = ?`, token)
	if err != nil {
		return fmt.Errorf("auth: revoke session: %w", err)
	}
	return nil
}
