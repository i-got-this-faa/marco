package auth

import (
	"context"
	"fmt"

	"github.com/emersion/go-sasl"
)

// SMTPAuth returns a sasl server that can be used for SMTP AUTH.
// It wraps the auth Manager for the PLAIN mechanism.
func SMTPAuth(m *Manager) sasl.Server {
	return sasl.NewPlainServer(func(identity, username, password string) error {
		_, err := m.Authenticate(context.Background(), username, password)
		if err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
		return nil
	})
}

// LoginFunc matches the go-imap Backend.Login signature.
type LoginFunc func(conn interface{}, username, password string) (interface{}, error)

// AuthAdapter adapts an auth.Manager into a function suitable for
// IMAP server login.
func AuthAdapter(m *Manager) LoginFunc {
	return func(conn interface{}, username, password string) (interface{}, error) {
		userID, err := m.Authenticate(context.Background(), username, password)
		if err != nil {
			return nil, err
		}
		return userID, nil
	}
}
