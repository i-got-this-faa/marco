package storage

import (
	"errors"
	"strings"
)

// Sentinel errors returned by storage functions.
var (
	ErrNotFound      = errors.New("storage: not found")
	ErrAlreadyExists = errors.New("storage: already exists")
	ErrMailboxFull   = errors.New("storage: mailbox full")
	ErrMaxRetries    = errors.New("storage: max retries exceeded")
)

// isConstraintError reports whether err is a SQL UNIQUE constraint violation.
func isConstraintError(err error) bool {
	return strings.Contains(err.Error(), "UNIQUE constraint")
}
