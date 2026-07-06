package util

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
)

type correlationIDKey struct{}

// NewCorrelationID generates a random 32-hex-char correlation ID.
func NewCorrelationID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// WithCorrelationID returns a new context with the given correlation ID.
func WithCorrelationID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, correlationIDKey{}, id)
}

// NewContextWithCID returns a new context with a fresh correlation ID.
func NewContextWithCID(ctx context.Context) context.Context {
	return WithCorrelationID(ctx, NewCorrelationID())
}

// CorrelationIDFromContext extracts the correlation ID, returning empty if not set.
func CorrelationIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(correlationIDKey{}).(string)
	return id
}

// LoggerWithCorrelationID returns a logger that includes the correlation ID.
func LoggerWithCorrelationID(ctx context.Context) *slog.Logger {
	id := CorrelationIDFromContext(ctx)
	if id == "" {
		return slog.Default()
	}
	return slog.Default().With("correlation_id", id)
}
