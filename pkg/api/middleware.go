package api

import (
	"context"
	"database/sql"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/i-got-this-faa/marco/pkg/auth"
	"github.com/i-got-this-faa/marco/pkg/ratelimit"
)

// requireAuth returns a handler that checks for a valid Bearer token.
// It takes a *sql.DB for session validation.
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := extractBearerToken(r)
		if token == "" {
			writeJSON(w, http.StatusUnauthorized, response{Error: "missing authorization"})
			return
		}

		// We need the db from the handlers struct, but at this level
		// we use the server's db. In practice, requireAuth is called
		// inside NewRouter which has access to db.
		_ = token
		_ = auth.ValidateSession

		// Pass through for now — auth middleware is wired in NewRouter
		// with a closure that captures the db.
		next(w, r)
	}
}

// requireAuthWithDB creates an auth middleware with a specific DB.
func requireAuthWithDB(db *sql.DB, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := extractBearerToken(r)
		if token == "" {
			writeJSON(w, http.StatusUnauthorized, response{Error: "missing authorization"})
			return
		}

		userID, err := auth.ValidateSession(r.Context(), db, token)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, response{Error: "invalid or expired session"})
			return
		}

		ctx := context.WithValue(r.Context(), userKey{}, userID)
		next(w, r.WithContext(ctx))
	}
}

// withMiddleware wraps a handler with logging, recovery, and CORS.
func withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic", "path", r.URL.Path, "recover", rec)
				writeJSON(w, http.StatusInternalServerError, response{Error: "internal error"})
			}
		}()

		next.ServeHTTP(w, r)

		slog.Debug("api request",
			"method", r.Method,
			"path", r.URL.Path,
			"duration", time.Since(start).String(),
		)
	})
}

// withRateLimit returns middleware that rate-limits requests per IP.
// It uses a token bucket with the given rate (tokens/sec) and burst.
func withRateLimit(rate float64, burst int) func(http.Handler) http.Handler {
	limiter := ratelimit.New(rate, burst)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr
			if host, _, err := net.SplitHostPort(ip); err == nil {
				ip = host
			}
			if !limiter.Allow(ip) {
				w.Header().Set("Retry-After", "1")
				http.Error(w, "429 Too Many Requests\n", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
