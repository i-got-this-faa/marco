package api

import (
	"crypto/tls"
	"database/sql"
	"net/http"

	"github.com/i-got-this-faa/marco/pkg/auth"
	"github.com/i-got-this-faa/marco/pkg/config"
	"github.com/i-got-this-faa/marco/pkg/dkim"
	"github.com/i-got-this-faa/marco/pkg/queue"
)

// NewServer creates the admin HTTP API server.
func NewServer(cfg *config.AdminConfig, db *sql.DB, qm *queue.Manager,
	am *auth.Manager, dk *dkim.Signer, tlsCfg *tls.Config) *http.Server {

	mux := NewRouter(db, qm, am, dk, cfg.SessionExpiry)

	var handler http.Handler = mux
	handler = withMiddleware(handler)
	if cfg.RateLimit > 0 {
		handler = withRateLimit(cfg.RateLimit, cfg.RateLimitBurst)(handler)
	}

	return &http.Server{
		Addr:      cfg.ListenAddr,
		Handler:   handler,
		TLSConfig: tlsCfg,
	}
}
