package api

import (
	"crypto/tls"
	"database/sql"
	"net/http"

	"github.com/i-got-this-faa/marco/pkg/auth"
	"github.com/i-got-this-faa/marco/pkg/blobstore"
	"github.com/i-got-this-faa/marco/pkg/config"
	"github.com/i-got-this-faa/marco/pkg/dkim"
	"github.com/i-got-this-faa/marco/pkg/metrics"
	"github.com/i-got-this-faa/marco/pkg/queue"
)

// NewServer creates the admin HTTP API server.
func NewServer(cfg *config.AdminConfig, db *sql.DB, blob blobstore.Store, qm *queue.Manager,
	am *auth.Manager, dk *dkim.Signer, tlsCfg *tls.Config, m *metrics.Registry, dkimCfg config.DKIMConfig, dkimPrivKeyPath string) *http.Server {

	mux := NewRouter(db, blob, qm, am, dk, cfg.SessionExpiry, m, dkimCfg, dkimPrivKeyPath)

	return &http.Server{
		Addr:      cfg.ListenAddr,
		Handler:   withMiddleware(mux),
		TLSConfig: tlsCfg,
	}
}
