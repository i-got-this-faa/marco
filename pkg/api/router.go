package api

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/i-got-this-faa/marco/pkg/auth"
	"github.com/i-got-this-faa/marco/pkg/config"
	"github.com/i-got-this-faa/marco/pkg/dkim"
	"github.com/i-got-this-faa/marco/pkg/metrics"
	"github.com/i-got-this-faa/marco/pkg/queue"
)

// NewRouter creates the HTTP handler with all routes.
func NewRouter(db *sql.DB, qm *queue.Manager, am *auth.Manager, dk *dkim.Signer,
	sessionExpiry time.Duration, m *metrics.Registry, dkimCfg config.DKIMConfig, dkimPrivKeyPath string) http.Handler {
	mux := http.NewServeMux()

	h := &handlers{
		db:              db,
		qm:              qm,
		am:              am,
		dk:              dk,
		metrics:         m,
		promHandler:     m.HTTPHandler(),
		sessionExpiry:   sessionExpiry,
		dkimPrivKeyPath: dkimPrivKeyPath,
		dkimCfg:         dkimCfg,
	}

	authMW := func(next http.HandlerFunc) http.HandlerFunc {
		return requireAuthWithDB(db, next)
	}

	mux.HandleFunc("GET /api/health", h.handleHealth)
	mux.HandleFunc("POST /api/login", h.handleLogin)
	mux.HandleFunc("POST /api/logout", authMW(h.handleLogout))
	mux.HandleFunc("GET /api/users", authMW(h.handleListUsers))
	mux.HandleFunc("POST /api/users", authMW(h.handleCreateUser))
	mux.HandleFunc("PUT /api/users/{id}", authMW(h.handleUpdateUser))
	mux.HandleFunc("DELETE /api/users/{id}", authMW(h.handleDeleteUser))
	mux.HandleFunc("GET /api/domains", authMW(h.handleListDomains))
	mux.HandleFunc("POST /api/domains", authMW(h.handleCreateDomain))
	mux.HandleFunc("DELETE /api/domains/{name}", authMW(h.handleDeleteDomain))
	mux.HandleFunc("GET /api/aliases", authMW(h.handleListAliases))
	mux.HandleFunc("POST /api/aliases", authMW(h.handleCreateAlias))
	mux.HandleFunc("DELETE /api/aliases/{id}", authMW(h.handleDeleteAlias))
	mux.HandleFunc("GET /api/queue", authMW(h.handleListQueue))
	mux.HandleFunc("DELETE /api/queue/{id}", authMW(h.handleDeleteQueue))
	mux.HandleFunc("GET /api/stats", authMW(h.handleStats))
	mux.HandleFunc("POST /api/dkim/rotate", authMW(h.handleDKIMRotate))
	mux.HandleFunc("GET /api/metrics", h.handleMetrics)

	return mux
}
