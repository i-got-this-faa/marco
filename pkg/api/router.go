package api

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/i-got-this-faa/marco/pkg/auth"
	"github.com/i-got-this-faa/marco/pkg/blobstore"
	"github.com/i-got-this-faa/marco/pkg/dkim"
	"github.com/i-got-this-faa/marco/pkg/queue"
)

// NewRouter creates the HTTP handler with all routes.
func NewRouter(db *sql.DB, blob blobstore.Store, qm *queue.Manager, am *auth.Manager, dk *dkim.Signer, sessionExpiry time.Duration) http.Handler {
	mux := http.NewServeMux()

	h := &handlers{
		db:            db,
		blob:          blob,
		qm:            qm,
		am:            am,
		dk:            dk,
		sessionExpiry: sessionExpiry,
	}

	authMW := func(next http.HandlerFunc) http.HandlerFunc {
		return requireAuthWithDB(db, next)
	}

	mux.HandleFunc("GET /api/health", h.handleHealth)
	mux.HandleFunc("POST /api/login", h.handleLogin)
	mux.HandleFunc("POST /api/logout", authMW(h.handleLogout))
	mux.HandleFunc("GET /api/users", authMW(h.handleListUsers))
	mux.HandleFunc("POST /api/users", authMW(h.handleCreateUser))
	mux.HandleFunc("GET /api/domains", authMW(h.handleListDomains))
	mux.HandleFunc("POST /api/domains", authMW(h.handleCreateDomain))
	mux.HandleFunc("DELETE /api/domains/{name}", authMW(h.handleDeleteDomain))
	mux.HandleFunc("GET /api/aliases", authMW(h.handleListAliases))
	mux.HandleFunc("POST /api/aliases", authMW(h.handleCreateAlias))
	mux.HandleFunc("DELETE /api/aliases/{id}", authMW(h.handleDeleteAlias))
	mux.HandleFunc("GET /api/queue", authMW(h.handleListQueue))
	mux.HandleFunc("DELETE /api/queue/{id}", authMW(h.handleDeleteQueue))
	mux.HandleFunc("GET /api/stats", authMW(h.handleStats))

	// User-scoped email browser endpoints.
	mux.HandleFunc("GET /api/me", authMW(h.handleMe))
	mux.HandleFunc("GET /api/mailboxes", authMW(h.handleListMailboxes))
	mux.HandleFunc("GET /api/mailboxes/{id}/messages", authMW(h.handleListMailboxMessages))
	mux.HandleFunc("GET /api/messages/{id}", authMW(h.handleGetMessage))
	mux.HandleFunc("POST /api/messages/{id}/flags", authMW(h.handleUpdateFlags))
	mux.HandleFunc("POST /api/messages/send", authMW(h.handleSendMessage))
	mux.HandleFunc("GET /api/contacts", authMW(h.handleListContacts))
	mux.HandleFunc("POST /api/contacts", authMW(h.handleCreateContact))
	mux.HandleFunc("DELETE /api/contacts/{id}", authMW(h.handleDeleteContact))

	return mux
}
