package imap

import (
	"context"
	"database/sql"
	"log/slog"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/backend"
	"github.com/i-got-this-faa/marco/pkg/auth"
	"github.com/i-got-this-faa/marco/pkg/blobstore"
)

// Backend implements backend.Backend for the IMAP server.
type Backend struct {
	db       *sql.DB
	blob     blobstore.Store
	auth     *auth.Manager
	log      *slog.Logger
	notifier *MailboxNotifier
}

// NewBackend creates a new IMAP backend.
func NewBackend(db *sql.DB, blob blobstore.Store, am *auth.Manager) *Backend {
	return &Backend{
		db:       db,
		blob:     blob,
		auth:     am,
		log:      slog.With("service", "imap"),
		notifier: NewMailboxNotifier(),
	}
}

// Login authenticates a user and returns a backend.User.
func (be *Backend) Login(connInfo *imap.ConnInfo, username, password string) (backend.User, error) {
	userID, err := be.auth.Authenticate(context.Background(), username, password)
	if err != nil {
		return nil, err
	}

	return &User{
		userID:   userID,
		email:    username,
		db:       be.db,
		blob:     be.blob,
		log:      be.log,
		notifier: be.notifier,
	}, nil
}
