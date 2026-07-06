package imap

import (
	"context"
	"database/sql"
	"log/slog"

	"github.com/emersion/go-imap/backend"
	"github.com/i-got-this-faa/marco/pkg/blobstore"
	"github.com/i-got-this-faa/marco/pkg/storage"
)

// User implements backend.User for a single IMAP session.
type User struct {
	userID   int64
	email    string
	db       *sql.DB
	blob     blobstore.Store
	log      *slog.Logger
	notifier *MailboxNotifier
}

// Username returns this user's username (email).
func (u *User) Username() string {
	return u.email
}

// ListMailboxes returns all mailboxes for this user.
func (u *User) ListMailboxes(subscribed bool) ([]backend.Mailbox, error) {
	mboxes, err := storage.ListMailboxes(context.TODO(), u.db, u.userID)
	if err != nil {
		return nil, err
	}

	results := make([]backend.Mailbox, len(mboxes))
	for i, m := range mboxes {
		results[i] = &Mailbox{
			user:      *u,
			mailboxID: m.ID,
			name:      m.Name,
			notifier:  u.notifier,
		}
	}
	return results, nil
}

// GetMailbox returns a specific mailbox by name.
func (u *User) GetMailbox(name string) (backend.Mailbox, error) {
	m, err := storage.GetMailbox(context.TODO(), u.db, u.userID, name)
	if err != nil {
		return nil, err
	}
	return &Mailbox{
		user:      *u,
		mailboxID: m.ID,
		name:      m.Name,
		notifier:  u.notifier,
	}, nil
}

// CreateMailbox creates a new mailbox.
func (u *User) CreateMailbox(name string) error {
	_, err := storage.CreateMailbox(context.TODO(), u.db, u.userID, name)
	return err
}

// DeleteMailbox deletes a mailbox.
func (u *User) DeleteMailbox(name string) error {
	m, err := storage.GetMailbox(context.TODO(), u.db, u.userID, name)
	if err != nil {
		return err
	}
	return storage.DeleteMailbox(context.TODO(), u.db, m.ID)
}

// RenameMailbox renames a mailbox.
func (u *User) RenameMailbox(existingName, newName string) error {
	m, err := storage.GetMailbox(context.TODO(), u.db, u.userID, existingName)
	if err != nil {
		return err
	}
	return storage.RenameMailbox(context.TODO(), u.db, m.ID, newName)
}

// Logout is called when the user logs out.
func (u *User) Logout() error {
	u.log.Debug("imap logout", "user", u.email)
	return nil
}
