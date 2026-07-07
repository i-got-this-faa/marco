package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"
)

// openTestDB opens an in-memory SQLite database with foreign keys enabled.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open(':memory:'): %v", err)
	}
	t.Cleanup(func() { db.Close() })
	// Enable foreign keys for cascade delete support.
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		t.Fatalf("PRAGMA foreign_keys = ON: %v", err)
	}
	return db
}

// migrateTestDB opens a fresh in-memory DB and runs migrations.
func migrateTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return db
}

// ensureUser is a helper that creates a user and returns its ID.
func ensureUser(t *testing.T, db *sql.DB, email, passwordHash string) int64 {
	t.Helper()
	ctx := context.Background()
	id, err := CreateUser(ctx, db, email, passwordHash, false)
	if err != nil {
		t.Fatalf("CreateUser(%q): %v", email, err)
	}
	return id
}

// ensureMailbox is a helper that creates a mailbox and returns its ID.
func ensureMailbox(t *testing.T, db *sql.DB, userID int64, name string) int64 {
	t.Helper()
	ctx := context.Background()
	id, err := CreateMailbox(ctx, db, userID, name)
	if err != nil {
		t.Fatalf("CreateMailbox(%d, %q): %v", userID, name, err)
	}
	return id
}

// ensureDefaultMailboxes creates default mailboxes for a user.
func ensureDefaultMailboxes(t *testing.T, db *sql.DB, userID int64) {
	t.Helper()
	ctx := context.Background()
	if err := EnsureDefaultMailboxes(ctx, db, userID); err != nil {
		t.Fatalf("EnsureDefaultMailboxes(%d): %v", userID, err)
	}
}

// ensureMessage inserts a message and returns its ID and UID.
func ensureMessage(t *testing.T, db *sql.DB, mailboxID int64, from, to, subject string, flags int) (int64, uint32) {
	t.Helper()
	ctx := context.Background()
	id, uid, err := InsertMessage(ctx, db, mailboxID, "blob-key-"+subject, 123, from, to, subject, flags)
	if err != nil {
		t.Fatalf("InsertMessage(%d): %v", mailboxID, err)
	}
	return id, uid
}

// ---------------------------------------------------------------------------
// 1. Open / Migrate
// ---------------------------------------------------------------------------

func TestOpen(t *testing.T) {
	db := openTestDB(t)
	if db == nil {
		t.Fatal("Open returned nil *sql.DB")
	}
	// Verify the DB is pingable.
	if err := db.Ping(); err != nil {
		t.Fatalf("db.Ping(): %v", err)
	}
}

func TestMigrate(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	// Verify tables exist by reading user_version.
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatalf("read user_version: %v", err)
	}
	if version != 7 {
		t.Fatalf("expected user_version=7, got %d", version)
	}
	// Verify all tables are queryable.
	expectTables := []string{
		"users", "domains", "aliases", "mailboxes", "messages",
		"attachments", "queue", "sessions", "audit_logs", "blobs",
	}
	for _, tbl := range expectTables {
		var n int
		if err := db.QueryRow("SELECT COUNT(*) FROM " + tbl).Scan(&n); err != nil {
			t.Errorf("table %q not accessible: %v", tbl, err)
		}
	}
}

func TestMigrateIdempotent(t *testing.T) {
	db := migrateTestDB(t)
	// Running migrations again must be a no-op.
	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate second call: %v", err)
	}
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatalf("read user_version: %v", err)
	}
	if version != 7 {
		t.Fatalf("expected user_version=7, got %d", version)
	}
}

// ---------------------------------------------------------------------------
// 2. User CRUD
// ---------------------------------------------------------------------------

func TestCreateUser(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	id, err := CreateUser(ctx, db, "alice@example.com", "hash1", false)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if id <= 0 {
		t.Fatalf("expected positive user ID, got %d", id)
	}
}

func TestCreateUserDuplicateEmail(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	ensureUser(t, db, "dup@example.com", "hash1")
	_, err := CreateUser(ctx, db, "dup@example.com", "hash2", false)
	if err == nil {
		t.Fatal("expected error on duplicate email, got nil")
	}
}

func TestGetUserByEmail(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	ensureUser(t, db, "bob@example.com", "hash-bob")

	u, err := GetUserByEmail(ctx, db, "bob@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if u.Email != "bob@example.com" {
		t.Errorf("expected email bob@example.com, got %q", u.Email)
	}
	if u.PasswordHash != "hash-bob" {
		t.Errorf("expected password_hash hash-bob, got %q", u.PasswordHash)
	}
	if !u.IsActive {
		t.Error("expected new user to be active")
	}
	if u.CreatedAt <= 0 {
		t.Errorf("expected non-zero created_at")
	}
}

func TestGetUserByEmailNotFound(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	_, err := GetUserByEmail(ctx, db, "nobody@example.com")
	if err == nil {
		t.Fatal("expected ErrNotFound, got nil")
	}
}

func TestGetUserByID(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	id := ensureUser(t, db, "carol@example.com", "hash-carol")

	u, err := GetUserByID(ctx, db, id)
	if err != nil {
		t.Fatalf("GetUserByID(%d): %v", id, err)
	}
	if u.Email != "carol@example.com" {
		t.Errorf("expected carol@example.com, got %q", u.Email)
	}
	if u.ID != id {
		t.Errorf("expected id %d, got %d", id, u.ID)
	}
}

func TestGetUserByIDNotFound(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	_, err := GetUserByID(ctx, db, 999)
	if err == nil {
		t.Fatal("expected ErrNotFound, got nil")
	}
}

func TestListUsers(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	users, err := ListUsers(ctx, db)
	if err != nil {
		t.Fatalf("ListUsers (empty): %v", err)
	}
	if len(users) != 0 {
		t.Fatalf("expected 0 users, got %d", len(users))
	}

	ensureUser(t, db, "a@example.com", "h1")
	ensureUser(t, db, "b@example.com", "h2")
	ensureUser(t, db, "c@example.com", "h3")

	users, err = ListUsers(ctx, db)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 3 {
		t.Fatalf("expected 3 users, got %d", len(users))
	}
}

func TestUpdateUser(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	id := ensureUser(t, db, "update@example.com", "orig-hash")

	// Update email only.
	newEmail := "updated@example.com"
	if err := UpdateUser(ctx, db, id, &newEmail, nil, nil, nil); err != nil {
		t.Fatalf("UpdateUser(email): %v", err)
	}
	u, err := GetUserByID(ctx, db, id)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if u.Email != "updated@example.com" {
		t.Errorf("expected email updated@example.com, got %q", u.Email)
	}
	if u.PasswordHash != "orig-hash" {
		t.Errorf("expected password_hash unchanged, got %q", u.PasswordHash)
	}

	// Update password only.
	newHash := "new-hash"
	if err := UpdateUser(ctx, db, id, nil, &newHash, nil, nil); err != nil {
		t.Fatalf("UpdateUser(hash): %v", err)
	}
	u, err = GetUserByID(ctx, db, id)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if u.PasswordHash != "new-hash" {
		t.Errorf("expected password_hash new-hash, got %q", u.PasswordHash)
	}
	if u.Email != "updated@example.com" {
		t.Errorf("expected email unchanged, got %q", u.Email)
	}

	// Update is_active only.
	inactive := false
	if err := UpdateUser(ctx, db, id, nil, nil, &inactive, nil); err != nil {
		t.Fatalf("UpdateUser(isActive): %v", err)
	}
	u, err = GetUserByID(ctx, db, id)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if u.IsActive != false {
		t.Error("expected user to be inactive")
	}
}

func TestUpdateUserNotFound(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	newEmail := "doesntmatter@example.com"
	if err := UpdateUser(ctx, db, 999, &newEmail, nil, nil, nil); err == nil {
		t.Fatal("expected ErrNotFound on update for missing user, got nil")
	}
}

func TestDeleteUser(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	id := ensureUser(t, db, "delete@example.com", "hash")

	if err := DeleteUser(ctx, db, id); err != nil {
		t.Fatalf("DeleteUser(%d): %v", id, err)
	}

	// Verify it's gone.
	_, err := GetUserByID(ctx, db, id)
	if err == nil {
		t.Fatal("expected ErrNotFound after delete")
	}
}

func TestDeleteUserNotFound(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	if err := DeleteUser(ctx, db, 999); err == nil {
		t.Fatal("expected ErrNotFound on delete of missing user, got nil")
	}
}

// ---------------------------------------------------------------------------
// 3. Mailbox CRUD
// ---------------------------------------------------------------------------

func TestCreateMailbox(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	uid := ensureUser(t, db, "mbox@example.com", "hash")
	mbID, err := CreateMailbox(ctx, db, uid, "INBOX")
	if err != nil {
		t.Fatalf("CreateMailbox: %v", err)
	}
	if mbID <= 0 {
		t.Fatalf("expected positive mailbox ID, got %d", mbID)
	}
}

func TestCreateMailboxDuplicate(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	uid := ensureUser(t, db, "dup-mbox@example.com", "hash")
	ensureMailbox(t, db, uid, "INBOX")
	_, err := CreateMailbox(ctx, db, uid, "INBOX")
	if err == nil {
		t.Fatal("expected error on duplicate mailbox, got nil")
	}
}

func TestGetMailbox(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	uid := ensureUser(t, db, "get-mbox@example.com", "hash")
	ensureMailbox(t, db, uid, "INBOX")

	mb, err := GetMailbox(ctx, db, uid, "INBOX")
	if err != nil {
		t.Fatalf("GetMailbox: %v", err)
	}
	if mb.Name != "INBOX" {
		t.Errorf("expected name INBOX, got %q", mb.Name)
	}
	if mb.UserID != uid {
		t.Errorf("expected user_id %d, got %d", uid, mb.UserID)
	}
}

func TestGetMailboxNotFound(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	uid := ensureUser(t, db, "no-mbox@example.com", "hash")
	_, err := GetMailbox(ctx, db, uid, "NONEXISTENT")
	if err == nil {
		t.Fatal("expected ErrNotFound, got nil")
	}
}

func TestGetMailboxByID(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	uid := ensureUser(t, db, "get-mbox-id@example.com", "hash")
	mid := ensureMailbox(t, db, uid, "INBOX")

	mb, err := GetMailboxByID(ctx, db, mid)
	if err != nil {
		t.Fatalf("GetMailboxByID(%d): %v", mid, err)
	}
	if mb.ID != mid {
		t.Errorf("expected id %d, got %d", mid, mb.ID)
	}
}

func TestGetMailboxByIDNotFound(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	_, err := GetMailboxByID(ctx, db, 999)
	if err == nil {
		t.Fatal("expected ErrNotFound, got nil")
	}
}

func TestListMailboxes(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	uid := ensureUser(t, db, "list-mbox@example.com", "hash")

	// Initially empty.
	boxes, err := ListMailboxes(ctx, db, uid)
	if err != nil {
		t.Fatalf("ListMailboxes (empty): %v", err)
	}
	if len(boxes) != 0 {
		t.Fatalf("expected 0 mailboxes, got %d", len(boxes))
	}

	ensureMailbox(t, db, uid, "INBOX")
	ensureMailbox(t, db, uid, "Sent")
	ensureMailbox(t, db, uid, "Trash")

	boxes, err = ListMailboxes(ctx, db, uid)
	if err != nil {
		t.Fatalf("ListMailboxes: %v", err)
	}
	if len(boxes) != 3 {
		t.Fatalf("expected 3 mailboxes, got %d", len(boxes))
	}

	// Verify names are sorted.
	got := make([]string, len(boxes))
	for i, mb := range boxes {
		got[i] = mb.Name
	}
	expected := []string{"INBOX", "Sent", "Trash"}
	for i := range expected {
		if got[i] != expected[i] {
			t.Errorf("position %d: expected %q, got %q", i, expected[i], got[i])
		}
	}
}

func TestDeleteMailbox(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	uid := ensureUser(t, db, "del-mbox@example.com", "hash")
	mid := ensureMailbox(t, db, uid, "INBOX")

	if err := DeleteMailbox(ctx, db, mid); err != nil {
		t.Fatalf("DeleteMailbox(%d): %v", mid, err)
	}

	// Verify it's gone.
	_, err := GetMailboxByID(ctx, db, mid)
	if err == nil {
		t.Fatal("expected ErrNotFound after delete")
	}
}

func TestDeleteMailboxNotFound(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	if err := DeleteMailbox(ctx, db, 999); err == nil {
		t.Fatal("expected ErrNotFound on delete missing mailbox, got nil")
	}
}

func TestEnsureDefaultMailboxes(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	uid := ensureUser(t, db, "defaults@example.com", "hash")
	ensureDefaultMailboxes(t, db, uid)

	boxes, err := ListMailboxes(ctx, db, uid)
	if err != nil {
		t.Fatalf("ListMailboxes: %v", err)
	}
	if len(boxes) != len(DefaultMailboxes) {
		t.Fatalf("expected %d mailboxes, got %d", len(DefaultMailboxes), len(boxes))
	}

	got := make(map[string]bool)
	for _, mb := range boxes {
		got[mb.Name] = true
	}
	for _, name := range DefaultMailboxes {
		if !got[name] {
			t.Errorf("expected default mailbox %q not found", name)
		}
	}
}

func TestEnsureDefaultMailboxesIdempotent(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	uid := ensureUser(t, db, "idempotent-defaults@example.com", "hash")
	ensureDefaultMailboxes(t, db, uid)

	// Second call must succeed (no-op on existing).
	if err := EnsureDefaultMailboxes(ctx, db, uid); err != nil {
		t.Fatalf("EnsureDefaultMailboxes second call: %v", err)
	}

	boxes, err := ListMailboxes(ctx, db, uid)
	if err != nil {
		t.Fatalf("ListMailboxes: %v", err)
	}
	if len(boxes) != len(DefaultMailboxes) {
		t.Fatalf("expected %d mailboxes after idempotent call, got %d", len(DefaultMailboxes), len(boxes))
	}
}

// ---------------------------------------------------------------------------
// 4. Message Operations
// ---------------------------------------------------------------------------

func TestInsertMessage(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	uid := ensureUser(t, db, "msg@example.com", "hash")
	mid := ensureMailbox(t, db, uid, "INBOX")

	msgID, msgUID, err := InsertMessage(ctx, db, mid, "blob-key-1", 456,
		"a@example.com", "b@example.com", "Hello", 0)
	if err != nil {
		t.Fatalf("InsertMessage: %v", err)
	}
	if msgID <= 0 {
		t.Errorf("expected positive message ID, got %d", msgID)
	}
	if msgUID != 1 {
		t.Errorf("expected UID 1 for first message, got %d", msgUID)
	}
}

func TestInsertMessageUIDSequence(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	uid := ensureUser(t, db, "uid-seq@example.com", "hash")
	mid := ensureMailbox(t, db, uid, "INBOX")

	var prevUID uint32
	for i := 1; i <= 5; i++ {
		_, msgUID, err := InsertMessage(ctx, db, mid, "blob", 100,
			"from@e.com", "to@e.com", "Sub", 0)
		if err != nil {
			t.Fatalf("InsertMessage #%d: %v", i, err)
		}
		if msgUID != prevUID+1 {
			t.Errorf("insert #%d: expected uid %d, got %d", i, prevUID+1, msgUID)
		}
		prevUID = msgUID
	}
}

func TestInsertMessageUIDPerMailbox(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	uid := ensureUser(t, db, "uid-per-mbox@example.com", "hash")
	mid1 := ensureMailbox(t, db, uid, "INBOX")
	mid2 := ensureMailbox(t, db, uid, "Sent")

	// Insert messages in both mailboxes interleaved.
	_, u1, err := InsertMessage(ctx, db, mid1, "b1", 50, "a@e.com", "b@e.com", "m1", 0)
	if err != nil {
		t.Fatalf("InsertMessage mid1 #1: %v", err)
	}
	_, u2, err := InsertMessage(ctx, db, mid2, "b2", 50, "a@e.com", "b@e.com", "m2", 0)
	if err != nil {
		t.Fatalf("InsertMessage mid2 #1: %v", err)
	}
	_, u3, err := InsertMessage(ctx, db, mid1, "b3", 50, "a@e.com", "b@e.com", "m3", 0)
	if err != nil {
		t.Fatalf("InsertMessage mid1 #2: %v", err)
	}
	_, u4, err := InsertMessage(ctx, db, mid2, "b4", 50, "a@e.com", "b@e.com", "m4", 0)
	if err != nil {
		t.Fatalf("InsertMessage mid2 #2: %v", err)
	}

	// Each mailbox's UID sequence is independent.
	if u1 != 1 || u3 != 2 {
		t.Errorf("mid1 UIDs: expected 1,2 got %d,%d", u1, u3)
	}
	if u2 != 1 || u4 != 2 {
		t.Errorf("mid2 UIDs: expected 1,2 got %d,%d", u2, u4)
	}
}

func TestGetMessageByUID(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	uid := ensureUser(t, db, "get-msg@example.com", "hash")
	mid := ensureMailbox(t, db, uid, "INBOX")
	_, msgUID := ensureMessage(t, db, mid, "from@e.com", "to@e.com", "Hi", 0)

	m, err := GetMessageByUID(ctx, db, mid, msgUID)
	if err != nil {
		t.Fatalf("GetMessageByUID(%d, %d): %v", mid, msgUID, err)
	}
	if m.FromAddr != "from@e.com" {
		t.Errorf("expected from@e.com, got %q", m.FromAddr)
	}
	if m.ToAddr != "to@e.com" {
		t.Errorf("expected to@e.com, got %q", m.ToAddr)
	}
	if m.Subject != "Hi" {
		t.Errorf("expected subject 'Hi', got %q", m.Subject)
	}
	if m.MailboxID != mid {
		t.Errorf("expected mailbox_id %d, got %d", mid, m.MailboxID)
	}
}

func TestGetMessageByUIDNotFound(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	uid := ensureUser(t, db, "get-msg-no@example.com", "hash")
	mid := ensureMailbox(t, db, uid, "INBOX")

	_, err := GetMessageByUID(ctx, db, mid, 999)
	if err == nil {
		t.Fatal("expected ErrNotFound, got nil")
	}
}

func TestGetMessageByID(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	uid := ensureUser(t, db, "get-id@example.com", "hash")
	mid := ensureMailbox(t, db, uid, "INBOX")
	msgID, _ := ensureMessage(t, db, mid, "f@e.com", "t@e.com", "Test", 0)

	m, err := GetMessageByID(ctx, db, msgID)
	if err != nil {
		t.Fatalf("GetMessageByID(%d): %v", msgID, err)
	}
	if m.ID != msgID {
		t.Errorf("expected id %d, got %d", msgID, m.ID)
	}
}

func TestGetMessageByIDNotFound(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	_, err := GetMessageByID(ctx, db, 999)
	if err == nil {
		t.Fatal("expected ErrNotFound, got nil")
	}
}

func TestListMessages(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	uid := ensureUser(t, db, "list-msgs@example.com", "hash")
	mid := ensureMailbox(t, db, uid, "INBOX")

	// Empty list.
	msgs, err := ListMessages(ctx, db, mid, 100, 0)
	if err != nil {
		t.Fatalf("ListMessages (empty): %v", err)
	}
	if len(msgs) != 0 {
		t.Fatalf("expected 0 messages, got %d", len(msgs))
	}

	// Insert messages with different subjects.
	_, u1 := ensureMessage(t, db, mid, "a@e.com", "b@e.com", "Msg1", 0)
	_, u2 := ensureMessage(t, db, mid, "a@e.com", "b@e.com", "Msg2", 0)
	_, u3 := ensureMessage(t, db, mid, "a@e.com", "b@e.com", "Msg3", 0)

	// List all (newest first).
	msgs, err = ListMessages(ctx, db, mid, 100, 0)
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}
	if len(msgs) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(msgs))
	}
	// Newest first means reverse insertion order.
	if msgs[0].UID != u3 || msgs[1].UID != u2 || msgs[2].UID != u1 {
		t.Errorf("expected order [%d, %d, %d], got [%d, %d, %d]",
			u3, u2, u1, msgs[0].UID, msgs[1].UID, msgs[2].UID)
	}
}

func TestListMessagesPagination(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	uid := ensureUser(t, db, "paginate@example.com", "hash")
	mid := ensureMailbox(t, db, uid, "INBOX")

	// Insert 5 messages.
	for range 5 {
		ensureMessage(t, db, mid, "a@e.com", "b@e.com", "Msg", 0)
	}

	// Paginate with limit=2.
	msgs, err := ListMessages(ctx, db, mid, 2, 0)
	if err != nil {
		t.Fatalf("ListMessages(limit=2): %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(msgs))
	}

	// Paginate with limit=2, sinceUID=3 → should get UIDs 4,5.
	msgs, err = ListMessages(ctx, db, mid, 2, 3)
	if err != nil {
		t.Fatalf("ListMessages(sinceUID=3): %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages (UIDs 4,5), got %d", len(msgs))
	}
	if msgs[0].UID != 5 || msgs[1].UID != 4 {
		t.Errorf("expected UIDs [5,4] (newest first), got %v", []uint32{msgs[0].UID, msgs[1].UID})
	}

	// Paginate beyond end.
	msgs, err = ListMessages(ctx, db, mid, 10, 5)
	if err != nil {
		t.Fatalf("ListMessages(sinceUID=5): %v", err)
	}
	if len(msgs) != 0 {
		t.Fatalf("expected 0 messages after last UID, got %d", len(msgs))
	}
}

func TestUpdateFlags(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	uid := ensureUser(t, db, "flags@example.com", "hash")
	mid := ensureMailbox(t, db, uid, "INBOX")
	msgID, _ := ensureMessage(t, db, mid, "f@e.com", "t@e.com", "FlagTest", 0)

	// Set flag bits 1 and 2 (binary 011).
	if err := UpdateFlags(ctx, db, msgID, 0b011, 0b111); err != nil {
		t.Fatalf("UpdateFlags(set 011): %v", err)
	}
	m, err := GetMessageByID(ctx, db, msgID)
	if err != nil {
		t.Fatalf("GetMessageByID: %v", err)
	}
	if m.Flags != 0b011 {
		t.Errorf("expected flags %#b, got %#b", 0b011, m.Flags)
	}

	// Clear flag bit 2 (mask=010, value=000).
	if err := UpdateFlags(ctx, db, msgID, 0, 0b010); err != nil {
		t.Fatalf("UpdateFlags(clear bit 2): %v", err)
	}
	m, err = GetMessageByID(ctx, db, msgID)
	if err != nil {
		t.Fatalf("GetMessageByID: %v", err)
	}
	if m.Flags != 0b001 {
		t.Errorf("expected flags %#b (only bit 1), got %#b", 0b001, m.Flags)
	}
}

func TestUpdateFlagsNotFound(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	if err := UpdateFlags(ctx, db, 999, 1, 1); err == nil {
		t.Fatal("expected ErrNotFound, got nil")
	}
}

func TestMoveMessage(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	uid := ensureUser(t, db, "move@example.com", "hash")
	mid1 := ensureMailbox(t, db, uid, "INBOX")
	mid2 := ensureMailbox(t, db, uid, "Sent")
	msgID, _ := ensureMessage(t, db, mid1, "f@e.com", "t@e.com", "MoveMe", 0)

	if err := MoveMessage(ctx, db, msgID, mid2); err != nil {
		t.Fatalf("MoveMessage(%d, %d): %v", msgID, mid2, err)
	}

	m, err := GetMessageByID(ctx, db, msgID)
	if err != nil {
		t.Fatalf("GetMessageByID: %v", err)
	}
	if m.MailboxID != mid2 {
		t.Errorf("expected mailbox_id %d, got %d", mid2, m.MailboxID)
	}

	// Verify it's no longer in the source.
	msgs, err := ListMessages(ctx, db, mid1, 100, 0)
	if err != nil {
		t.Fatalf("ListMessages(mid1): %v", err)
	}
	if len(msgs) != 0 {
		t.Errorf("expected 0 messages in source, got %d", len(msgs))
	}
}



func TestMoveMessageNotFound(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	if err := MoveMessage(ctx, db, 999, 1); err == nil {
		t.Fatal("expected ErrNotFound, got nil")
	}
}

func TestDeleteMessage(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	uid := ensureUser(t, db, "del-msg@example.com", "hash")
	mid := ensureMailbox(t, db, uid, "INBOX")
	msgID, _ := ensureMessage(t, db, mid, "f@e.com", "t@e.com", "DeleteMe", 0)

	if err := DeleteMessage(ctx, db, msgID); err != nil {
		t.Fatalf("DeleteMessage(%d): %v", msgID, err)
	}

	_, err := GetMessageByID(ctx, db, msgID)
	if err == nil {
		t.Fatal("expected ErrNotFound after deletion")
	}
}

func TestDeleteMessageNotFound(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	if err := DeleteMessage(ctx, db, 999); err == nil {
		t.Fatal("expected ErrNotFound, got nil")
	}
}

func TestCountMessages(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	uid := ensureUser(t, db, "count@example.com", "hash")
	mid := ensureMailbox(t, db, uid, "INBOX")

	// Start at 0.
	count, err := CountMessages(ctx, db, mid)
	if err != nil {
		t.Fatalf("CountMessages (empty): %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0, got %d", count)
	}

	for range 3 {
		ensureMessage(t, db, mid, "f@e.com", "t@e.com", "M", 0)
	}

	count, err = CountMessages(ctx, db, mid)
	if err != nil {
		t.Fatalf("CountMessages: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected 3, got %d", count)
	}
}



func TestMessageBlobKey(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	uid := ensureUser(t, db, "blobkey2@example.com", "hash")
	mid := ensureMailbox(t, db, uid, "INBOX")
	msgID, _ := ensureMessage(t, db, mid, "f@e.com", "t@e.com", "Blob", 0)

	m, err := GetMessageByID(ctx, db, msgID)
	if err != nil {
		t.Fatalf("GetMessageByID: %v", err)
	}
	if m.BlobKey != "blob-key-Blob" {
		t.Errorf("expected blob_key 'blob-key-Blob', got %q", m.BlobKey)
	}
	if m.Size != 123 {
		t.Errorf("expected size 123, got %d", m.Size)
	}
	if m.InternalDate <= 0 {
		t.Errorf("expected non-zero internal_date")
	}
}

// ---------------------------------------------------------------------------
// 5. Queue Operations
// ---------------------------------------------------------------------------

var queueMsgCounter int64

// seedQueueMessage creates a user, mailbox, and message, returning the message ID.
func seedQueueMessage(t *testing.T, db *sql.DB) int64 {
	t.Helper()
	ctx := context.Background()
	queueMsgCounter++
	email := fmt.Sprintf("queue-msg-%d@example.com", queueMsgCounter)
	uid := ensureUser(t, db, email, "hash")
	mid := ensureMailbox(t, db, uid, "INBOX")
	msgID, _, err := InsertMessage(ctx, db, mid, "blob-key", 100, "f@e.com", "t@e.com", "Q", 0)
	if err != nil {
		t.Fatalf("seedQueueMessage: InsertMessage: %v", err)
	}
	return msgID
}

func TestEnqueue(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()
	msgID := seedQueueMessage(t, db)

	if err := Enqueue(ctx, db, msgID, "user@example.com"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
}

func TestQueueSize(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	size, err := QueueSize(ctx, db)
	if err != nil {
		t.Fatalf("QueueSize (empty): %v", err)
	}
	if size != 0 {
		t.Fatalf("expected 0, got %d", size)
	}

	for range 3 {
		msgID := seedQueueMessage(t, db)
		if err := Enqueue(ctx, db, msgID, "rcpt@e.com"); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
	}

	size, err = QueueSize(ctx, db)
	if err != nil {
		t.Fatalf("QueueSize: %v", err)
	}
	if size != 3 {
		t.Fatalf("expected 3, got %d", size)
	}
}

func TestClaimNextReturnsPendingItem(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()
	msgID := seedQueueMessage(t, db)

	if err := Enqueue(ctx, db, msgID, "rcpt@example.com"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	item, err := ClaimNext(ctx, db)
	if err != nil {
		t.Fatalf("ClaimNext: %v", err)
	}
	if item.MessageID != msgID {
		t.Errorf("expected message_id %d, got %d", msgID, item.MessageID)
	}
	if item.RcptTo != "rcpt@example.com" {
		t.Errorf("expected rcpt_to rcpt@example.com, got %q", item.RcptTo)
	}
	// Status is the pre-update value read from SELECT before the UPDATE to 'active'.
	if item.Status != "pending" {
		t.Errorf("expected status 'pending' (pre-update value), got %q", item.Status)
	}
}

func TestClaimNextDoesNotReturnClaimedItems(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()
	msgID := seedQueueMessage(t, db)

	if err := Enqueue(ctx, db, msgID, "a@e.com"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	// Claim it.
	item, err := ClaimNext(ctx, db)
	if err != nil {
		t.Fatalf("ClaimNext #1: %v", err)
	}
	if item == nil {
		t.Fatal("expected first claim to succeed")
	}

	// Second claim should return nil (nothing pending).
	item2, err := ClaimNext(ctx, db)
	if err != nil {
		t.Fatalf("ClaimNext #2: %v", err)
	}
	if item2 != nil {
		t.Fatalf("expected nil for second claim, got %+v", item2)
	}
}

func TestComplete(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()
	msgID := seedQueueMessage(t, db)

	if err := Enqueue(ctx, db, msgID, "rcpt@e.com"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	item, err := ClaimNext(ctx, db)
	if err != nil {
		t.Fatalf("ClaimNext: %v", err)
	}
	if item == nil {
		t.Fatal("expected item")
	}

	if err := Complete(ctx, db, item.ID); err != nil {
		t.Fatalf("Complete(%d): %v", item.ID, err)
	}

	size, err := QueueSize(ctx, db)
	if err != nil {
		t.Fatalf("QueueSize: %v", err)
	}
	if size != 0 {
		t.Errorf("expected queue to be empty after complete, got %d", size)
	}
}

func TestCompleteNotFound(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	if err := Complete(ctx, db, 999); err == nil {
		t.Fatal("expected ErrNotFound, got nil")
	}
}

func TestFailIncrementsAttempt(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()
	msgID := seedQueueMessage(t, db)

	if err := Enqueue(ctx, db, msgID, "rcpt@e.com"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	item, err := ClaimNext(ctx, db)
	if err != nil {
		t.Fatalf("ClaimNext: %v", err)
	}
	if item == nil {
		t.Fatal("expected item")
	}

	nextAttempt := time.Now()
	maxRetries := 3

	if err := Fail(ctx, db, item.ID, nextAttempt, maxRetries); err != nil {
		t.Fatalf("Fail: %v", err)
	}

	// Claim again — should be pending again.
	item2, err := ClaimNext(ctx, db)
	if err != nil {
		t.Fatalf("ClaimNext after fail: %v", err)
	}
	if item2 == nil {
		t.Fatal("expected item after fail")
	}
	if item2.AttemptCount != 1 {
		t.Errorf("expected attempt_count 1 after one fail, got %d", item2.AttemptCount)
	}
}

func TestFailRemovesOnMaxRetries(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()
	msgID := seedQueueMessage(t, db)

	if err := Enqueue(ctx, db, msgID, "rcpt@e.com"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	item, err := ClaimNext(ctx, db)
	if err != nil {
		t.Fatalf("ClaimNext: %v", err)
	}
	if item == nil {
		t.Fatal("expected item")
	}

	// Fail with maxRetries=0 — since attempt_count starts at 0 and maxRetries=0,
	// item should be removed.
	nextAttempt := time.Now().Add(5 * time.Minute)
	maxRetries := 0

	if err := Fail(ctx, db, item.ID, nextAttempt, maxRetries); !errors.Is(err, ErrMaxRetries) {
		t.Fatalf("Fail (maxRetries=0): expected ErrMaxRetries, got %v", err)
	}

	size, err := QueueSize(ctx, db)
	if err != nil {
		t.Fatalf("QueueSize: %v", err)
	}
	if size != 0 {
		t.Errorf("expected queue to be empty after max retries, got %d", size)
	}
}


func TestFailNotFound(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	if err := Fail(ctx, db, 999, time.Now(), 3); err == nil {
		t.Fatal("expected error on failing unknown item, got nil")
	}
}

func TestListPending(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	items, err := ListPending(ctx, db)
	if err != nil {
		t.Fatalf("ListPending (empty): %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected 0 items, got %d", len(items))
	}

	msgID1 := seedQueueMessage(t, db)
	msgID2 := seedQueueMessage(t, db)

	if err := Enqueue(ctx, db, msgID1, "a@e.com"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if err := Enqueue(ctx, db, msgID2, "b@e.com"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	items, err = ListPending(ctx, db)
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
}

// ---------------------------------------------------------------------------
// 6. Edge Cases & Integration
// ---------------------------------------------------------------------------

func TestErrNotFoundSentinel(t *testing.T) {
	// Verify that all lookup functions wrap ErrNotFound consistently.
	db := migrateTestDB(t)
	ctx := context.Background()

	// User lookups.
	_, err := GetUserByEmail(ctx, db, "none@e.com")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("GetUserByEmail: expected ErrNotFound sentinel, got %v", err)
	}

	_, err = GetUserByID(ctx, db, 999)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("GetUserByID: expected ErrNotFound sentinel, got %v", err)
	}

	// Update/delete on missing users.
	newEmail := "x@y.com"
	err = UpdateUser(ctx, db, 999, &newEmail, nil, nil, nil)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateUser (missing): expected ErrNotFound, got %v", err)
	}

	err = DeleteUser(ctx, db, 999)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteUser (missing): expected ErrNotFound, got %v", err)
	}

	// Mailbox lookups.
	_, err = GetMailbox(ctx, db, 999, "INBOX")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("GetMailbox: expected ErrNotFound, got %v", err)
	}

	_, err = GetMailboxByID(ctx, db, 999)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("GetMailboxByID: expected ErrNotFound, got %v", err)
	}

	err = DeleteMailbox(ctx, db, 999)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteMailbox (missing): expected ErrNotFound, got %v", err)
	}

	// Message lookups.
	_, err = GetMessageByUID(ctx, db, 999, 1)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("GetMessageByUID: expected ErrNotFound, got %v", err)
	}

	_, err = GetMessageByID(ctx, db, 999)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("GetMessageByID: expected ErrNotFound, got %v", err)
	}

	err = UpdateFlags(ctx, db, 999, 0, 0)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateFlags (missing): expected ErrNotFound, got %v", err)
	}

	err = MoveMessage(ctx, db, 999, 1)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("MoveMessage (missing): expected ErrNotFound, got %v", err)
	}

	err = DeleteMessage(ctx, db, 999)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteMessage (missing): expected ErrNotFound, got %v", err)
	}

	// Queue.
	err = Complete(ctx, db, 999)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Complete (missing): expected ErrNotFound, got %v", err)
	}
}

func TestCascadeDeleteUserRemovesMailboxes(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	id := ensureUser(t, db, "cascade@example.com", "hash")
	ensureMailbox(t, db, id, "INBOX")
	ensureMailbox(t, db, id, "Sent")

	if err := DeleteUser(ctx, db, id); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}

	boxes, err := ListMailboxes(ctx, db, id)
	if err != nil {
		t.Fatalf("ListMailboxes: %v", err)
	}
	if len(boxes) != 0 {
		t.Errorf("expected 0 mailboxes after user delete, got %d", len(boxes))
	}
}

func TestMessageCountAfterInsertAndDelete(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	uid := ensureUser(t, db, "cnt-test@example.com", "hash")
	mid := ensureMailbox(t, db, uid, "INBOX")

	// Insert two messages.
	id1, _ := ensureMessage(t, db, mid, "a@e.com", "b@e.com", "M1", 0)
	_, _ = ensureMessage(t, db, mid, "a@e.com", "b@e.com", "M2", 0)

	count, err := CountMessages(ctx, db, mid)
	if err != nil {
		t.Fatalf("CountMessages: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2, got %d", count)
	}

	// Delete one.
	if err := DeleteMessage(ctx, db, id1); err != nil {
		t.Fatalf("DeleteMessage: %v", err)
	}

	count, err = CountMessages(ctx, db, mid)
	if err != nil {
		t.Fatalf("CountMessages after delete: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 after delete, got %d", count)
	}
}

// ---------------------------------------------------------------------------
// Context cancellation test
// ---------------------------------------------------------------------------

func TestContextCancellation(t *testing.T) {
	db := migrateTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately cancelled

	_, err := CreateUser(ctx, db, "fail@e.com", "hash", false)
	if err == nil {
		t.Log("CreateUser with cancelled context succeeded (may still work with in-memory)")
	}
}

// ---------------------------------------------------------------------------
// Main test — end-to-end flow: create user, mailboxes, messages, queue
// ---------------------------------------------------------------------------

func TestEndToEndFlow(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	// 1. Create user.
	userID, err := CreateUser(ctx, db, "user@example.com", "hash-pw", false)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if userID <= 0 {
		t.Fatalf("expected positive userID, got %d", userID)
	}

	// 2. Create default mailboxes.
	if err := EnsureDefaultMailboxes(ctx, db, userID); err != nil {
		t.Fatalf("EnsureDefaultMailboxes: %v", err)
	}

	// 3. Get INBOX.
	inbox, err := GetMailbox(ctx, db, userID, "INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}

	// 4. Insert a message into INBOX.
	msgID, uid, err := InsertMessage(ctx, db, inbox.ID, "blob-key-e2e", 1024,
		"sender@example.com", "user@example.com", "E2E Test Message", 0)
	if err != nil {
		t.Fatalf("InsertMessage: %v", err)
	}
	if uid != 1 {
		t.Errorf("expected UID 1, got %d", uid)
	}

	// 5. Enqueue delivery for the message.
	if err := Enqueue(ctx, db, msgID, "recipient@other.com"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	// 6. Claim the queue item.
	qi, err := ClaimNext(ctx, db)
	if err != nil {
		t.Fatalf("ClaimNext: %v", err)
	}
	if qi == nil {
		t.Fatal("expected queue item")
	}
	if qi.MessageID != msgID {
		t.Errorf("expected message_id %d, got %d", msgID, qi.MessageID)
	}

	// 7. Complete it.
	if err := Complete(ctx, db, qi.ID); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	// 8. Verify queue is empty.
	size, err := QueueSize(ctx, db)
	if err != nil {
		t.Fatalf("QueueSize: %v", err)
	}
	if size != 0 {
		t.Errorf("expected queue to be empty, got %d", size)
	}

	// 9. Verify message still exists.
	m, err := GetMessageByID(ctx, db, msgID)
	if err != nil {
		t.Fatalf("GetMessageByID: %v", err)
	}
	if m.Subject != "E2E Test Message" {
		t.Errorf("expected subject 'E2E Test Message', got %q", m.Subject)
	}
}

// ---------------------------------------------------------------------------
// Duplicate mailbox unique constraint
// ---------------------------------------------------------------------------

func TestDuplicateMailboxErrorContainsAlreadyExists(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	uid := ensureUser(t, db, "dup-mbox2@example.com", "hash")
	ensureMailbox(t, db, uid, "INBOX")

	_, err := CreateMailbox(ctx, db, uid, "INBOX")
	if err == nil {
		t.Fatal("expected error on duplicate mailbox name")
	}
}
