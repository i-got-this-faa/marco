package imap

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/backend"
	"github.com/i-got-this-faa/marco/pkg/auth"
	"github.com/i-got-this-faa/marco/pkg/blobstore"
	"github.com/i-got-this-faa/marco/pkg/config"
	"github.com/i-got-this-faa/marco/pkg/storage"
	_ "modernc.org/sqlite"
)

// ---------------------------------------------------------------------------
// testLiteral implements imap.Literal for test convenience.
// ---------------------------------------------------------------------------

type testLiteral struct {
	r *bytes.Reader
}

func (l *testLiteral) Read(p []byte) (int, error) { return l.r.Read(p) }
func (l *testLiteral) Len() int                   { return l.r.Len() }

func newTestLiteral(s string) *testLiteral {
	return &testLiteral{r: bytes.NewReader([]byte(s))}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open(':memory:'): %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return db
}

func setupTest(t *testing.T) (*Backend, *auth.Manager, *sql.DB) {
	t.Helper()
	db := openTestDB(t)
	blob := blobstore.NewSQLiteStore(db)
	am := auth.NewManager(db)
	be := NewBackend(db, blob, am)
	return be, am, db
}

func createTestUser(t *testing.T, am *auth.Manager, email, password string) int64 {
	t.Helper()
	ctx := context.Background()
	id, err := am.CreateUser(ctx, email, password, false)
	if err != nil {
		t.Fatalf("CreateUser(%q): %v", email, err)
	}
	return id
}

func loginHelper(t *testing.T, be *Backend, email, password string) backend.User {
	t.Helper()
	user, err := be.Login(nil, email, password)
	if err != nil {
		t.Fatalf("Login(%q): %v", email, err)
	}
	return user
}

func mustCreateMessage(t *testing.T, mb backend.Mailbox, body string, flags []string) {
	t.Helper()
	if err := mb.CreateMessage(flags, time.Now(), newTestLiteral(body)); err != nil {
		t.Fatalf("CreateMessage: %v", err)
	}
}

func testBody() string {
	return "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: test\r\n\r\nHello, world."
}

const testEmail = "test@example.com"
const testPassword = "test-password"

// ---------------------------------------------------------------------------
// 1. Server creation
// ---------------------------------------------------------------------------

func TestNewServer(t *testing.T) {
	db := openTestDB(t)
	blob := blobstore.NewSQLiteStore(db)
	am := auth.NewManager(db)
	be := NewBackend(db, blob, am)

	cfg := &config.IMAPConfig{
		ListenAddr: "0.0.0.0:1143",
		ImapsAddr:  "0.0.0.0:1993",
	}

	s := NewServer(cfg, be, nil)
	if s == nil {
		t.Fatal("NewServer returned nil")
	}
	if s.Addr != "0.0.0.0:1143" {
		t.Fatalf("expected Addr 0.0.0.0:1143, got %q", s.Addr)
	}
	if s.AllowInsecureAuth {
		t.Fatal("AllowInsecureAuth should be false by default")
	}
	if s.TLSConfig != nil {
		t.Fatal("TLSConfig should be nil when nil passed")
	}
}

// ---------------------------------------------------------------------------
// 2. Backend: Login & Logout
// ---------------------------------------------------------------------------

func TestBackendLoginSuccess(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)

	user, err := be.Login(nil, testEmail, testPassword)
	if err != nil {
		t.Fatalf("Login with valid credentials failed: %v", err)
	}
	if user == nil {
		t.Fatal("Login returned nil user")
	}
	if user.Username() != testEmail {
		t.Fatalf("expected username %q, got %q", testEmail, user.Username())
	}
}

func TestBackendLoginWrongPassword(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)

	_, err := be.Login(nil, testEmail, "wrong-password")
	if err == nil {
		t.Fatal("Login with wrong password should fail")
	}
}

func TestBackendLoginUnknownUser(t *testing.T) {
	be, _, _ := setupTest(t)

	_, err := be.Login(nil, "unknown@example.com", testPassword)
	if err == nil {
		t.Fatal("Login with unknown user should fail")
	}
}

func TestBackendLoginInactiveUser(t *testing.T) {
	be, am, db := setupTest(t)
	ctx := context.Background()
	id := createTestUser(t, am, testEmail, testPassword)

	inactive := false
	if err := storage.UpdateUser(ctx, db, id, nil, nil, &inactive, nil); err != nil {
		t.Fatalf("UpdateUser deactivate: %v", err)
	}

	_, err := be.Login(nil, testEmail, testPassword)
	if err == nil {
		t.Fatal("Login with inactive user should fail")
	}
}

func TestBackendLogout(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)

	user := loginHelper(t, be, testEmail, testPassword)
	if err := user.Logout(); err != nil {
		t.Fatalf("Logout should not error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 3. User operations
// ---------------------------------------------------------------------------

func TestUserUsername(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)

	user := loginHelper(t, be, testEmail, testPassword)
	if got := user.Username(); got != testEmail {
		t.Fatalf("Username() = %q, want %q", got, testEmail)
	}
}

func TestUserListMailboxes(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	mailboxes, err := user.ListMailboxes(false)
	if err != nil {
		t.Fatalf("ListMailboxes: %v", err)
	}

	expected := []string{"INBOX", "Sent", "Trash", "Spam", "Drafts"}
	if len(mailboxes) != len(expected) {
		t.Fatalf("expected %d mailboxes, got %d", len(expected), len(mailboxes))
	}
	for _, mb := range mailboxes {
		found := false
		for _, exp := range expected {
			if mb.Name() == exp {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("unexpected mailbox %q in default set", mb.Name())
		}
	}
}

func TestUserGetMailbox(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	mb, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}
	if mb.Name() != "INBOX" {
		t.Fatalf("expected mailbox name INBOX, got %q", mb.Name())
	}
}

func TestUserGetMailboxNotFound(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	_, err := user.GetMailbox("NonExistent")
	if err == nil {
		t.Fatal("GetMailbox for non-existent mailbox should error")
	}
}

func TestUserCreateMailbox(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	if err := user.CreateMailbox("Archive"); err != nil {
		t.Fatalf("CreateMailbox(Archive): %v", err)
	}

	mb, err := user.GetMailbox("Archive")
	if err != nil {
		t.Fatalf("GetMailbox(Archive) after create: %v", err)
	}
	if mb.Name() != "Archive" {
		t.Fatalf("expected Archive, got %q", mb.Name())
	}
}

func TestUserCreateMailboxDuplicate(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	if err := user.CreateMailbox("INBOX"); err == nil {
		t.Fatal("CreateMailbox for duplicate INBOX should fail")
	}
}

func TestUserDeleteMailbox(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	if err := user.DeleteMailbox("Trash"); err != nil {
		t.Fatalf("DeleteMailbox(Trash): %v", err)
	}

	_, err := user.GetMailbox("Trash")
	if err == nil {
		t.Fatal("GetMailbox(Trash) after delete should fail")
	}
}

func TestUserDeleteMailboxNotFound(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	if err := user.DeleteMailbox("NonExistent"); err == nil {
		t.Fatal("DeleteMailbox for non-existent mailbox should fail")
	}
}

func TestUserRenameMailbox(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	err := user.RenameMailbox("INBOX", "INBOX-renamed")
	if err == nil {
		t.Fatal("RenameMailbox should return error for MVP")
	}
}

// ---------------------------------------------------------------------------
// 4. Mailbox operations
// ---------------------------------------------------------------------------

func TestMailboxName(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	mb, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}
	if mb.Name() != "INBOX" {
		t.Fatalf("Name() = %q, want %q", mb.Name(), "INBOX")
	}
}

func TestMailboxInfo(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	mb, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}

	info, err := mb.Info()
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Name != "INBOX" {
		t.Fatalf("info.Name = %q, want %q", info.Name, "INBOX")
	}
	if info.Delimiter != "." {
		t.Fatalf("info.Delimiter = %q, want %q", info.Delimiter, ".")
	}
}

func TestMailboxStatus(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	mb, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}

	status, err := mb.Status([]imap.StatusItem{imap.StatusMessages, imap.StatusUidNext, imap.StatusUidValidity})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Messages != 0 {
		t.Fatalf("expected 0 messages, got %d", status.Messages)
	}
	if status.UidNext != 1 {
		t.Fatalf("expected UidNext=1 for empty, got %d", status.UidNext)
	}
	if status.UidValidity == 0 {
		t.Fatal("UidValidity should be non-zero (mailboxID)")
	}
}

func TestMailboxStatusAfterInsert(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	mb, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}

	mustCreateMessage(t, mb, testBody(), []string{imap.SeenFlag})

	status, err := mb.Status([]imap.StatusItem{imap.StatusMessages, imap.StatusUidNext})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Messages != 1 {
		t.Fatalf("expected 1 message, got %d", status.Messages)
	}
	if status.UidNext != 2 {
		t.Fatalf("expected UidNext=2, got %d", status.UidNext)
	}
}

func TestMailboxCreateMessage(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	mb, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}

	mustCreateMessage(t, mb, testBody(), []string{imap.SeenFlag})

	status, _ := mb.Status([]imap.StatusItem{imap.StatusMessages})
	if status.Messages != 1 {
		t.Fatalf("expected 1 message, got %d", status.Messages)
	}
}

func TestMailboxCreateMessageNoFlags(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	mb, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}

	mustCreateMessage(t, mb, testBody(), nil)

	status, _ := mb.Status([]imap.StatusItem{imap.StatusMessages})
	if status.Messages != 1 {
		t.Fatalf("expected 1 message, got %d", status.Messages)
	}
}

func TestMailboxCreateMessageEmptyBody(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	mb, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}

	mustCreateMessage(t, mb, "", nil)

	status, _ := mb.Status([]imap.StatusItem{imap.StatusMessages})
	if status.Messages != 1 {
		t.Fatalf("expected 1 message after inserting empty body, got %d", status.Messages)
	}
}

func TestMailboxListMessages(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	mb, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}

	mustCreateMessage(t, mb, testBody(), []string{imap.SeenFlag})

	ch := make(chan *imap.Message, 10)
	seqset := &imap.SeqSet{}
	seqset.AddNum(1)
	err = mb.ListMessages(false, seqset, []imap.FetchItem{imap.FetchFlags}, ch)
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}

	msg := <-ch
	if msg == nil {
		t.Fatal("ListMessages returned nil message")
	}
	if msg.SeqNum != 1 {
		t.Fatalf("expected SeqNum=1, got %d", msg.SeqNum)
	}
	if len(msg.Flags) != 1 || msg.Flags[0] != imap.SeenFlag {
		t.Fatalf("expected Seen flag, got %v", msg.Flags)
	}
}

func TestMailboxListMessagesMultiple(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	mb, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}

	mustCreateMessage(t, mb, testBody(), []string{imap.SeenFlag})
	mustCreateMessage(t, mb, testBody(), []string{imap.DraftFlag})

	ch := make(chan *imap.Message, 10)
	seqset := &imap.SeqSet{}
	seqset.AddRange(1, 2)
	err = mb.ListMessages(false, seqset, []imap.FetchItem{imap.FetchFlags}, ch)
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}

	var msgs []*imap.Message
	for msg := range ch {
		msgs = append(msgs, msg)
	}
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(msgs))
	}
}

func TestMailboxListMessagesFetchBody(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	mb, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}

	body := "From: sender@test.com\r\nSubject: fetch body\r\n\r\nHello fetch test."
	mustCreateMessage(t, mb, body, []string{imap.SeenFlag})

	ch := make(chan *imap.Message, 10)
	seqset := &imap.SeqSet{}
	seqset.AddNum(1)
	err = mb.ListMessages(false, seqset, []imap.FetchItem{imap.FetchRFC822}, ch)
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}

	msg := <-ch
	if msg == nil {
		t.Fatal("ListMessages returned nil message")
	}

	section := &imap.BodySectionName{}
	bodyReader := msg.GetBody(section)
	if bodyReader == nil {
		t.Fatal("expected body section in fetched message")
	}

	got, err := io.ReadAll(bodyReader)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if string(got) != body {
		t.Fatalf("body mismatch:\n  got:  %q\n  want: %q", string(got), body)
	}
}

func TestMailboxListMessagesFetchEnvelope(t *testing.T) {
	be, am, db := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	ctx := context.Background()
	blob := blobstore.NewSQLiteStore(db)
	body := "From: alice@test.com\r\nTo: bob@test.com\r\nSubject: Hello\r\n\r\nHi Bob."
	blobKey, _, err := blob.Put(ctx, strings.NewReader(body), nil)
	if err != nil {
		t.Fatalf("blob.Put: %v", err)
	}

	mbox, err := storage.GetMailbox(ctx, db, 1, "INBOX")
	if err != nil {
		t.Fatalf("GetMailbox: %v", err)
	}

	_, _, err = storage.InsertMessage(ctx, db, mbox.ID, blobKey, int64(len(body)),
		"alice@test.com", "bob@test.com", "Hello", 0)
	if err != nil {
		t.Fatalf("InsertMessage: %v", err)
	}

	mb, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}

	ch := make(chan *imap.Message, 10)
	seqset := &imap.SeqSet{}
	seqset.AddNum(1)
	err = mb.ListMessages(false, seqset, []imap.FetchItem{imap.FetchEnvelope}, ch)
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}

	msg := <-ch
	if msg == nil {
		t.Fatal("ListMessages returned nil message")
	}
	if msg.Envelope == nil {
		t.Fatal("expected envelope")
	}
	if msg.Envelope.Subject != "Hello" {
		t.Fatalf("expected subject 'Hello', got %q", msg.Envelope.Subject)
	}
	if len(msg.Envelope.From) == 0 || msg.Envelope.From[0].MailboxName != "alice@test.com" {
		t.Fatalf("expected from alice@test.com, got %+v", msg.Envelope.From)
	}
}

func TestMailboxSearchMessages(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	mb, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}

	mustCreateMessage(t, mb, testBody(), nil)
	mustCreateMessage(t, mb, testBody(), nil)

	uids, err := mb.SearchMessages(false, &imap.SearchCriteria{})
	if err != nil {
		t.Fatalf("SearchMessages: %v", err)
	}
	if len(uids) != 2 {
		t.Fatalf("expected 2 results, got %d: %v", len(uids), uids)
	}
	// When uid=false, SearchMessages returns sequence numbers (1-indexed).
	if uids[0] != 1 || uids[1] != 2 {
		t.Fatalf("expected seq numbers [1, 2], got %v", uids)
	}
}

func TestMailboxUpdateFlagsAdd(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	mb, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}

	mustCreateMessage(t, mb, testBody(), nil)

	seqset := &imap.SeqSet{}
	seqset.AddNum(1)
	if err := mb.UpdateMessagesFlags(false, seqset, imap.AddFlags, []string{imap.SeenFlag}); err != nil {
		t.Fatalf("UpdateMessagesFlags: %v", err)
	}

	ch := make(chan *imap.Message, 10)
	seqset2 := &imap.SeqSet{}
	seqset2.AddNum(1)
	_ = mb.ListMessages(false, seqset2, []imap.FetchItem{imap.FetchFlags}, ch)
	msg := <-ch
	if msg == nil {
		t.Fatal("expected message after flag update")
	}
	if len(msg.Flags) != 1 || msg.Flags[0] != imap.SeenFlag {
		t.Fatalf("expected Seen flag, got %v", msg.Flags)
	}
}

func TestMailboxUpdateFlagsRemove(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	mb, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}

	mustCreateMessage(t, mb, testBody(), []string{imap.SeenFlag, imap.FlaggedFlag})

	seqset := &imap.SeqSet{}
	seqset.AddNum(1)
	if err := mb.UpdateMessagesFlags(false, seqset, imap.RemoveFlags, []string{imap.SeenFlag}); err != nil {
		t.Fatalf("UpdateMessagesFlags: %v", err)
	}

	ch := make(chan *imap.Message, 10)
	seqset2 := &imap.SeqSet{}
	seqset2.AddNum(1)
	_ = mb.ListMessages(false, seqset2, []imap.FetchItem{imap.FetchFlags}, ch)
	msg := <-ch
	if msg == nil {
		t.Fatal("expected message after flag removal")
	}
	if len(msg.Flags) != 1 || msg.Flags[0] != imap.FlaggedFlag {
		t.Fatalf("expected Flagged flag, got %v", msg.Flags)
	}
}

func TestMailboxUpdateFlagsSet(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	mb, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}

	mustCreateMessage(t, mb, testBody(), []string{imap.SeenFlag, imap.DraftFlag})

	seqset := &imap.SeqSet{}
	seqset.AddNum(1)
	if err := mb.UpdateMessagesFlags(false, seqset, imap.SetFlags, []string{imap.AnsweredFlag}); err != nil {
		t.Fatalf("UpdateMessagesFlags: %v", err)
	}

	ch := make(chan *imap.Message, 10)
	seqset2 := &imap.SeqSet{}
	seqset2.AddNum(1)
	_ = mb.ListMessages(false, seqset2, []imap.FetchItem{imap.FetchFlags}, ch)
	msg := <-ch
	if msg == nil {
		t.Fatal("expected message after flag set")
	}
	if len(msg.Flags) != 1 || msg.Flags[0] != imap.AnsweredFlag {
		t.Fatalf("expected Answered flag, got %v", msg.Flags)
	}
}

func TestMailboxUpdateFlagsUID(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	mb, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}

	mustCreateMessage(t, mb, testBody(), nil)
	mustCreateMessage(t, mb, testBody(), nil)

	// Add Seen to UID 2 only.
	seqset2 := &imap.SeqSet{}
	seqset2.AddNum(2)
	if err := mb.UpdateMessagesFlags(true, seqset2, imap.AddFlags, []string{imap.SeenFlag}); err != nil {
		t.Fatalf("UpdateMessagesFlags: %v", err)
	}

	// List all via UID to check flags.
	chAll := make(chan *imap.Message, 10)
	seqsetAll := &imap.SeqSet{}
	seqsetAll.AddRange(1, 2)
	_ = mb.ListMessages(true, seqsetAll, []imap.FetchItem{imap.FetchFlags}, chAll)

	var msgs []*imap.Message
	for m := range chAll {
		msgs = append(msgs, m)
	}
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(msgs))
	}

	// Messages are in ascending UID order.
	if len(msgs[0].Flags) != 0 || len(msgs[1].Flags) != 1 || msgs[1].Flags[0] != imap.SeenFlag {
		t.Fatalf("expected UID 1: no flags, UID 2: Seen; got UID 1: %v, UID 2: %v", msgs[0].Flags, msgs[1].Flags)
	}
}

func TestMailboxCopyMessages(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	inbox, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}

	mustCreateMessage(t, inbox, testBody(), []string{imap.SeenFlag})

	seqset := &imap.SeqSet{}
	seqset.AddNum(1)
	if err := inbox.CopyMessages(false, seqset, "Sent"); err != nil {
		t.Fatalf("CopyMessages: %v", err)
	}

	sent, err := user.GetMailbox("Sent")
	if err != nil {
		t.Fatalf("GetMailbox(Sent): %v", err)
	}

	status, _ := sent.Status([]imap.StatusItem{imap.StatusMessages})
	if status.Messages != 1 {
		t.Fatalf("expected 1 message in Sent after copy, got %d", status.Messages)
	}

	inboxStatus, _ := inbox.Status([]imap.StatusItem{imap.StatusMessages})
	if inboxStatus.Messages != 1 {
		t.Fatalf("expected 1 message still in INBOX after copy, got %d", inboxStatus.Messages)
	}
}

func TestMailboxCopyMessagesUID(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	inbox, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}

	mustCreateMessage(t, inbox, testBody(), nil)
	mustCreateMessage(t, inbox, testBody(), nil)

	seqset := &imap.SeqSet{}
	seqset.AddNum(2)
	if err := inbox.CopyMessages(true, seqset, "Sent"); err != nil {
		t.Fatalf("CopyMessages: %v", err)
	}

	sent, err := user.GetMailbox("Sent")
	if err != nil {
		t.Fatalf("GetMailbox(Sent): %v", err)
	}
	sentStatus, _ := sent.Status([]imap.StatusItem{imap.StatusMessages})
	if sentStatus.Messages != 1 {
		t.Fatalf("expected 1 message in Sent after UID copy, got %d", sentStatus.Messages)
	}
}

func TestMailboxCopyMessagesToNonExistent(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	inbox, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}

	mustCreateMessage(t, inbox, testBody(), nil)

	seqset := &imap.SeqSet{}
	seqset.AddNum(1)
	if err := inbox.CopyMessages(false, seqset, "NonExistent"); err == nil {
		t.Fatal("CopyMessages to non-existent mailbox should fail")
	}
}

func TestMailboxExpunge(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	mb, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}

	mustCreateMessage(t, mb, testBody(), []string{imap.DeletedFlag})
	mustCreateMessage(t, mb, testBody(), nil)

	statusBefore, _ := mb.Status([]imap.StatusItem{imap.StatusMessages})
	if statusBefore.Messages != 2 {
		t.Fatalf("expected 2 messages before expunge, got %d", statusBefore.Messages)
	}

	if err := mb.Expunge(); err != nil {
		t.Fatalf("Expunge: %v", err)
	}

	statusAfter, _ := mb.Status([]imap.StatusItem{imap.StatusMessages})
	if statusAfter.Messages != 1 {
		t.Fatalf("expected 1 message after expunge, got %d", statusAfter.Messages)
	}
}

func TestMailboxExpungeNoneFlagged(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	mb, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}

	mustCreateMessage(t, mb, testBody(), []string{imap.SeenFlag})
	mustCreateMessage(t, mb, testBody(), []string{imap.DraftFlag})

	if err := mb.Expunge(); err != nil {
		t.Fatalf("Expunge: %v", err)
	}

	status, _ := mb.Status([]imap.StatusItem{imap.StatusMessages})
	if status.Messages != 2 {
		t.Fatalf("expected both messages to remain after expunge (no Deleted flag), got %d", status.Messages)
	}
}

func TestMailboxExpungeEmptyMailbox(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	mb, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}

	if err := mb.Expunge(); err != nil {
		t.Fatalf("Expunge on empty mailbox should not error: %v", err)
	}
}

func TestMailboxSetSubscribed(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	mb, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}

	if err := mb.SetSubscribed(true); err != nil {
		t.Fatalf("SetSubscribed(true): %v", err)
	}
	if err := mb.SetSubscribed(false); err != nil {
		t.Fatalf("SetSubscribed(false): %v", err)
	}
}

func TestMailboxCheck(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	mb, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}

	if err := mb.Check(); err != nil {
		t.Fatalf("Check: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 5. Integration: Server.Serve / Close
// ---------------------------------------------------------------------------

func TestServerServeAndClose(t *testing.T) {
	db := openTestDB(t)
	blob := blobstore.NewSQLiteStore(db)
	am := auth.NewManager(db)
	be := NewBackend(db, blob, am)

	cfg := &config.IMAPConfig{
		ListenAddr: "127.0.0.1:19930",
	}
	s := NewServer(cfg, be, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:19930")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Serve(ln)
	}()

	time.Sleep(50 * time.Millisecond)

	select {
	case err := <-errCh:
		t.Fatalf("Serve returned unexpectedly: %v", err)
	default:
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 6. Edge cases
// ---------------------------------------------------------------------------

func TestMailboxCreateMessageLargeBody(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	mb, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}

	body := make([]byte, 64*1024)
	_, _ = rand.Read(body)
	if err := mb.CreateMessage(nil, time.Now(), newTestLiteral(string(body))); err != nil {
		t.Fatalf("CreateMessage with 64KB body: %v", err)
	}

	status, _ := mb.Status([]imap.StatusItem{imap.StatusMessages})
	if status.Messages != 1 {
		t.Fatalf("expected 1 message after inserting 64KB body, got %d", status.Messages)
	}
}

func TestUIDSequence(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	mb, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}

	for range 5 {
		mustCreateMessage(t, mb, testBody(), nil)
	}

	status, _ := mb.Status([]imap.StatusItem{imap.StatusMessages, imap.StatusUidNext})
	if status.Messages != 5 {
		t.Fatalf("expected 5 messages, got %d", status.Messages)
	}
	if status.UidNext != 6 {
		t.Fatalf("expected UidNext=6, got %d", status.UidNext)
	}
}

func TestUIDPerMailbox(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	inbox, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}
	sent, err := user.GetMailbox("Sent")
	if err != nil {
		t.Fatalf("GetMailbox(Sent): %v", err)
	}

	mustCreateMessage(t, inbox, testBody(), nil)
	mustCreateMessage(t, sent, testBody(), nil)
	mustCreateMessage(t, inbox, testBody(), nil)

	inboxStatus, _ := inbox.Status([]imap.StatusItem{imap.StatusMessages, imap.StatusUidNext})
	sentStatus, _ := sent.Status([]imap.StatusItem{imap.StatusMessages, imap.StatusUidNext})

	if inboxStatus.Messages != 2 {
		t.Fatalf("expected 2 messages in INBOX, got %d", inboxStatus.Messages)
	}
	if inboxStatus.UidNext != 3 {
		t.Fatalf("expected UidNext=3 in INBOX, got %d", inboxStatus.UidNext)
	}
	if sentStatus.Messages != 1 {
		t.Fatalf("expected 1 message in Sent, got %d", sentStatus.Messages)
	}
	if sentStatus.UidNext != 2 {
		t.Fatalf("expected UidNext=2 in Sent, got %d", sentStatus.UidNext)
	}
}

func TestLoginAndMailboxFlow(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	mailboxes, err := user.ListMailboxes(false)
	if err != nil {
		t.Fatalf("ListMailboxes: %v", err)
	}
	if len(mailboxes) < 1 {
		t.Fatal("no mailboxes")
	}

	inbox := mailboxes[0]
	for range 3 {
		mustCreateMessage(t, inbox, testBody(), []string{imap.SeenFlag})
	}

	status, err := inbox.Status([]imap.StatusItem{imap.StatusMessages, imap.StatusUidNext})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Messages != 3 {
		t.Fatalf("expected 3 messages, got %d", status.Messages)
	}
	if status.UidNext != 4 {
		t.Fatalf("expected UidNext=4, got %d", status.UidNext)
	}

	seqset := &imap.SeqSet{}
	seqset.AddNum(2)
	if err := inbox.UpdateMessagesFlags(false, seqset, imap.AddFlags, []string{imap.DeletedFlag}); err != nil {
		t.Fatalf("UpdateMessagesFlags: %v", err)
	}
	if err := inbox.Expunge(); err != nil {
		t.Fatalf("Expunge: %v", err)
	}

	statusAfter, _ := inbox.Status([]imap.StatusItem{imap.StatusMessages})
	if statusAfter.Messages != 2 {
		t.Fatalf("expected 2 messages after expunge, got %d", statusAfter.Messages)
	}
}

func TestListMessagesFromDifferentMailbox(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	drafts, err := user.GetMailbox("Drafts")
	if err != nil {
		t.Fatalf("GetMailbox(Drafts): %v", err)
	}

	mustCreateMessage(t, drafts, "Draft message 1", []string{imap.DraftFlag})
	mustCreateMessage(t, drafts, "Draft message 2", []string{imap.DraftFlag, imap.SeenFlag})

	status, _ := drafts.Status([]imap.StatusItem{imap.StatusMessages, imap.StatusUidNext})
	if status.Messages != 2 {
		t.Fatalf("expected 2 draft messages, got %d", status.Messages)
	}
	if status.UidNext != 3 {
		t.Fatalf("expected UidNext=3 in Drafts, got %d", status.UidNext)
	}

	ch := make(chan *imap.Message, 10)
	seqset := &imap.SeqSet{}
	seqset.AddRange(1, 2)
	if err := drafts.ListMessages(false, seqset, []imap.FetchItem{imap.FetchFlags}, ch); err != nil {
		t.Fatalf("ListMessages: %v", err)
	}

	var msgs []*imap.Message
	for msg := range ch {
		msgs = append(msgs, msg)
	}
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages from ListMessages, got %d", len(msgs))
	}
}

func TestMailboxCopyMessagesToSameMailbox(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	mb, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}

	mustCreateMessage(t, mb, testBody(), nil)

	seqset := &imap.SeqSet{}
	seqset.AddNum(1)
	if err := mb.CopyMessages(false, seqset, "INBOX"); err != nil {
		t.Fatalf("CopyMessages to INBOX: %v", err)
	}

	status, _ := mb.Status([]imap.StatusItem{imap.StatusMessages})
	if status.Messages != 2 {
		t.Fatalf("expected 2 messages after copy-to-self, got %d", status.Messages)
	}
}

func TestMessageBlobKeyPreserved(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	body := "From: x@y\r\nSubject: blob test\r\n\r\nDistinctive blob content."

	mb, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}

	mustCreateMessage(t, mb, body, nil)

	ch := make(chan *imap.Message, 10)
	seqset := &imap.SeqSet{}
	seqset.AddNum(1)
	if err := mb.ListMessages(false, seqset, []imap.FetchItem{imap.FetchRFC822}, ch); err != nil {
		t.Fatalf("ListMessages: %v", err)
	}

	msg := <-ch
	section := &imap.BodySectionName{}
	r := msg.GetBody(section)
	if r == nil {
		t.Fatal("body section not found in fetched message")
	}
	got, _ := io.ReadAll(r)
	if string(got) != body {
		t.Fatalf("body content mismatch:\ngot:  %q\nwant: %q", string(got), body)
	}
}

func TestMailboxListMessagesNoItems(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	mb, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}

	mustCreateMessage(t, mb, testBody(), nil)

	ch := make(chan *imap.Message, 10)
	seqset := &imap.SeqSet{}
	seqset.AddNum(1)
	if err := mb.ListMessages(false, seqset, nil, ch); err != nil {
		t.Fatalf("ListMessages with no items: %v", err)
	}
	msg := <-ch
	if msg == nil {
		t.Fatal("expected message even with no fetch items")
	}
}

func TestMailboxListMessagesRespectsUIDFilter(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	mb, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}

	mustCreateMessage(t, mb, testBody(), nil)
	mustCreateMessage(t, mb, testBody(), nil)
	mustCreateMessage(t, mb, testBody(), nil)

	ch := make(chan *imap.Message, 10)
	seqset := &imap.SeqSet{}
	seqset.AddRange(2, 3)
	if err := mb.ListMessages(true, seqset, []imap.FetchItem{imap.FetchFlags}, ch); err != nil {
		t.Fatalf("ListMessages: %v", err)
	}

	var msgs []*imap.Message
	for msg := range ch {
		msgs = append(msgs, msg)
	}
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages with UIDs 2-3, got %d", len(msgs))
	}
	// Messages sorted by UID ascending.
	if msgs[0].Uid != 2 || msgs[1].Uid != 3 {
		t.Fatalf("expected Uids [2,3], got [%d,%d]", msgs[0].Uid, msgs[1].Uid)
	}
}

func TestMailboxStatusFlags(t *testing.T) {
	be, am, _ := setupTest(t)
	_ = createTestUser(t, am, testEmail, testPassword)
	user := loginHelper(t, be, testEmail, testPassword)

	mb, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}

	status, err := mb.Status(nil)
	if err != nil {
		t.Fatalf("Status with nil items: %v", err)
	}
	if status == nil {
		t.Fatal("expected non-nil status with nil items")
	}

	expectedFlags := []string{imap.SeenFlag, imap.AnsweredFlag, imap.FlaggedFlag, imap.DeletedFlag, imap.DraftFlag}
	for _, f := range expectedFlags {
		found := false
		for _, sf := range status.Flags {
			if sf == f {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected standard flag %q in mailbox status, got %v", f, status.Flags)
		}
	}
}

func TestFlagsToBitsAndBack(t *testing.T) {
	tests := []struct {
		name  string
		flags []string
	}{
		{"Seen", []string{imap.SeenFlag}},
		{"Seen+Answered", []string{imap.SeenFlag, imap.AnsweredFlag}},
		{"Deleted+Flagged", []string{imap.DeletedFlag, imap.FlaggedFlag}},
		{"All", []string{imap.SeenFlag, imap.AnsweredFlag, imap.FlaggedFlag, imap.DeletedFlag, imap.DraftFlag}},
		{"Empty", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bits := flagsToBits(tt.flags)
			got := flagsToIMAP(bits)
			if len(got) != len(tt.flags) {
				t.Fatalf("len mismatch: got %d flags, want %d: got=%v want=%v", len(got), len(tt.flags), got, tt.flags)
			}
			for _, want := range tt.flags {
				found := false
				for _, g := range got {
					if g == want {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("flag %q missing from round-trip result %v", want, got)
				}
			}
		})
	}
}

func TestFlagsToBitsOrderIndependent(t *testing.T) {
	a := flagsToBits([]string{imap.SeenFlag, imap.DraftFlag})
	b := flagsToBits([]string{imap.DraftFlag, imap.SeenFlag})
	if a != b {
		t.Fatalf("flag bits not order-independent: %d vs %d", a, b)
	}
}
