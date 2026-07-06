package pop3

import (
	"bufio"
	"context"
	"database/sql"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/i-got-this-faa/marco/pkg/auth"
	"github.com/i-got-this-faa/marco/pkg/blobstore"
	"github.com/i-got-this-faa/marco/pkg/config"
	"github.com/i-got-this-faa/marco/pkg/storage"
	_ "modernc.org/sqlite"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	f, err := os.CreateTemp("", "marco-pop3-test-*.sqlite")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	f.Close()
	db, err := sql.Open("sqlite", f.Name())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() {
		db.Close()
		os.Remove(f.Name())
	})
	return db
}

func migrateTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db := openTestDB(t)
	if err := storage.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func testPOP3Config() *config.POP3Config {
	return &config.POP3Config{ListenAddr: ":110"}
}

func testServer(t *testing.T) (*Server, *sql.DB) {
	t.Helper()
	db := migrateTestDB(t)
	blob := blobstore.NewFSStore(t.TempDir())
	am := auth.NewManager(db)
	_, err := am.CreateUser(context.Background(), "test@example.com", "secret123")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	srv := NewServer(testPOP3Config(), db, blob, am, nil)
	return srv, db
}

// discardConn implements net.Conn by discarding writes and providing an EOF
// reader. Safe for unit tests that check return values, not wire output.
type discardConn struct {
	io.Reader
	io.Writer
}

func newDiscardConn() *discardConn {
	return &discardConn{Reader: strings.NewReader(""), Writer: io.Discard}
}
func (c *discardConn) Close() error                                   { return nil }
func (c *discardConn) LocalAddr() net.Addr                            { return &net.TCPAddr{Port: 0} }
func (c *discardConn) RemoteAddr() net.Addr                           { return &net.TCPAddr{Port: 0} }
func (c *discardConn) SetDeadline(time.Time) error                    { return nil }
func (c *discardConn) SetReadDeadline(time.Time) error                { return nil }
func (c *discardConn) SetWriteDeadline(time.Time) error               { return nil }

func makeSession(srv *Server, state int, uid int64) *Session {
	c := newDiscardConn()
	return &Session{
		srv:           srv,
		conn:          c,
		br:            bufio.NewReader(c),
		bw:            bufio.NewWriter(c),
		userID:        uid,
		state:         state,
		markedDeleted: make(map[int64]bool),
		startOfLine:   true,
	}
}

func writeTestMessage(t *testing.T, db *sql.DB, blob blobstore.Store, uid int64, body string) {
	t.Helper()
	ctx := context.Background()
	mbox, err := storage.GetMailbox(ctx, db, uid, "INBOX")
	if err != nil {
		t.Fatalf("get inbox: %v", err)
	}
	k, sz, err := blob.Put(ctx, strings.NewReader(body), nil)
	if err != nil {
		t.Fatalf("put blob: %v", err)
	}
	_, _, err = storage.InsertMessage(ctx, db, mbox.ID, k, sz,
		"sender@test.com", "test@example.com", "Test", 0)
	if err != nil {
		t.Fatalf("insert msg: %v", err)
	}
}

// --- Auth ---

func TestAuth_Success(t *testing.T) {
	srv, _ := testServer(t)
	s := makeSession(srv, stateAuthorization, 0)
	s.handleUSER("test@example.com")
	s.handlePASS("secret123")
	if s.state != stateTransaction {
		t.Fatal("expected transaction state after auth")
	}
	if s.userID == 0 {
		t.Fatal("expected non-zero userID")
	}
}

func TestAuth_WrongPassword(t *testing.T) {
	srv, _ := testServer(t)
	s := makeSession(srv, stateAuthorization, 0)
	s.handleUSER("test@example.com")
	s.handlePASS("wrongpassword123")
	if s.state != stateAuthorization {
		t.Fatal("should remain in authorization state")
	}
}

func TestAuth_UnknownUser(t *testing.T) {
	srv, _ := testServer(t)
	s := makeSession(srv, stateAuthorization, 0)
	s.handleUSER("nobody@example.com")
	s.handlePASS("secret123")
	if s.state != stateAuthorization {
		t.Fatal("should remain in authorization state")
	}
}

func TestAuth_NoUserFirst(t *testing.T) {
	srv, _ := testServer(t)
	s := makeSession(srv, stateAuthorization, 0)
	s.handlePASS("secret123")
	if s.state != stateAuthorization {
		t.Fatal("should remain in authorization state")
	}
}

// --- Transaction commands ---

func TestSTAT(t *testing.T) {
	srv, db := testServer(t)
	writeTestMessage(t, db, srv.blob, 1, "From: t\r\n\r\nBody")
	s := makeSession(srv, stateTransaction, 1)
	if !s.handleSTAT() {
		t.Fatal("STAT should return true")
	}
}

func TestLIST_NoArg(t *testing.T) {
	srv, db := testServer(t)
	writeTestMessage(t, db, srv.blob, 1, "From: t\r\n\r\nBody")
	s := makeSession(srv, stateTransaction, 1)
	if !s.handleLIST("") {
		t.Fatal("LIST should return true")
	}
}

func TestLIST_WithArg(t *testing.T) {
	srv, db := testServer(t)
	writeTestMessage(t, db, srv.blob, 1, "From: t\r\n\r\nBody")
	s := makeSession(srv, stateTransaction, 1)
	if !s.handleLIST("1") {
		t.Fatal("LIST 1 should return true")
	}
}

func TestLIST_NotFound(t *testing.T) {
	srv, _ := testServer(t)
	s := makeSession(srv, stateTransaction, 1)
	if !s.handleLIST("999") {
		t.Fatal("LIST with missing msg returns true (continue)")
	}
}

func TestRETR(t *testing.T) {
	srv, db := testServer(t)
	writeTestMessage(t, db, srv.blob, 1, "From: t\r\n\r\nBody")
	s := makeSession(srv, stateTransaction, 1)
	if !s.handleRETR("1") {
		t.Fatal("RETR should return true")
	}
}

func TestDELE_QUIT(t *testing.T) {
	srv, db := testServer(t)
	writeTestMessage(t, db, srv.blob, 1, "From: t\r\n\r\nBody")
	s := makeSession(srv, stateTransaction, 1)

	if !s.handleDELE("1") {
		t.Fatal("DELE should return true")
	}
	if !s.markedDeleted[1] {
		t.Fatal("msg should be marked deleted")
	}

	ctx := context.Background()
	mbox, _ := storage.GetMailbox(ctx, db, 1, "INBOX")
	msgs, _ := storage.ListMessages(ctx, db, mbox.ID, 0, 0)
	if len(msgs) != 1 {
		t.Fatalf("expected 1 msg before QUIT, got %d", len(msgs))
	}

	s.handleQUIT()
	msgs, _ = storage.ListMessages(ctx, db, mbox.ID, 0, 0)
	if len(msgs) != 0 {
		t.Fatalf("expected 0 msgs after QUIT, got %d", len(msgs))
	}
}

func TestRSET(t *testing.T) {
	srv, db := testServer(t)
	writeTestMessage(t, db, srv.blob, 1, "From: t\r\n\r\nBody")
	s := makeSession(srv, stateTransaction, 1)
	s.handleDELE("1")

	if !s.handleRSET() {
		t.Fatal("RSET should return true")
	}
	if len(s.markedDeleted) != 0 {
		t.Fatal("markedDeleted should be empty")
	}

	ctx := context.Background()
	mbox, _ := storage.GetMailbox(ctx, db, 1, "INBOX")
	msgs, _ := storage.ListMessages(ctx, db, mbox.ID, 0, 0)
	if len(msgs) != 1 {
		t.Fatalf("expected 1 msg after RSET, got %d", len(msgs))
	}
}

func TestNOOP(t *testing.T) {
	srv, _ := testServer(t)
	s := makeSession(srv, stateTransaction, 1)
	if !s.handleCommand("NOOP", "") {
		t.Fatal("NOOP should return true")
	}
}

func TestTOP(t *testing.T) {
	srv, db := testServer(t)
	writeTestMessage(t, db, srv.blob, 1, "From: t@e.com\r\nSubject: T\r\n\r\nL1\r\nL2\r\nL3")
	s := makeSession(srv, stateTransaction, 1)
	if !s.handleTOP("1 2") {
		t.Fatal("TOP should return true")
	}
}

func TestUIDL(t *testing.T) {
	srv, db := testServer(t)
	writeTestMessage(t, db, srv.blob, 1, "From: t\r\n\r\nBody")
	s := makeSession(srv, stateTransaction, 1)
	if !s.handleUIDL("") {
		t.Fatal("UIDL should return true")
	}
}

func TestUIDL_WithArg(t *testing.T) {
	srv, db := testServer(t)
	writeTestMessage(t, db, srv.blob, 1, "From: t\r\n\r\nBody")
	s := makeSession(srv, stateTransaction, 1)
	if !s.handleUIDL("1") {
		t.Fatal("UIDL 1 should return true")
	}
}

func TestQUIT_Closes(t *testing.T) {
	srv, _ := testServer(t)
	s := makeSession(srv, stateAuthorization, 0)
	if s.handleQUIT() {
		t.Fatal("QUIT should return false")
	}
}

func TestCommandRequiresAuth(t *testing.T) {
	srv, _ := testServer(t)
	s := makeSession(srv, stateAuthorization, 0)
	if !s.handleCommand("STAT", "") {
		t.Fatal("STAT before auth returns true (continue)")
	}
	if s.state != stateAuthorization {
		t.Fatal("should remain in authorization state")
	}
}

func TestCAPA(t *testing.T) {
	srv, _ := testServer(t)
	s := makeSession(srv, stateAuthorization, 0)
	if !s.handleCAPA() {
		t.Fatal("CAPA should return true")
	}
}

// --- Pipe integration ---

func TestPipeSession(t *testing.T) {
	srv, db := testServer(t)
	writeTestMessage(t, db, srv.blob, 1, "From: t\r\n\r\nHello POP3")

	serverEnd, clientEnd := net.Pipe()
	done := make(chan struct{})

	go func() {
		defer close(done)
		s := &Session{
			srv:           srv,
			conn:          serverEnd,
			br:            bufio.NewReader(serverEnd),
			bw:            bufio.NewWriter(serverEnd),
			log:           srv.log,
			state:         stateAuthorization,
			markedDeleted: make(map[int64]bool),
			startOfLine:   true,
		}
		s.handle()
	}()

	br := bufio.NewReader(clientEnd)
	bw := bufio.NewWriter(clientEnd)

	mustOK := func(when string) {
		r, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("%s: read: %v", when, err)
		}
		if !strings.HasPrefix(r, "+OK") {
			t.Errorf("%s: expected +OK, got %s", when, strings.TrimSpace(r))
		}
	}
	drainDot := func() {
		for {
			l, e := br.ReadString('\n')
			if e != nil {
				t.Fatalf("drain dot: %v", e)
			}
			if strings.TrimRight(l, "\r\n") == "." {
				break
			}
		}
	}

	mustOK("greeting")
	bw.WriteString("USER test@example.com\r\n"); bw.Flush()
	mustOK("USER")
	bw.WriteString("PASS secret123\r\n"); bw.Flush()
	mustOK("PASS")
	bw.WriteString("STAT\r\n"); bw.Flush()
	mustOK("STAT")
	bw.WriteString("LIST\r\n"); bw.Flush()
	mustOK("LIST")
	drainDot()
	bw.WriteString("QUIT\r\n"); bw.Flush()
	mustOK("QUIT")
	clientEnd.Close()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out")
	}
}
