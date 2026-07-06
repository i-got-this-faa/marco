package smtp

import (
	"context"
	"crypto/tls"
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
	dto "github.com/prometheus/client_model/go"
	"github.com/i-got-this-faa/marco/pkg/auth"
	"github.com/i-got-this-faa/marco/pkg/blobstore"
	"github.com/i-got-this-faa/marco/pkg/config"
	"github.com/i-got-this-faa/marco/pkg/metrics"
	"github.com/i-got-this-faa/marco/pkg/queue"
	"github.com/i-got-this-faa/marco/pkg/storage"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := storage.Open(":memory:?mode=memory")
	if err != nil {
		t.Fatalf("Open(':memory:'): %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func migrateTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db := openTestDB(t)
	if err := storage.Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return db
}

// testConfig returns a minimal SMTPConfig for testing.
func testConfig() *config.SMTPConfig {
	return &config.SMTPConfig{
		ListenAddr:      "127.0.0.1:0",
		Hostname:        "test.local",
		MaxMessageSize:  256 * 1024, // 256 KB
		MaxRecipients:   10,
	}
}

func testBackend(t *testing.T) (*Backend, *sql.DB) {
	t.Helper()
	db := migrateTestDB(t)
	ctx := context.Background()

	// Create a system user (id=0) for the OUTBOUND mailbox.
	// SQLite allows explicit id assignment even with AUTOINCREMENT.
	hash, err := auth.HashPassword("system")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	_, err = db.ExecContext(ctx,
		`INSERT INTO users (id, email, password_hash, created_at) VALUES (0, 'system@test.local', ?, 0)`,
		hash,
	)
	if err != nil {
		t.Fatalf("create system user: %v", err)
	}

	// OUTBOUND mailbox needed by enqueueOutbound.
	if _, err := storage.CreateMailbox(ctx, db, 0, "OUTBOUND"); err != nil {
		t.Fatalf("CreateMailbox(OUTBOUND): %v", err)
	}

	// Create a test user with default mailboxes.
	_, err = auth.NewManager(db).CreateUser(ctx, "user@test.local", "testpass", false)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	blob := blobstore.NewSQLiteStore(db)
	metricsReg := metrics.NewRegistry()
	qm := queue.NewManager(db, blob, 1, 3, time.Second, "")
	am := auth.NewManager(db)
	cfg := testConfig()

	be := &Backend{
		db:      db,
		blob:    blob,
		queue:   qm,
		auth:    am,
		cfg:     cfg,
		metrics: metricsReg,
		log:     slog.With("service", "smtp", "test", true),
	}
	return be, db
}

// testSession returns a bare Session (not attached to a real SMTP server).
func testSession(t *testing.T) (*Session, *sql.DB) {
	t.Helper()
	be, db := testBackend(t)
	return &Session{backend: be}, db
}


// generateTestCert creates a self-signed TLS certificate for testing.
func generateTestCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Marco Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"127.0.0.1"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create cert: %w", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}
// readCounter reads the current value of a prometheus.Counter.
func readCounter(t *testing.T, c interface {
	Write(*dto.Metric) error
}) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatalf("Write counter: %v", err)
	}
	return m.GetCounter().GetValue()
}

// readGauge reads the current value of a prometheus.Gauge.
func readGauge(t *testing.T, g interface {
	Write(*dto.Metric) error
}) float64 {
	t.Helper()
	var m dto.Metric
	if err := g.Write(&m); err != nil {
		t.Fatalf("Write gauge: %v", err)
	}
	return m.GetGauge().GetValue()
}

// requireSMTPError asserts that err is a non-nil *smtp.SMTPError and
// returns it.
func requireSMTPError(t *testing.T, err error) *smtp.SMTPError {
	t.Helper()
	if err == nil {
		t.Fatal("expected SMTP error, got nil")
	}
	smtpErr, ok := err.(*smtp.SMTPError)
	if !ok {
		t.Fatalf("error type = %T, want *smtp.SMTPError", err)
	}
	return smtpErr
}

// ---------------------------------------------------------------------------
// Backend tests
// ---------------------------------------------------------------------------

func TestBackend_NewSession(t *testing.T) {
	be, _ := testBackend(t)

	sess, err := be.NewSession(nil)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if sess == nil {
		t.Fatal("NewSession returned nil session")
	}

	// Metrics should have been incremented.
	if got := readCounter(t, be.metrics.SMTPConnections); got != 1 {
		t.Errorf("SMTPConnections = %f, want 1", got)
	}
	if got := readGauge(t, be.metrics.ActiveConnections); got != 1 {
		t.Errorf("ActiveConnections = %f, want 1", got)
	}

	// Logout decrements active count.
	if err := sess.Logout(); err != nil {
		t.Errorf("Logout: %v", err)
	}
	if got := readGauge(t, be.metrics.ActiveConnections); got != 0 {
		t.Errorf("ActiveConnections after Logout = %f, want 0", got)
	}
}

// ---------------------------------------------------------------------------
// Session – Mail
// ---------------------------------------------------------------------------

func TestSession_Mail_Valid(t *testing.T) {
	sess, _ := testSession(t)
	if err := sess.Mail("sender@example.com", nil); err != nil {
		t.Errorf("Mail(valid): %v", err)
	}
	if sess.from != "sender@example.com" {
		t.Errorf("from = %q, want %q", sess.from, "sender@example.com")
	}
}

func TestSession_Mail_Invalid_NoAtSign(t *testing.T) {
	sess, _ := testSession(t)
	err := sess.Mail("noatsign", nil)
	smtpErr := requireSMTPError(t, err)
	if smtpErr.Code != 553 {
		t.Errorf("error code = %d, want 553", smtpErr.Code)
	}
}

// ---------------------------------------------------------------------------
// Session – Rcpt
// ---------------------------------------------------------------------------

func TestSession_Rcpt_LocalDomain(t *testing.T) {
	sess, _ := testSession(t)
	if err := sess.Mail("from@test.local", nil); err != nil {
		t.Fatal(err)
	}
	if err := sess.Rcpt("user@test.local", nil); err != nil {
		t.Errorf("Rcpt(local domain): %v", err)
	}
	if len(sess.recipients) != 1 || sess.recipients[0] != "user@test.local" {
		t.Errorf("recipients = %v, want [user@test.local]", sess.recipients)
	}
}

func TestSession_Rcpt_ExternalDomain_Rejected(t *testing.T) {
	sess, _ := testSession(t)
	if err := sess.Mail("from@test.local", nil); err != nil {
		t.Fatal(err)
	}
	err := sess.Rcpt("someone@external.com", nil)
	smtpErr := requireSMTPError(t, err)
	if smtpErr.Code != 550 {
		t.Errorf("error code = %d, want 550", smtpErr.Code)
	}
}

func TestSession_Rcpt_InvalidAddress(t *testing.T) {
	sess, _ := testSession(t)
	if err := sess.Mail("from@test.local", nil); err != nil {
		t.Fatal(err)
	}
	err := sess.Rcpt("bogus", nil)
	smtpErr := requireSMTPError(t, err)
	if smtpErr.Code != 553 {
		t.Errorf("error code = %d, want 553", smtpErr.Code)
	}
}

func TestSession_Rcpt_MaxRecipients(t *testing.T) {
	sess, _ := testSession(t)
	cfg := sess.backend.cfg
	cfg.MaxRecipients = 3

	if err := sess.Mail("from@test.local", nil); err != nil {
		t.Fatal(err)
	}

	for i := range cfg.MaxRecipients {
		addr := fmt.Sprintf("u%d@test.local", i)
		if err := sess.Rcpt(addr, nil); err != nil {
			t.Fatalf("Rcpt(%q) on iteration %d: %v", addr, i, err)
		}
	}

	// One more should be rejected.
	err := sess.Rcpt("overflow@test.local", nil)
	smtpErr := requireSMTPError(t, err)
	if smtpErr.Code != 552 {
		t.Errorf("error code = %d, want 552", smtpErr.Code)
	}
}

func TestSession_Rcpt_AuthBypass(t *testing.T) {
	sess, _ := testSession(t)
	sess.authed = true
	sess.authedUser = "user@test.local"

	if err := sess.Mail("user@test.local", nil); err != nil {
		t.Fatal(err)
	}

	// Authenticated sessions can relay to any domain.
	if err := sess.Rcpt("anyone@external.com", nil); err != nil {
		t.Errorf("authenticated Rcpt should allow external: %v", err)
	}
	if len(sess.recipients) != 1 {
		t.Errorf("recipients = %v, want 1", sess.recipients)
	}
}

// ---------------------------------------------------------------------------
// Session – Data (unit tests, no network)
// ---------------------------------------------------------------------------

func TestSession_Data_LocalDelivery(t *testing.T) {
	sess, db := testSession(t)
	ctx := context.Background()

	if err := sess.Mail("remote@example.com", nil); err != nil {
		t.Fatal(err)
	}
	if err := sess.Rcpt("user@test.local", nil); err != nil {
		t.Fatal(err)
	}

	msgBody := "From: remote@example.com\r\nTo: user@test.local\r\nSubject: Hello\r\n\r\nHi there!"
	if err := sess.Data(strings.NewReader(msgBody)); err != nil {
		t.Fatalf("Data: %v", err)
	}

	// Verify the message was delivered to user@test.local's INBOX.
	user, err := storage.GetUserByEmail(ctx, db, "user@test.local")
	if err != nil {
		t.Fatal(err)
	}
	mbox, err := storage.GetMailbox(ctx, db, user.ID, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := storage.ListMessages(ctx, db, mbox.ID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("INBOX has %d messages, want 1", len(msgs))
	}
	if msgs[0].FromAddr != "remote@example.com" {
		t.Errorf("FromAddr = %q, want %q", msgs[0].FromAddr, "remote@example.com")
	}
	if msgs[0].ToAddr != "user@test.local" {
		t.Errorf("ToAddr = %q, want %q", msgs[0].ToAddr, "user@test.local")
	}
	if msgs[0].Subject != "Hello" {
		t.Errorf("Subject = %q, want %q", msgs[0].Subject, "Hello")
	}
}

func TestSession_Data_ExceedsMaxSize(t *testing.T) {
	sess, _ := testSession(t)
	sess.backend.cfg.MaxMessageSize = 100

	if err := sess.Mail("from@test.local", nil); err != nil {
		t.Fatal(err)
	}
	if err := sess.Rcpt("user@test.local", nil); err != nil {
		t.Fatal(err)
	}

	body := strings.Repeat("X", 101)
	err := sess.Data(strings.NewReader(body))
	smtpErr := requireSMTPError(t, err)
	if smtpErr.Code != 552 {
		t.Errorf("error code = %d, want 552", smtpErr.Code)
	}
}

func TestSession_Data_OutboundDelivery(t *testing.T) {
	sess, db := testSession(t)
	ctx := context.Background()

	sess.authed = true
	sess.authedUser = "user@test.local"

	if err := sess.Mail("from@test.local", nil); err != nil {
		t.Fatal(err)
	}
	// A recipient not in our users table triggers outbound enqueue.
	if err := sess.Rcpt("external@other.com", nil); err != nil {
		t.Fatal(err)
	}

	msgBody := "From: from@test.local\r\nTo: external@other.com\r\nSubject: Outbound\r\n\r\nBody."
	if err := sess.Data(strings.NewReader(msgBody)); err != nil {
		t.Fatalf("Data: %v", err)
	}

	// Verify the OUTBOUND mailbox got a message.
	mbox, err := storage.GetMailbox(ctx, db, 0, "OUTBOUND")
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := storage.ListMessages(ctx, db, mbox.ID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) < 1 {
		t.Fatal("expected at least one message in OUTBOUND mailbox")
	}

	// Verify a queue entry was created.
	pending, err := storage.ListPending(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) < 1 {
		t.Fatal("expected at least one pending queue item")
	}
}

func TestSession_Data_LocalAndExternal(t *testing.T) {
	sess, db := testSession(t)
	ctx := context.Background()

	sess.authed = true
	sess.authedUser = "user@test.local"

	if err := sess.Mail("from@example.com", nil); err != nil {
		t.Fatal(err)
	}
	if err := sess.Rcpt("user@test.local", nil); err != nil {
		t.Fatal(err)
	}
	if err := sess.Rcpt("external@other.com", nil); err != nil {
		t.Fatal(err)
	}

	msgBody := "From: from@example.com\r\nTo: user@test.local, external@other.com\r\nSubject: Both\r\n\r\nHi."
	if err := sess.Data(strings.NewReader(msgBody)); err != nil {
		t.Fatalf("Data: %v", err)
	}

	// Local user should have a message in INBOX.
	user, err := storage.GetUserByEmail(ctx, db, "user@test.local")
	if err != nil {
		t.Fatal(err)
	}
	mbox, err := storage.GetMailbox(ctx, db, user.ID, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	localMsgs, err := storage.ListMessages(ctx, db, mbox.ID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(localMsgs) != 1 {
		t.Errorf("INBOX has %d messages, want 1", len(localMsgs))
	}

	// External recipient should generate a queue entry.
	pending, err := storage.ListPending(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) < 1 {
		t.Fatal("expected at least one pending queue item for external delivery")
	}
}

// ---------------------------------------------------------------------------
// Session – Reset
// ---------------------------------------------------------------------------

func TestSession_Reset(t *testing.T) {
	sess, _ := testSession(t)
	sess.from = "someone@test.local"
	sess.recipients = []string{"a@test.local", "b@test.local"}

	sess.Reset()

	if sess.from != "" {
		t.Errorf("from after Reset = %q, want empty", sess.from)
	}
	if sess.recipients != nil {
		t.Errorf("recipients after Reset = %v, want nil", sess.recipients)
	}
}

// ---------------------------------------------------------------------------
// Session – Logout
// ---------------------------------------------------------------------------

func TestSession_Logout(t *testing.T) {
	be, _ := testBackend(t)
	sess := &Session{backend: be}

	// Simulate NewSession incrementing the gauge.
	be.metrics.ActiveConnections.Inc()

	if err := sess.Logout(); err != nil {
		t.Errorf("Logout: %v", err)
	}
	if got := readGauge(t, be.metrics.ActiveConnections); got != 0 {
		t.Errorf("ActiveConnections after Logout = %f, want 0", got)
	}
}

// ---------------------------------------------------------------------------
// Server lifecycle
// ---------------------------------------------------------------------------

func TestServer_NewServer(t *testing.T) {
	be, db := testBackend(t)
	cfg := testConfig()

	srv := NewServer(cfg, db, be.blob, be.queue, be.auth, nil, be.metrics, nil)
	if srv == nil {
		t.Fatal("NewServer returned nil")
	}
	if srv.Addr != cfg.ListenAddr {
		t.Errorf("Addr = %q, want %q", srv.Addr, cfg.ListenAddr)
	}
	if srv.Domain != cfg.Hostname {
		t.Errorf("Domain = %q, want %q", srv.Domain, cfg.Hostname)
	}
	if srv.MaxMessageBytes != cfg.MaxMessageSize {
		t.Errorf("MaxMessageBytes = %d, want %d", srv.MaxMessageBytes, cfg.MaxMessageSize)
	}
	if srv.MaxRecipients != cfg.MaxRecipients {
		t.Errorf("MaxRecipients = %d, want %d", srv.MaxRecipients, cfg.MaxRecipients)
	}
	if srv.AllowInsecureAuth != false {
		t.Errorf("AllowInsecureAuth = %v, want false", srv.AllowInsecureAuth)
	}
}

func TestServer_ServeAndShutdown(t *testing.T) {
	be, db := testBackend(t)
	cfg := testConfig()
	srv := NewServer(cfg, db, be.blob, be.queue, be.auth, nil, be.metrics, nil)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer l.Close()

	go func() {
		// Serve blocks until listener is closed or Shutdown is called.
		if err := srv.Serve(l); err != nil {
			t.Logf("Serve returned (expected): %v", err)
		}
	}()

	time.Sleep(50 * time.Millisecond)

	// Connect and verify we get an SMTP greeting.
	conn, err := net.DialTimeout("tcp", l.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	greeting := string(buf[:n])
	if !strings.Contains(greeting, "220") {
		t.Errorf("greeting = %q, want 220", greeting)
	}
	conn.Close()

	// Shutdown gracefully.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
}

func TestServer_ServeTLS(t *testing.T) {
	cert, err := generateTestCert()
	if err != nil {
		t.Fatalf("generateTestCert: %v", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	be, db := testBackend(t)
	cfg := testConfig()
	srv := NewServer(cfg, db, be.blob, be.queue, be.auth, nil, be.metrics, tlsCfg)
	if srv.TLSConfig == nil {
		t.Fatal("TLSConfig should be set")
	}

	tlsL, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer tlsL.Close()

	go srv.Serve(tlsL)
	time.Sleep(50 * time.Millisecond)
	defer srv.Shutdown(context.Background())

	addr := tlsL.Addr().String()
	tlsConn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("TLS dial: %v", err)
	}
	defer tlsConn.Close()

	tp := textproto.NewConn(tlsConn)
	_, _, err = tp.ReadResponse(220)
	if err != nil {
		t.Fatalf("expected 220 greeting over TLS: %v", err)
	}
	tp.Close()
}

// ---------------------------------------------------------------------------
// Full integration: SMTP client → server → verify delivery
// ---------------------------------------------------------------------------

func TestSMTPIntegration_LocalDelivery(t *testing.T) {
	be, db := testBackend(t)
	ctx := context.Background()
	cfg := testConfig()
	srv := NewServer(cfg, db, be.blob, be.queue, be.auth, nil, be.metrics, nil)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	// Pre-whitelist the greylist triplet so the test RCPT TO is not rejected.
	if err := storage.RecordAttempt(ctx, db, "127.0.0.1", "sender@example.com", "user@test.local"); err != nil {
		t.Fatalf("greylist record attempt: %v", err)
	}
	if err := storage.MarkPassed(ctx, db, "127.0.0.1", "sender@example.com", "user@test.local"); err != nil {
		t.Fatalf("greylist pre-whitelist: %v", err)
	}

	go srv.Serve(l)
	time.Sleep(50 * time.Millisecond)
	defer srv.Shutdown(context.Background())

	addr := l.Addr().String()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	tp := textproto.NewConn(conn)
	// Read greeting.
	if _, _, err := tp.ReadResponse(220); err != nil {
		t.Fatalf("expected 220 greeting: %v", err)
	}

	// HELO
	if err := tp.PrintfLine("HELO test-client"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tp.ReadResponse(250); err != nil {
		t.Fatalf("HELO: %v", err)
	}

	// MAIL FROM
	if err := tp.PrintfLine("MAIL FROM:<sender@example.com>"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tp.ReadResponse(250); err != nil {
		t.Fatalf("MAIL FROM: %v", err)
	}

	// RCPT TO
	if err := tp.PrintfLine("RCPT TO:<user@test.local>"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tp.ReadResponse(250); err != nil {
		t.Fatalf("RCPT TO: %v", err)
	}

	// DATA
	if err := tp.PrintfLine("DATA"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tp.ReadResponse(354); err != nil {
		t.Fatalf("expected 354 start input: %v", err)
	}

	msgBody := "From: sender@example.com\r\nTo: user@test.local\r\nSubject: Integration Test\r\n\r\nHello from SMTP!"
	if err := tp.PrintfLine("%s", msgBody); err != nil {
		t.Fatal(err)
	}
	if err := tp.PrintfLine("."); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tp.ReadResponse(250); err != nil {
		t.Fatalf("expected 250 message accepted: %v", err)
	}

	tp.Close()

	user, err := storage.GetUserByEmail(ctx, db, "user@test.local")
	if err != nil {
		t.Fatalf("user user@test.local not found: %v", err)
	}
	mbox, err := storage.GetMailbox(ctx, db, user.ID, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := storage.ListMessages(ctx, db, mbox.ID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("INBOX has %d messages, want 1", len(msgs))
	}
	if msgs[0].Subject != "Integration Test" {
		t.Errorf("Subject = %q, want %q", msgs[0].Subject, "Integration Test")
	}
}

func TestSMTPIntegration_RelayRejected(t *testing.T) {
	be, db := testBackend(t)
	cfg := testConfig()
	srv := NewServer(cfg, db, be.blob, be.queue, be.auth, nil, be.metrics, nil)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	go srv.Serve(l)
	time.Sleep(50 * time.Millisecond)
	defer srv.Shutdown(context.Background())

	addr := l.Addr().String()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	tp := textproto.NewConn(conn)

	if _, _, err := tp.ReadResponse(220); err != nil {
		t.Fatalf("expected 220: %v", err)
	}
	if err := tp.PrintfLine("HELO client"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tp.ReadResponse(250); err != nil {
		t.Fatalf("HELO: %v", err)
	}
	if err := tp.PrintfLine("MAIL FROM:<me@test.local>"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tp.ReadResponse(250); err != nil {
		t.Fatalf("MAIL FROM: %v", err)
	}
	if err := tp.PrintfLine("RCPT TO:<victim@external.com>"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tp.ReadResponse(550); err != nil {
		t.Fatalf("expected 550 relay rejected: %v", err)
	}
	tp.Close()
}

func TestSMTPIntegration_EHLO(t *testing.T) {
	be, db := testBackend(t)
	cfg := testConfig()
	srv := NewServer(cfg, db, be.blob, be.queue, be.auth, nil, be.metrics, nil)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	go srv.Serve(l)
	time.Sleep(50 * time.Millisecond)
	defer srv.Shutdown(context.Background())

	addr := l.Addr().String()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	tp := textproto.NewConn(conn)

	if _, _, err := tp.ReadResponse(220); err != nil {
		t.Fatalf("expected 220: %v", err)
	}
	if err := tp.PrintfLine("EHLO test-client"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tp.ReadResponse(250); err != nil {
		t.Fatalf("EHLO: %v", err)
	}
	tp.Close()
}

func TestSMTPIntegration_InvalidMailFrom(t *testing.T) {
	be, db := testBackend(t)
	cfg := testConfig()
	srv := NewServer(cfg, db, be.blob, be.queue, be.auth, nil, be.metrics, nil)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	go srv.Serve(l)
	time.Sleep(50 * time.Millisecond)
	defer srv.Shutdown(context.Background())

	addr := l.Addr().String()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	tp := textproto.NewConn(conn)

	if _, _, err := tp.ReadResponse(220); err != nil {
		t.Fatalf("expected 220: %v", err)
	}
	if err := tp.PrintfLine("HELO client"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tp.ReadResponse(250); err != nil {
		t.Fatalf("HELO: %v", err)
	}
	// MAIL FROM with invalid syntax is rejected by go-smtp's parser with 501.
	if err := tp.PrintfLine("MAIL FROM:<bogus>"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tp.ReadResponse(501); err != nil {
		t.Fatalf("expected 501 for invalid MAIL FROM: %v", err)
	}
	tp.Close()
}

func TestSMTPIntegration_Quit(t *testing.T) {
	be, db := testBackend(t)
	cfg := testConfig()
	srv := NewServer(cfg, db, be.blob, be.queue, be.auth, nil, be.metrics, nil)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	go srv.Serve(l)
	time.Sleep(50 * time.Millisecond)
	defer srv.Shutdown(context.Background())

	addr := l.Addr().String()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	tp := textproto.NewConn(conn)

	if _, _, err := tp.ReadResponse(220); err != nil {
		t.Fatalf("expected 220: %v", err)
	}
	if err := tp.PrintfLine("QUIT"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tp.ReadResponse(221); err != nil {
		t.Fatalf("expected 221 bye: %v", err)
	}
	tp.Close()
}

// ---------------------------------------------------------------------------
// Greylist
// ---------------------------------------------------------------------------

func TestGreylist_StorageFunctions(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	ip := "10.0.0.1"
	from := "sender@external.com"
	to := "user@test.local"

	// Initially not whitelisted.
	whitelisted, err := storage.IsWhitelisted(ctx, db, ip, from, to)
	if err != nil {
		t.Fatalf("IsWhitelisted (initial): %v", err)
	}
	if whitelisted {
		t.Fatal("expected not whitelisted initially")
	}

	// Record first attempt.
	if err := storage.RecordAttempt(ctx, db, ip, from, to); err != nil {
		t.Fatalf("RecordAttempt: %v", err)
	}

	// Still not whitelisted (time hasn't passed).
	whitelisted, err = storage.IsWhitelisted(ctx, db, ip, from, to)
	if err != nil {
		t.Fatalf("IsWhitelisted (after record): %v", err)
	}
	if whitelisted {
		t.Fatal("expected not whitelisted after record (passed=0)")
	}

	// Record another attempt (upsert should succeed).
	if err := storage.RecordAttempt(ctx, db, ip, from, to); err != nil {
		t.Fatalf("RecordAttempt (second): %v", err)
	}

	// Mark as passed.
	if err := storage.MarkPassed(ctx, db, ip, from, to); err != nil {
		t.Fatalf("MarkPassed: %v", err)
	}

	// Now should be whitelisted.
	whitelisted, err = storage.IsWhitelisted(ctx, db, ip, from, to)
	if err != nil {
		t.Fatalf("IsWhitelisted (after mark): %v", err)
	}
	if !whitelisted {
		t.Fatal("expected whitelisted after MarkPassed")
	}

	// Different triplet should not be whitelisted.
	whitelisted, err = storage.IsWhitelisted(ctx, db, ip, from, "other@test.local")
	if err != nil {
		t.Fatalf("IsWhitelisted (different to): %v", err)
	}
	if whitelisted {
		t.Fatal("expected different triplet not whitelisted")
	}

	// Non-existent triplet.
	whitelisted, err = storage.IsWhitelisted(ctx, db, "9.9.9.9", "nobody@example.com", "missing@test.local")
	if err != nil {
		t.Fatalf("IsWhitelisted (non-existent): %v", err)
	}
	if whitelisted {
		t.Fatal("expected non-existent triplet not whitelisted")
	}
}


func TestGreylist_Rcpt(t *testing.T) {
	be, db := testBackend(t)
	ctx := context.Background()

	// Test 1: Session with nil conn skips greylisting (no error from Rcpt path).
	s := &Session{
		backend: be,
		from:    "sender@external.com",
	}
	// Rcpt should succeed (conn is nil → greylist skipped).
	if err := s.Rcpt("user@test.local", nil); err != nil {
		t.Fatalf("expected Rcpt to succeed with nil conn, got: %v", err)
	}

	// Test 2: Pre-whitelist a triplet directly, then verify Rcpt succeeds (storage check).
	// This simulates what happens after the greylist delay has passed.
	if err := storage.RecordAttempt(ctx, db, "10.0.0.1", "sender@external.com", "user@test.local"); err != nil {
		t.Fatalf("RecordAttempt: %v", err)
	}
	if err := storage.MarkPassed(ctx, db, "10.0.0.1", "sender@external.com", "user@test.local"); err != nil {
		t.Fatalf("MarkPassed: %v", err)
	}
	whitelisted, err := storage.IsWhitelisted(ctx, db, "10.0.0.1", "sender@external.com", "user@test.local")
	if err != nil {
		t.Fatalf("IsWhitelisted: %v", err)
	}
	if !whitelisted {
		t.Fatal("expected triplet to be whitelisted")
	}

	// Test 3: Non-whitelisted triplet.
	whitelisted, err = storage.IsWhitelisted(ctx, db, "10.0.0.2", "attacker@evil.com", "victim@test.local")
	if err != nil {
		t.Fatalf("IsWhitelisted: %v", err)
	}
	if whitelisted {
		t.Fatal("expected unrecorded triplet not whitelisted")
	}

	// Test 4: Authenticated session should skip greylisting.
	s2 := &Session{
		backend: be,
		from:    "sender@external.com",
		authed:  true,
	}
	if err := s2.Rcpt("user@test.local", nil); err != nil {
		t.Fatalf("expected authenticated Rcpt to succeed, got: %v", err)
	}
}
