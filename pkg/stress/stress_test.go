package stress

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/i-got-this-faa/marco/pkg/auth"
	"github.com/i-got-this-faa/marco/pkg/blobstore"
	"github.com/i-got-this-faa/marco/pkg/config"
	"github.com/i-got-this-faa/marco/pkg/metrics"
	"github.com/i-got-this-faa/marco/pkg/queue"
	"github.com/i-got-this-faa/marco/pkg/smtp"
	"github.com/i-got-this-faa/marco/pkg/storage"
	_ "modernc.org/sqlite"
)

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		t.Fatalf("PRAGMA foreign_keys = ON: %v", err)
	}
	if err := storage.Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return db
}

func setupUsers(t *testing.T, db *sql.DB, count int) []string {
	t.Helper()
	ctx := context.Background()
	emails := make([]string, count)
	mgr := auth.NewManager(db)
	for i := range count {
		email := fmt.Sprintf("stress-user-%d@test.local", i)
		_, err := mgr.CreateUser(ctx, email, fmt.Sprintf("password-%d", i))
		if err != nil {
			t.Fatalf("CreateUser %d: %v", i, err)
		}
		emails[i] = email
	}
	return emails
}

func startSMTPServer(t *testing.T, db *sql.DB) string {
	t.Helper()
	blob := blobstore.NewSQLiteStore(db)
	met := metrics.NewRegistry()
	qm := queue.NewManager(db, blob, 1, 3, time.Second, "")
	am := auth.NewManager(db)

	cfg := &config.SMTPConfig{
		Hostname:       "test.local",
		ListenAddr:     "127.0.0.1:0",
		MaxMessageSize: 25 * 1024 * 1024,
		MaxRecipients:  100,
	}

	srv := smtp.NewServer(cfg, db, blob, qm, am, nil, met, (*tls.Config)(nil))
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	go srv.Serve(l)
	time.Sleep(50 * time.Millisecond)
	t.Cleanup(func() {
		srv.Shutdown(context.Background())
		l.Close()
	})

	return l.Addr().String()
}

func TestConcurrentSMTPConnections(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	setupUsers(t, db, 5)

	mgr := auth.NewManager(db)
	_, err := mgr.CreateUser(ctx, "stress-sender@test.local", "sender-password-ok")
	if err != nil {
		t.Fatalf("CreateUser sender: %v", err)
	}

	addr := startSMTPServer(t, db)

	const numConns = 10
	var wg sync.WaitGroup
	errs := make(chan error, numConns)

	for i := 0; i < numConns; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				errs <- fmt.Errorf("conn %d: dial: %w", id, err)
				return
			}
			defer conn.Close()

			tp := textproto.NewConn(conn)
			if _, _, err := tp.ReadResponse(220); err != nil {
				errs <- fmt.Errorf("conn %d: greeting: %w", id, err)
				return
			}
			if err := tp.PrintfLine("HELO client-%d", id); err != nil {
				errs <- fmt.Errorf("conn %d: HELO: %w", id, err)
				return
			}
			if _, _, err := tp.ReadResponse(250); err != nil {
				errs <- fmt.Errorf("conn %d: HELO response: %w", id, err)
				return
			}
			if err := tp.PrintfLine("MAIL FROM:<sender@test.local>"); err != nil {
				errs <- fmt.Errorf("conn %d: MAIL FROM: %w", id, err)
				return
			}
			if _, _, err := tp.ReadResponse(250); err != nil {
				errs <- fmt.Errorf("conn %d: MAIL FROM response: %w", id, err)
				return
			}
			if err := tp.PrintfLine("RCPT TO:<stress-user-0@test.local>"); err != nil {
				errs <- fmt.Errorf("conn %d: RCPT TO: %w", id, err)
				return
			}
			if _, _, err := tp.ReadResponse(250); err != nil {
				errs <- fmt.Errorf("conn %d: RCPT TO response: %w", id, err)
				return
			}
			if err := tp.PrintfLine("DATA"); err != nil {
				errs <- fmt.Errorf("conn %d: DATA: %w", id, err)
				return
			}
			if _, _, err := tp.ReadResponse(354); err != nil {
				errs <- fmt.Errorf("conn %d: DATA start: %w", id, err)
				return
			}
			tp.PrintfLine("From: sender@test.local")
			tp.PrintfLine("To: stress-user-0@test.local")
			tp.PrintfLine("Subject: Stress %d", id)
			tp.PrintfLine("")
			tp.PrintfLine("Hello from concurrent stress test %d!", id)
			tp.PrintfLine(".")
			if _, _, err := tp.ReadResponse(250); err != nil {
				errs <- fmt.Errorf("conn %d: data complete: %w", id, err)
				return
			}
			tp.Close()
		}(i)
	}

	wg.Wait()
	close(errs)

	var failures []string
	for err := range errs {
		failures = append(failures, err.Error())
	}
	if len(failures) > 0 {
		t.Errorf("%d/%d connections failed: %s", len(failures), numConns, strings.Join(failures, "; "))
	} else {
		t.Logf("All %d concurrent SMTP connections succeeded", numConns)
	}

	user, err := storage.GetUserByEmail(ctx, db, "stress-user-0@test.local")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	inbox, err := storage.GetMailbox(ctx, db, user.ID, "INBOX")
	if err != nil {
		t.Fatalf("GetMailbox: %v", err)
	}
	msgs, err := storage.ListMessages(ctx, db, inbox.ID, 100, 0)
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}
	if len(msgs) == 0 {
		t.Error("no messages delivered to stress-user-0 INBOX")
	} else {
		t.Logf("%d messages delivered to stress-user-0 inbox", len(msgs))
	}
}

func TestConcurrentQueueOperations(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()

	mgr := auth.NewManager(db)
	userID, err := mgr.CreateUser(ctx, "queue-user@test.local", "queue-password-ok")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	mbox, err := storage.GetMailbox(ctx, db, userID, "INBOX")
	if err != nil {
		t.Fatalf("GetMailbox: %v", err)
	}
	msgID, _, err := storage.InsertMessage(ctx, db, mbox.ID, "blob-key", 100, "f@e.com", "t@e.com", "Subject", 0)
	if err != nil {
		t.Fatalf("InsertMessage: %v", err)
	}

	const numOps = 50
	var enqueueWg sync.WaitGroup
	for i := 0; i < numOps; i++ {
		enqueueWg.Add(1)
		go func(id int) {
			defer enqueueWg.Done()
			storage.Enqueue(ctx, db, msgID, fmt.Sprintf("rcpt-%d@other.com", id))
		}(i)
	}
	enqueueWg.Wait()

	count, err := storage.QueueSize(ctx, db)
	if err != nil {
		t.Fatalf("QueueSize: %v", err)
	}
	if count != numOps {
		t.Errorf("expected %d queue items, got %d", numOps, count)
	}

	// Worker pool claiming items concurrently until queue is drained.
	var claimMu sync.Mutex
	var totalClaimed int
	var claimWg sync.WaitGroup
	for w := 0; w < 5; w++ {
		claimWg.Add(1)
		go func() {
			defer claimWg.Done()
			for {
				claimMu.Lock()
				remaining, _ := storage.QueueSize(ctx, db)
				claimMu.Unlock()
				if remaining == 0 {
					return
				}
				item, err := storage.ClaimNext(ctx, db)
				if err != nil {
					return
				}
				if item == nil {
					time.Sleep(1 * time.Millisecond)
					continue
				}
				if err := storage.Complete(ctx, db, item.ID); err == nil {
					claimMu.Lock()
					totalClaimed++
					claimMu.Unlock()
				}
			}
		}()
	}
	claimWg.Wait()

	if totalClaimed != numOps {
		t.Errorf("claimed %d/%d items", totalClaimed, numOps)
	}

	count, _ = storage.QueueSize(ctx, db)
	if count != 0 {
		t.Errorf("expected empty queue, got %d items", count)
	}
}

func TestLargeMessageDelivery(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	users := setupUsers(t, db, 3)
	mgr := auth.NewManager(db)
	_, err := mgr.CreateUser(ctx, "big-sender@test.local", "big-sender-pass")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	addr := startSMTPServer(t, db)

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	tp := textproto.NewConn(conn)
	tp.ReadResponse(220)
	tp.PrintfLine("HELO big-sender")
	tp.ReadResponse(250)
	tp.PrintfLine("MAIL FROM:<big-sender@test.local>")
	tp.ReadResponse(250)
	tp.PrintfLine("RCPT TO:<%s>", users[0])
	tp.ReadResponse(250)
	tp.PrintfLine("DATA")
	tp.ReadResponse(354)

	tp.PrintfLine("From: sender@example.com")
	tp.PrintfLine("To: %s", users[0])
	tp.PrintfLine("Subject: Large")
	tp.PrintfLine("")
	chunk := strings.Repeat("Hello World! ", 1000)
	for i := 0; i < 100; i++ {
		tp.PrintfLine("%s", chunk[:min(len(chunk), 1000)])
	}
	tp.PrintfLine(".")
	resp, msg, _ := tp.ReadResponse(250)
	if resp != 250 {
		t.Logf("large message response: %d %s", resp, msg)
	}
	tp.Close()

	u, err := storage.GetUserByEmail(ctx, db, users[0])
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	inbox, err := storage.GetMailbox(ctx, db, u.ID, "INBOX")
	if err != nil {
		t.Fatalf("GetMailbox: %v", err)
	}
	msgs, _ := storage.ListMessages(ctx, db, inbox.ID, 10, 0)

	found := false
	for _, m := range msgs {
		if m.FromAddr == "sender@example.com" || m.Subject == "Large" {
			found = true
			if m.Size < 100000 {
				t.Errorf("message size = %d, expected > 100000", m.Size)
			}
		}
	}
	if !found {
		t.Error("large message not delivered")
	}
}
