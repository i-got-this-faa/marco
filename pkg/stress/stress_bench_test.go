package stress

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net"
	"net/textproto"
	"runtime"
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

// ---------------------------------------------------------------------------
// Stress benchmarks — run with:
//   go test ./pkg/stress/... -bench=. -benchmem -benchtime=1x -timeout=600s
// ---------------------------------------------------------------------------

// makeDB creates a fresh in-memory SQLite DB with the schema migrated.
func makeDB(b *testing.B) *sql.DB {
	b.Helper()
	db, err := sql.Open("sqlite", "file::memory:?cache=shared")
	if err != nil {
		b.Fatalf("sql.Open: %v", err)
	}
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		b.Fatalf("PRAGMA foreign_keys = ON: %v", err)
	}
	if err := storage.Migrate(db); err != nil {
		b.Fatalf("Migrate: %v", err)
	}
	b.Cleanup(func() { db.Close() })
	return db
}

// makeUsers creates N users in the given DB and returns their emails.
func makeUsers(b *testing.B, ctx context.Context, db *sql.DB, n int) []string {
	b.Helper()
	mgr := auth.NewManager(db)
	emails := make([]string, n)
	for i := 0; i < n; i++ {
		email := fmt.Sprintf("user-%d@test.local", i)
		if _, err := mgr.CreateUser(ctx, email, fmt.Sprintf("password-%d", i), false); err != nil {
			b.Fatalf("CreateUser %d: %v", i, err)
		}
		emails[i] = email
	}
	return emails
}

// makeSender creates one dedicated sender user.
func makeSender(b *testing.B, ctx context.Context, db *sql.DB) string {
	b.Helper()
	mgr := auth.NewManager(db)
	if _, err := mgr.CreateUser(ctx, "bench-sender@test.local", "sender-password-ok", false); err != nil {
		b.Fatalf("CreateUser sender: %v", err)
	}
	return "bench-sender@test.local"
}

// makeRefMessage inserts a reference message for queue tests and returns its ID.
func makeRefMessage(b *testing.B, ctx context.Context, db *sql.DB, userEmail string) int64 {
	b.Helper()
	u, err := storage.GetUserByEmail(ctx, db, userEmail)
	if err != nil {
		b.Fatalf("GetUserByEmail: %v", err)
	}
	mbox, err := storage.GetMailbox(ctx, db, u.ID, "INBOX")
	if err != nil {
		b.Fatalf("GetMailbox: %v", err)
	}
	id, _, err := storage.InsertMessage(ctx, db, mbox.ID, "ref-blob", 512*1024, "f@e.com", "t@e.com", "Ref", 0)
	if err != nil {
		b.Fatalf("InsertMessage: %v", err)
	}
	return id
}

// makeServer starts an SMTP server on a fresh listener, returning addr + stop.
func makeServer(b *testing.B, db *sql.DB) (addr string, stop func()) {
	b.Helper()
	blob := blobstore.NewSQLiteStore(db)
	met := metrics.NewRegistry()
	qm := queue.NewManager(db, blob, 1, 3, time.Second, "", queue.RelayConfig{})
	am := auth.NewManager(db)

	cfg := &config.SMTPConfig{
		Hostname:       "test.local",
		ListenAddr:     "127.0.0.1:0",
		MaxMessageSize: 10 * 1024 * 1024,
		MaxRecipients:  1000,
	}

	be := smtp.NewBackend(cfg, db, blob, qm, am, nil, met)
	srv := smtp.NewServer(be, (*tls.Config)(nil))
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("Listen: %v", err)
	}
	addr = l.Addr().String()

	done := make(chan struct{})
	go func() {
		srv.Serve(l)
		srv.Shutdown(context.Background())
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)

	return addr, func() { l.Close(); <-done }
}

// smtpSendMsgWithRetry sends one message, retrying "connection refused" 5x.
func smtpSendMsgWithRetry(addr, from, to, subject, body string) error {
	var lastErr error
	for retry := 0; retry < 5; retry++ {
		err := smtpSendMsg(addr, from, to, subject, body)
		if err == nil {
			return nil
		}
		lastErr = err
		if strings.Contains(err.Error(), "connection refused") {
			time.Sleep(time.Duration(50*(retry+1)) * time.Millisecond)
			continue
		}
		return err
	}
	return fmt.Errorf("gave up after 5 retries: %w", lastErr)
}

func smtpSendMsg(addr, from, to, subject, body string) error {
	conn, err := net.DialTimeout("tcp", addr, 30*time.Second)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	tp := textproto.NewConn(conn)
	if _, _, err := tp.ReadResponse(220); err != nil {
		return fmt.Errorf("greeting: %w", err)
	}
	tp.PrintfLine("HELO stress")
	tp.ReadResponse(250)
	tp.PrintfLine("MAIL FROM:<%s>", from)
	tp.ReadResponse(250)
	tp.PrintfLine("RCPT TO:<%s>", to)
	tp.ReadResponse(250)
	tp.PrintfLine("DATA")
	tp.ReadResponse(354)

	tp.PrintfLine("From: %s", from)
	tp.PrintfLine("To: %s", to)
	tp.PrintfLine("Subject: %s", subject)
	tp.PrintfLine("")
	for i := 0; i < len(body); i += 900 {
		end := i + 900
		if end > len(body) {
			end = len(body)
		}
		tp.PrintfLine("%s", body[i:end])
	}
	tp.PrintfLine(".")
	resp, msg, err := tp.ReadResponse(250)
	if err != nil || resp != 250 {
		return fmt.Errorf("data: %d %s: %w", resp, msg, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Benchmark 1: 1000 concurrent SMTP connections, 512 KB each
// ---------------------------------------------------------------------------

func BenchmarkConcurrentSMTP(b *testing.B) {
	const msgSize = 512 * 1024
	const totalConns = 1000
	const maxInFlight = 100
	body := strings.Repeat("A", msgSize)

	for i := 0; i < b.N; i++ {
		db := makeDB(b)
		ctx := context.Background()
		users := makeUsers(b, ctx, db, 5)
		sender := makeSender(b, ctx, db)

		addr, stop := makeServer(b, db)

		sem := make(chan struct{}, maxInFlight)
		var wg sync.WaitGroup
		errCh := make(chan error, totalConns)
		start := time.Now()
		b.SetBytes(int64(totalConns) * int64(msgSize))

		for j := 0; j < totalConns; j++ {
			sem <- struct{}{}
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				defer func() { <-sem }()
				to := users[id%len(users)]
				subject := fmt.Sprintf("Conc-%d-%d", i, id)
				if err := smtpSendMsgWithRetry(addr, sender, to, subject, body); err != nil {
					errCh <- fmt.Errorf("conn %d: %w", id, err)
				}
			}(j)
		}
		wg.Wait()
		close(errCh)
		elapsed := time.Since(start)

		var failures []string
		for err := range errCh {
			failures = append(failures, err.Error())
		}

		b.ReportMetric(float64(totalConns)/elapsed.Seconds(), "conns/sec")
		totalMB := float64(totalConns*msgSize) / (1024 * 1024)
		b.ReportMetric(totalMB/elapsed.Seconds(), "MB/sec")
		b.ReportMetric(float64(len(failures)), "failures")

		if len(failures) > 0 {
			b.Errorf("%d/%d failed", len(failures), totalConns)
		} else {
			b.Logf("✓ %d conns in %v (%.0f conns/sec, %.1f MB/sec, %d failures)",
				totalConns, elapsed, float64(totalConns)/elapsed.Seconds(), totalMB/elapsed.Seconds(), len(failures))
		}

		stop()

		// Verify delivery.
		var total int
		for _, email := range users {
			u, _ := storage.GetUserByEmail(ctx, db, email)
			if u == nil {
				continue
			}
			mbox, _ := storage.GetMailbox(ctx, db, u.ID, "INBOX")
			if mbox == nil {
				continue
			}
			msgs, _ := storage.ListMessages(ctx, db, mbox.ID, 100000, 0)
			total += len(msgs)
		}
		b.Logf("Delivered: %d msgs", total)
	}
}

// ---------------------------------------------------------------------------
// Benchmark 2: 5000 queue ops (enqueue + claim + complete)
// ---------------------------------------------------------------------------

func BenchmarkQueueOps(b *testing.B) {
	ctx := context.Background()
	const batchSize = 5000

	for i := 0; i < b.N; i++ {
		db := makeDB(b)
		users := makeUsers(b, ctx, db, 1)
		msgID := makeRefMessage(b, ctx, db, users[0])

		// Enqueue.
		start := time.Now()
		var enqWg sync.WaitGroup
		for j := 0; j < batchSize; j++ {
			enqWg.Add(1)
			go func(id int) {
				defer enqWg.Done()
				storage.Enqueue(ctx, db, msgID, fmt.Sprintf("rcpt-%d@other.com", id))
			}(j)
		}
		enqWg.Wait()
		enqTime := time.Since(start)
		b.ReportMetric(float64(batchSize)/enqTime.Seconds(), "enqueue/sec")

		// Verify count.
		count, _ := storage.QueueSize(ctx, db)
		b.Logf("Queue size after enqueue: %d", count)

		// Claim + complete with 20 workers.
		claimStart := time.Now()
		var claimMu sync.Mutex
		var totalClaimed int
		var claimWg sync.WaitGroup

		for w := 0; w < 20; w++ {
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
		claimTime := time.Since(claimStart)

		b.SetBytes(int64(batchSize))
		b.ReportMetric(float64(batchSize)/claimTime.Seconds(), "claim+complete/sec")
		b.ReportMetric(float64(totalClaimed), "claimed_items")

		if totalClaimed != batchSize {
			b.Errorf("claimed %d/%d items", totalClaimed, batchSize)
		} else {
			b.Logf("✓ %d queue ops: enq %v (%d/s) claim+complete %v (%d/s)",
				batchSize, enqTime, int(float64(batchSize)/enqTime.Seconds()),
				claimTime, int(float64(batchSize)/claimTime.Seconds()))
		}
	}
}

// ---------------------------------------------------------------------------
// Benchmark 3: 512 KB message throughput (single-stream)
// ---------------------------------------------------------------------------

func BenchmarkLargeMessage(b *testing.B) {
	body := strings.Repeat("Hello World! ", 512*1024/13)
	bodySize := len(body)
	b.SetBytes(int64(bodySize))

	db := makeDB(b)
	ctx := context.Background()
	users := makeUsers(b, ctx, db, 5)
	sender := makeSender(b, ctx, db)
	addr, stop := makeServer(b, db)
	defer stop()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		to := users[i%len(users)]
		subject := fmt.Sprintf("Large-%d", i)
		start := time.Now()

		err := smtpSendMsgWithRetry(addr, sender, to, subject, body)
		elapsed := time.Since(start)

		if err != nil {
			b.Fatalf("send %d failed: %v", i, err)
		}
		b.ReportMetric(float64(bodySize)/1024/1024/elapsed.Seconds(), "MB/sec")
	}
}

// ---------------------------------------------------------------------------
// Benchmark 4: Memory/goroutine/GC profile during sustained SMTP load
// ---------------------------------------------------------------------------

func BenchmarkResourceProfile(b *testing.B) {
	db := makeDB(b)
	ctx := context.Background()
	users := makeUsers(b, ctx, db, 5)
	sender := makeSender(b, ctx, db)
	addr, stop := makeServer(b, db)
	defer stop()

	runtime.GC()
	runtime.GC()
	var m0 runtime.MemStats
	runtime.ReadMemStats(&m0)
	g0 := runtime.NumGoroutine()

	const msgs = 100
	const concurrency = 50
	body := strings.Repeat("B", 1500)

	b.ResetTimer()

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	errCh := make(chan error, msgs)

	for i := 0; i < msgs; i++ {
		sem <- struct{}{}
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			defer func() { <-sem }()
			to := users[id%len(users)]
			subject := fmt.Sprintf("Profile-%d", id)
			if err := smtpSendMsgWithRetry(addr, sender, to, subject, body); err != nil {
				errCh <- err
			}
		}(i)
	}
	wg.Wait()
	close(errCh)

	var failures []string
	for err := range errCh {
		failures = append(failures, err.Error())
	}

	runtime.GC()
	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)
	g1 := runtime.NumGoroutine()

	b.StopTimer()
	b.ReportMetric(float64(g1-g0), "extra_goroutines")
	b.ReportMetric(float64(m1.TotalAlloc-m0.TotalAlloc)/1024/1024, "alloc_MB")
	b.ReportMetric(float64(m1.Mallocs-m0.Mallocs)/float64(msgs), "mallocs/msg")
	b.ReportMetric(float64(m1.NumGC-m0.NumGC), "gc_cycles")

	if len(failures) > 0 {
		b.Errorf("%d failures: %s", len(failures), failures[0])
	} else {
		b.Logf("✓ %d msgs: +%d goroutines, +%.1f MB alloc, +%d GC, %.0f mallocs/msg",
			msgs, g1-g0, float64(m1.TotalAlloc-m0.TotalAlloc)/1024/1024,
			m1.NumGC-m0.NumGC, float64(m1.Mallocs-m0.Mallocs)/float64(msgs))
	}
}
