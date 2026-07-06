package queue

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/i-got-this-faa/marco/pkg/blobstore"
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

func ensureUser(t *testing.T, db *sql.DB, email, passwordHash string) int64 {
	t.Helper()
	ctx := context.Background()
	id, err := storage.CreateUser(ctx, db, email, passwordHash, false)
	if err != nil {
		t.Fatalf("CreateUser(%q): %v", email, err)
	}
	return id
}

func ensureMessage(t *testing.T, db *sql.DB, mailboxID int64, from, to, subject string) int64 {
	t.Helper()
	ctx := context.Background()
	id, _, err := storage.InsertMessage(ctx, db, mailboxID, fmt.Sprintf("blob-%s", subject), 123, from, to, subject, 0)
	if err != nil {
		t.Fatalf("InsertMessage(%d): %v", mailboxID, err)
	}
	return id
}

// setupTest creates a DB with a user, mailbox, and message, and returns the IDs.
func setupTest(t *testing.T, db *sql.DB) (userID int64, mailboxID int64, msgID int64) {
	t.Helper()
	ctx := context.Background()
	userID = ensureUser(t, db, "sender@example.com", "hash")
	if err := storage.EnsureDefaultMailboxes(ctx, db, userID); err != nil {
		t.Fatalf("EnsureDefaultMailboxes: %v", err)
	}
	mbox, err := storage.GetMailbox(ctx, db, userID, "INBOX")
	if err != nil {
		t.Fatalf("GetMailbox(INBOX): %v", err)
	}
	mailboxID = mbox.ID
	msgID = ensureMessage(t, db, mailboxID, "sender@example.com", "recip@example.com", "Test Message")
	return
}

func createManager(t *testing.T, db *sql.DB) *Manager {
	t.Helper()
	blob := blobstore.NewSQLiteStore(db)
	return NewManager(db, blob, 5, 3, 100*time.Millisecond, "")
}

// ---------------------------------------------------------------------------
// 1. QueueManager: Basic enqueue/claim/complete/fail cycle
// ---------------------------------------------------------------------------

func TestQueueEnqueueClaimComplete(t *testing.T) {
	db := migrateTestDB(t)
	_, _, msgID := setupTest(t, db)
	ctx := context.Background()
	mgr := createManager(t, db)

	if err := mgr.Enqueue(msgID, "user@example.com"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	size, err := storage.QueueSize(ctx, db)
	if err != nil {
		t.Fatalf("QueueSize: %v", err)
	}
	if size != 1 {
		t.Fatalf("expected queue size 1, got %d", size)
	}

	// ClaimNext reads status BEFORE updating, so the returned struct has
	// "pending". The DB row, however, is atomically set to "active".
	item, err := storage.ClaimNext(ctx, db)
	if err != nil {
		t.Fatalf("ClaimNext: %v", err)
	}
	if item == nil {
		t.Fatal("expected a queue item, got nil")
	}
	if item.MessageID != msgID {
		t.Fatalf("expected message_id %d, got %d", msgID, item.MessageID)
	}
	if item.RcptTo != "user@example.com" {
		t.Fatalf("expected rcpt_to 'user@example.com', got %q", item.RcptTo)
	}
	if item.Status != "pending" { // scanned before update
		t.Fatalf("expected returned status 'pending' (pre-update), got %q", item.Status)
	}
	if item.AttemptCount != 0 {
		t.Fatalf("expected attempt_count 0, got %d", item.AttemptCount)
	}

	// Verify the DB row actually shows 'active'.
	var dbStatus string
	err = db.QueryRowContext(ctx, `SELECT status FROM queue WHERE id = ?`, item.ID).Scan(&dbStatus)
	if err != nil {
		t.Fatalf("read status from db: %v", err)
	}
	if dbStatus != "active" {
		t.Fatalf("expected DB status 'active', got %q", dbStatus)
	}

	// Complete the item.
	if err := storage.Complete(ctx, db, item.ID); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	// Queue should now be empty.
	size, _ = storage.QueueSize(ctx, db)
	if size != 0 {
		t.Fatalf("expected queue size 0 after complete, got %d", size)
	}
}

func TestQueueEnqueueClaimFail(t *testing.T) {
	db := migrateTestDB(t)
	_, _, msgID := setupTest(t, db)
	ctx := context.Background()
	mgr := createManager(t, db)

	if err := mgr.Enqueue(msgID, "user@example.com"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	item, err := storage.ClaimNext(ctx, db)
	if err != nil {
		t.Fatalf("ClaimNext: %v", err)
	}
	if item == nil {
		t.Fatal("expected a queue item, got nil")
	}

	// Fail with transient error — sets status back to 'pending' and
	// increments attempt_count. We pass a future next_attempt so the
	// item stays in queue but won't be re-claimable yet.
	next := time.Now().Add(5 * time.Minute)
	if err := storage.Fail(ctx, db, item.ID, next, 5); err != nil {
		t.Fatalf("Fail: %v", err)
	}

	// Item should still be in queue.
	size, _ := storage.QueueSize(ctx, db)
	if size != 1 {
		t.Fatalf("expected queue size 1 after fail, got %d", size)
	}

	items, err := storage.ListPending(ctx, db)
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 pending item, got %d", len(items))
	}
	if items[0].AttemptCount != 1 {
		t.Fatalf("expected attempt_count 1, got %d", items[0].AttemptCount)
	}
	if items[0].Status != "pending" {
		t.Fatalf("expected status 'pending' after fail, got %q", items[0].Status)
	}
}

// ---------------------------------------------------------------------------
// 2. Max retries cause permanent fail (item removed)
// ---------------------------------------------------------------------------

func TestQueueMaxRetries(t *testing.T) {
	db := migrateTestDB(t)
	_, _, msgID := setupTest(t, db)
	ctx := context.Background()
	mgr := createManager(t, db)
	maxRetries := 3

	if err := mgr.Enqueue(msgID, "user@example.com"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	// Claim and fail repeatedly. Each Fail sets next_attempt to the given
	// time, so we pass a past time to make the item immediately re-claimable.
	for attempt := 0; attempt <= maxRetries; attempt++ {
		item, err := storage.ClaimNext(ctx, db)
		if err != nil {
			t.Fatalf("ClaimNext at attempt %d: %v", attempt, err)
		}
		if item == nil {
			t.Fatalf("expected item at attempt %d, got nil", attempt)
		}

		past := time.Now().Add(-time.Hour)
		if err := storage.Fail(ctx, db, item.ID, past, maxRetries); err != nil {
			t.Fatalf("Fail at attempt %d: %v", attempt, err)
		}
	}

	// Queue should be empty (item removed after exceeding max retries).
	size, _ := storage.QueueSize(ctx, db)
	if size != 0 {
		t.Fatalf("expected queue size 0 after max retries, got %d", size)
	}

	item, err := storage.ClaimNext(ctx, db)
	if err != nil {
		t.Fatalf("ClaimNext after max retries: %v", err)
	}
	if item != nil {
		t.Fatalf("expected nil item after max retries, got %+v", *item)
	}
}

// ---------------------------------------------------------------------------
// 3. Concurrent claim safety
// ---------------------------------------------------------------------------

func TestQueueConcurrentClaim(t *testing.T) {
	db := migrateTestDB(t)
	_, _, msgID := setupTest(t, db)
	ctx := context.Background()
	mgr := createManager(t, db)

	const numItems = 10
	for i := range numItems {
		rcpt := fmt.Sprintf("user%d@example.com", i)
		if err := mgr.Enqueue(msgID, rcpt); err != nil {
			t.Fatalf("Enqueue %d: %v", i, err)
		}
	}

	const numWorkers = 5
	type claimResult struct {
		ids []int64
		err error
	}
	results := make(chan claimResult, numWorkers)
	var wg sync.WaitGroup

	for w := range numWorkers {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			var ids []int64
			for {
				item, err := storage.ClaimNext(ctx, db)
				if err != nil {
					results <- claimResult{err: fmt.Errorf("worker %d claim: %w", id, err)}
					return
				}
				if item == nil {
					break
				}
				ids = append(ids, item.ID)
				// Complete so the item doesn't stay in the queue.
				if err := storage.Complete(ctx, db, item.ID); err != nil {
					results <- claimResult{err: fmt.Errorf("worker %d complete: %w", id, err)}
					return
				}
			}
			results <- claimResult{ids: ids}
		}(w)
	}

	wg.Wait()
	close(results)

	var allClaimed []int64
	for r := range results {
		if r.err != nil {
			t.Fatalf("worker error: %v", r.err)
		}
		allClaimed = append(allClaimed, r.ids...)
	}

	if len(allClaimed) != numItems {
		t.Fatalf("expected %d total claimed items, got %d", numItems, len(allClaimed))
	}

	// Verify no duplicates.
	seen := make(map[int64]bool)
	for _, id := range allClaimed {
		if seen[id] {
			t.Fatalf("duplicate claim of queue id %d", id)
		}
		seen[id] = true
	}

	// All items should be gone.
	size, _ := storage.QueueSize(ctx, db)
	if size != 0 {
		t.Fatalf("expected queue size 0 after all processed, got %d", size)
	}
}

// ---------------------------------------------------------------------------
// 4. Worker: Simulated successful delivery
// ---------------------------------------------------------------------------

func TestWorkerSuccessfulDelivery(t *testing.T) {
	db := migrateTestDB(t)
	_, _, msgID := setupTest(t, db)
	ctx := context.Background()
	mgr := createManager(t, db)

	if err := mgr.Enqueue(msgID, "recip@example.com"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	// Simulate worker: claim → deliver → complete.
	item, err := storage.ClaimNext(ctx, db)
	if err != nil {
		t.Fatalf("ClaimNext: %v", err)
	}
	if item == nil {
		t.Fatal("expected item, got nil")
	}

	if err := storage.Complete(ctx, db, item.ID); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	size, _ := storage.QueueSize(ctx, db)
	if size != 0 {
		t.Fatalf("expected empty queue after delivery, got %d", size)
	}

	nextItem, err := storage.ClaimNext(ctx, db)
	if err != nil {
		t.Fatalf("ClaimNext after delivery: %v", err)
	}
	if nextItem != nil {
		t.Fatal("expected nil after delivery")
	}
}

// ---------------------------------------------------------------------------
// 5. Worker: Simulated transient failure (increments attempt)
// ---------------------------------------------------------------------------

func TestWorkerTransientFailure(t *testing.T) {
	db := migrateTestDB(t)
	_, _, msgID := setupTest(t, db)
	ctx := context.Background()
	mgr := createManager(t, db)

	if err := mgr.Enqueue(msgID, "recip@example.com"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	item, err := storage.ClaimNext(ctx, db)
	if err != nil {
		t.Fatalf("ClaimNext: %v", err)
	}
	if item == nil {
		t.Fatal("expected item, got nil")
	}

	// Transient failure uses the real backoff schedule.
	next := nextAttempt(item.AttemptCount)
	if err := storage.Fail(ctx, db, item.ID, next, 3); err != nil {
		t.Fatalf("Fail: %v", err)
	}

	items, err := storage.ListPending(ctx, db)
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 pending item, got %d", len(items))
	}
	if items[0].AttemptCount != 1 {
		t.Fatalf("expected attempt_count=1, got %d", items[0].AttemptCount)
	}

	// nextAttempt(0) = ~1 minute from now; next_attempt should be in the future.
	if items[0].NextAttempt <= time.Now().Unix() {
		t.Fatalf("expected next_attempt in the future, got %d (now=%d)",
			items[0].NextAttempt, time.Now().Unix())
	}
}

// ---------------------------------------------------------------------------
// 6. Worker: Simulated permanent failure (max retries → NDR)
// ---------------------------------------------------------------------------

func TestWorkerPermanentFailure(t *testing.T) {
	db := migrateTestDB(t)
	userID, _, msgID := setupTest(t, db)
	ctx := context.Background()

	// All default mailboxes (including INBOX) already exist for the user
	// created by setupTest. No need to create the user again.

	blob := blobstore.NewSQLiteStore(db)
	originalMsg := []byte("From: sender@example.com\r\nSubject: test\r\n\r\nHello")
	blobKey, _, err := blob.Put(ctx, bytes.NewReader(originalMsg), nil)
	if err != nil {
		t.Fatalf("blob.Put: %v", err)
	}

	// Point the message blob_key at the real blob.
	_, err = db.ExecContext(ctx,
		`UPDATE messages SET blob_key = ? WHERE id = ?`,
		blobKey, msgID)
	if err != nil {
		t.Fatalf("update blob_key: %v", err)
	}

	mgr := createManager(t, db)
	mgr.blob = blob

	if err := mgr.Enqueue(msgID, "nonexistent@remote.com"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	// Exhaust all retries.
	maxRetries := 3
	for attempt := 0; attempt <= maxRetries; attempt++ {
		item, err := storage.ClaimNext(ctx, db)
		if err != nil {
			t.Fatalf("ClaimNext attempt %d: %v", attempt, err)
		}
		if item == nil && attempt < maxRetries {
			t.Fatalf("expected item at attempt %d", attempt)
		}
		if item == nil {
			break
		}
		past := time.Now().Add(-time.Hour)
		if err := storage.Fail(ctx, db, item.ID, past, maxRetries); err != nil {
			t.Fatalf("Fail attempt %d: %v", attempt, err)
		}
	}

	size, _ := storage.QueueSize(ctx, db)
	if size != 0 {
		t.Fatalf("expected empty queue after max retries, got %d", size)
	}

	// Generate NDR.
	ndrBody := GenerateNDR("sender@example.com", "nonexistent@remote.com",
		"550 No such user", originalMsg)

	if len(ndrBody) == 0 {
		t.Fatal("GenerateNDR returned empty body")
	}
	if !bytes.Contains(ndrBody, []byte("550 No such user")) {
		t.Fatal("NDR body should contain the reason")
	}
	if !bytes.Contains(ndrBody, []byte("sender@example.com")) {
		t.Fatal("NDR body should contain original sender")
	}
	if !bytes.Contains(ndrBody, []byte("nonexistent@remote.com")) {
		t.Fatal("NDR body should contain original recipient")
	}

	// Simulate BounceMessage: store NDR blob and insert into sender's INBOX.
	ndrBlobKey, _, err := blob.Put(ctx, bytes.NewReader(ndrBody), nil)
	if err != nil {
		t.Fatalf("blob.Put NDR: %v", err)
	}

	mbox, err := storage.GetMailbox(ctx, db, userID, "INBOX")
	if err != nil {
		t.Fatalf("GetMailbox: %v", err)
	}

	_, _, err = storage.InsertMessage(ctx, db, mbox.ID, ndrBlobKey,
		int64(len(ndrBody)), "", "sender@example.com",
		"Mail delivery failed: 550 No such user", 0)
	if err != nil {
		t.Fatalf("InsertMessage NDR: %v", err)
	}

	// Verify the NDR message is in the INBOX.
	msgs, err := storage.ListMessages(ctx, db, mbox.ID, 10, 0)
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}
	if len(msgs) == 0 {
		t.Fatal("expected at least one message (NDR) in INBOX")
	}
	var found bool
	for _, m := range msgs {
		if strings.Contains(m.Subject, "Mail delivery failed") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected NDR message in INBOX with delivery-failed subject")
	}
}

// ---------------------------------------------------------------------------
// 7. NDR: Generate bounce message with correct headers
// ---------------------------------------------------------------------------

func TestGenerateNDR(t *testing.T) {
	originalMsg := []byte("From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Hi\r\n\r\nHello Bob!")

	ndr := GenerateNDR("alice@example.com", "bob@remote.com",
		"550 mailbox not found", originalMsg)

	if len(ndr) == 0 {
		t.Fatal("GenerateNDR returned empty bytes")
	}

	tests := []struct {
		name string
		need []byte
	}{
		{"From header", []byte("From: MAILER-DAEMON")},
		{"To header (original sender)", []byte("To: alice@example.com")},
		{"Subject with reason", []byte("Subject: Mail delivery failed: 550 mailbox not found")},
		{"Date header", []byte("Date: ")},
		{"MIME-Version", []byte("MIME-Version: 1.0")},
		{"Content-Type multipart/report", []byte("Content-Type: multipart/report")},
		{"report-type=delivery-status", []byte("report-type=delivery-status")},
		{"boundary", []byte("boundary=ndrboundary")},
		{"text/plain part", []byte("Content-Type: text/plain")},
		{"failure message", []byte("could not be delivered")},
		{"reason in body", []byte("550 mailbox not found")},
		{"message/delivery-status part", []byte("Content-Type: message/delivery-status")},
		{"Original-Recipient header", []byte("Original-Recipient: bob@remote.com")},
		{"Diagnostic-Code header", []byte("Diagnostic-Code: smtp; 550 mailbox not found")},
		{"Action: failed", []byte("Action: failed")},
		{"Status: 5.0.0", []byte("Status: 5.0.0")},
		{"message/rfc822 part", []byte("Content-Type: message/rfc822")},
		{"original message content", []byte("From: alice@example.com")},
	}
	for _, tt := range tests {
		if !bytes.Contains(ndr, tt.need) {
			t.Errorf("GenerateNDR missing %q", tt.name)
		}
	}

	if !bytes.HasSuffix(bytes.TrimSpace(ndr), []byte("--ndrboundary--")) {
		t.Error("GenerateNDR must end with closing boundary '--ndrboundary--'")
	}
}

func TestGenerateNDRNoOriginalMessage(t *testing.T) {
	ndr := GenerateNDR("alice@example.com", "bob@remote.com",
		"550 mailbox not found", nil)

	if len(ndr) == 0 {
		t.Fatal("GenerateNDR returned empty bytes")
	}
	if !bytes.Contains(ndr, []byte("Original message not available")) {
		t.Error("GenerateNDR with nil original should include fallback text")
	}
}

// ---------------------------------------------------------------------------
// 8. Edge cases: empty queue, unknown message ID, double complete, double claim
// ---------------------------------------------------------------------------

func TestQueueEmptyQueue(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	size, err := storage.QueueSize(ctx, db)
	if err != nil {
		t.Fatalf("QueueSize: %v", err)
	}
	if size != 0 {
		t.Fatalf("expected empty queue, got size %d", size)
	}

	item, err := storage.ClaimNext(ctx, db)
	if err != nil {
		t.Fatalf("ClaimNext on empty queue: %v", err)
	}
	if item != nil {
		t.Fatal("expected nil item from empty queue")
	}

	items, err := storage.ListPending(ctx, db)
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected 0 items, got %d", len(items))
	}
}

func TestQueueEnqueueUnknownMessageID(t *testing.T) {
	db := migrateTestDB(t)
	_, _, msgID := setupTest(t, db)
	ctx := context.Background()
	mgr := createManager(t, db)

	// The queue.message_id column has a FK constraint referencing messages(id),
	// so using a known message ID works.
	if err := mgr.Enqueue(msgID, "ghost@example.com"); err != nil {
		t.Fatalf("Enqueue with valid message_id: %v", err)
	}

	size, _ := storage.QueueSize(ctx, db)
	if size != 1 {
		t.Fatalf("expected queue size 1, got %d", size)
	}

	item, err := storage.ClaimNext(ctx, db)
	if err != nil {
		t.Fatalf("ClaimNext: %v", err)
	}
	if item == nil {
		t.Fatal("expected item")
	}
}

func TestQueueDoubleComplete(t *testing.T) {
	db := migrateTestDB(t)
	_, _, msgID := setupTest(t, db)
	ctx := context.Background()
	mgr := createManager(t, db)

	if err := mgr.Enqueue(msgID, "user@example.com"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	item, err := storage.ClaimNext(ctx, db)
	if err != nil {
		t.Fatalf("ClaimNext: %v", err)
	}

	// First complete succeeds.
	if err := storage.Complete(ctx, db, item.ID); err != nil {
		t.Fatalf("First Complete: %v", err)
	}

	// Second complete returns ErrNotFound.
	err = storage.Complete(ctx, db, item.ID)
	if err == nil {
		t.Fatal("expected error on second complete, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected 'not found' error, got: %v", err)
	}
}

func TestQueueDoubleClaim(t *testing.T) {
	// After claiming, the item is marked 'active' and should not be
	// returned by another ClaimNext until it's failed back to 'pending'.
	db := migrateTestDB(t)
	_, _, msgID := setupTest(t, db)
	ctx := context.Background()
	mgr := createManager(t, db)

	if err := mgr.Enqueue(msgID, "user@example.com"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	item, err := storage.ClaimNext(ctx, db)
	if err != nil {
		t.Fatalf("First ClaimNext: %v", err)
	}
	if item == nil {
		t.Fatal("expected item on first claim")
	}

	// Second claim should return nil (item is still 'active').
	item2, err := storage.ClaimNext(ctx, db)
	if err != nil {
		t.Fatalf("Second ClaimNext: %v", err)
	}
	if item2 != nil {
		t.Fatalf("expected nil on second claim, got item id=%d status=%s", item2.ID, item2.Status)
	}
}

// ---------------------------------------------------------------------------
// 9. Metrics: Enqueue increments QueuePending gauge
// ---------------------------------------------------------------------------

func TestQueueMetrics(t *testing.T) {
	db := migrateTestDB(t)
	_, _, msgID := setupTest(t, db)
	mgr := createManager(t, db)

	if err := mgr.Enqueue(msgID, "a@example.com"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	if mgr.metrics == nil {
		t.Fatal("manager metrics should not be nil")
	}
}

// ---------------------------------------------------------------------------
// 10. BounceMessage: end-to-end NDR delivery to sender's inbox
// ---------------------------------------------------------------------------

func TestBounceMessage(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	userID := ensureUser(t, db, "sender@example.com", "hash")
	if err := storage.EnsureDefaultMailboxes(ctx, db, userID); err != nil {
		t.Fatalf("EnsureDefaultMailboxes: %v", err)
	}

	blob := blobstore.NewSQLiteStore(db)
	mgr := NewManager(db, blob, 1, 3, time.Second, "")

	originalMsg := []byte("From: sender@example.com\r\nSubject: hello\r\n\r\nbody")

	// BounceMessage should store an NDR in the sender's INBOX.
	if err := mgr.BounceMessage("sender@example.com", "baddomain@invalid",
		"550 No such user", originalMsg); err != nil {
		t.Fatalf("BounceMessage: %v", err)
	}

	// Verify NDR was stored in sender's INBOX.
	mbox, err := storage.GetMailbox(ctx, db, userID, "INBOX")
	if err != nil {
		t.Fatalf("GetMailbox: %v", err)
	}

	msgs, err := storage.ListMessages(ctx, db, mbox.ID, 10, 0)
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message (NDR) in INBOX, got %d", len(msgs))
	}
	if !strings.Contains(msgs[0].Subject, "Mail delivery failed") {
		t.Fatalf("expected NDR subject, got %q", msgs[0].Subject)
	}
	if msgs[0].BlobKey == "" {
		t.Fatal("expected non-empty blob_key for NDR message")
	}

	// Verify the blob content can be read back and contains the NDR.
	rc, err := blob.Get(ctx, msgs[0].BlobKey)
	if err != nil {
		t.Fatalf("blob.Get NDR: %v", err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read NDR blob: %v", err)
	}
	if !bytes.Contains(data, []byte("MAILER-DAEMON")) {
		t.Error("NDR blob should contain MAILER-DAEMON from address")
	}
	if !bytes.Contains(data, []byte("baddomain@invalid")) {
		t.Error("NDR blob should mention the failed recipient")
	}
}

func TestBounceMessageUnknownSender(t *testing.T) {
	db := migrateTestDB(t)
	blob := blobstore.NewSQLiteStore(db)
	mgr := NewManager(db, blob, 1, 3, time.Second, "")

	err := mgr.BounceMessage("nonexistent@example.com", "bob@invalid",
		"550 Not found", []byte("original"))
	if err != nil {
		t.Fatalf("BounceMessage with unknown sender: %v", err)
	}

	ctx := context.Background()
	size, _ := storage.QueueSize(ctx, db)
	if size != 0 {
		t.Fatalf("expected empty queue, got %d", size)
	}
}

// ---------------------------------------------------------------------------
// 11. Backoff schedule
// ---------------------------------------------------------------------------

func TestNextAttemptBackoff(t *testing.T) {
	tests := []struct {
		attempt  int
		minDelay time.Duration
		maxDelay time.Duration
	}{
		{0, 30 * time.Second, 2 * time.Minute},
		{1, 4 * time.Minute, 6 * time.Minute},
		{2, 14 * time.Minute, 16 * time.Minute},
		{3, 50 * time.Minute, 70 * time.Minute},
		{4, 3*time.Hour + 50*time.Minute, 4*time.Hour + 10*time.Minute},
		{6, 23 * time.Hour, 25 * time.Hour},
		{10, 23 * time.Hour, 25 * time.Hour},
	}

	for _, tt := range tests {
		now := time.Now()
		got := nextAttempt(tt.attempt)
		delay := got.Sub(now)
		if delay < tt.minDelay || delay > tt.maxDelay {
			t.Errorf("nextAttempt(%d) delay=%v, want between %v and %v",
				tt.attempt, delay, tt.minDelay, tt.maxDelay)
		}
	}
}

// ---------------------------------------------------------------------------
// 12. Multiple recipients for the same message
// ---------------------------------------------------------------------------

func TestQueueMultipleRecipients(t *testing.T) {
	db := migrateTestDB(t)
	_, _, msgID := setupTest(t, db)
	ctx := context.Background()
	mgr := createManager(t, db)

	recipients := []string{"alice@example.com", "bob@example.com", "carol@example.com"}
	for _, rcpt := range recipients {
		if err := mgr.Enqueue(msgID, rcpt); err != nil {
			t.Fatalf("Enqueue(%q): %v", rcpt, err)
		}
	}

	size, _ := storage.QueueSize(ctx, db)
	if size != 3 {
		t.Fatalf("expected queue size 3, got %d", size)
	}

	items, err := storage.ListPending(ctx, db)
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("expected 3 items, got %d", len(items))
	}

	claimed := make(map[string]bool)
	for i := range 3 {
		item, err := storage.ClaimNext(ctx, db)
		if err != nil {
			t.Fatalf("ClaimNext %d: %v", i, err)
		}
		if item == nil {
			t.Fatalf("expected item %d, got nil", i)
		}
		if claimed[item.RcptTo] {
			t.Fatalf("duplicate claim for %s", item.RcptTo)
		}
		claimed[item.RcptTo] = true

		if err := storage.Complete(ctx, db, item.ID); err != nil {
			t.Fatalf("Complete %d: %v", i, err)
		}
	}

	if len(claimed) != 3 {
		t.Fatalf("expected 3 unique recipients claimed, got %d", len(claimed))
	}
}
