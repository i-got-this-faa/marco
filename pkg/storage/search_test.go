package storage

import (
	"context"
	"testing"
)

func TestSearchFTS5IndexCreated(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	// Verify the FTS5 virtual table is accessible.
	var count int
	err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM messages_fts`,
	).Scan(&count)
	if err != nil {
		t.Fatalf("messages_fts not accessible: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 rows in empty FTS index, got %d", count)
	}

	// Verify triggers exist.
	var triggerCount int
	err = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name LIKE 'messages_%'`,
	).Scan(&triggerCount)
	if err != nil {
		t.Fatalf("query triggers: %v", err)
	}
	if triggerCount != 3 {
		t.Fatalf("expected 3 FTS triggers (ai, ad, au), got %d", triggerCount)
	}
}

func TestSearchMessagesBySubject(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	userID := ensureUser(t, db, "user@example.com", "hash")
	mboxID := ensureMailbox(t, db, userID, "INBOX")

	ensureMessage(t, db, mboxID, "alice@example.com", "bob@example.com", "Hello World", 0)
	ensureMessage(t, db, mboxID, "carol@example.com", "dave@example.com", "Meeting Tomorrow", 0)
	ensureMessage(t, db, mboxID, "eve@example.com", "frank@example.com", "Hello Again", 0)

	// Search by subject.
	msgs, err := SearchMessages(ctx, db, mboxID, "Hello", 10)
	if err != nil {
		t.Fatalf("SearchMessages(Hello): %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages matching 'Hello', got %d", len(msgs))
	}

	msgs, err = SearchMessages(ctx, db, mboxID, "Meeting", 10)
	if err != nil {
		t.Fatalf("SearchMessages(Meeting): %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message matching 'Meeting', got %d", len(msgs))
	}
	if msgs[0].Subject != "Meeting Tomorrow" {
		t.Fatalf("expected subject 'Meeting Tomorrow', got %q", msgs[0].Subject)
	}

	// No match.
	msgs, err = SearchMessages(ctx, db, mboxID, "Nonexistent", 10)
	if err != nil {
		t.Fatalf("SearchMessages(Nonexistent): %v", err)
	}
	if len(msgs) != 0 {
		t.Fatalf("expected 0 messages matching 'Nonexistent', got %d", len(msgs))
	}
}

func TestSearchMessagesByFrom(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	userID := ensureUser(t, db, "user@example.com", "hash")
	mboxID := ensureMailbox(t, db, userID, "INBOX")

	ensureMessage(t, db, mboxID, "alice_unique@example.com", "bob@example.com", "Subject A", 0)
	ensureMessage(t, db, mboxID, "bob@example.com", "carol@example.com", "Subject B", 0)
	ensureMessage(t, db, mboxID, "carol@example.com", "dave@example.com", "Subject C", 0)

	msgs, err := SearchMessages(ctx, db, mboxID, "alice_unique@example.com", 10)
	if err != nil {
		t.Fatalf("SearchMessages(alice): %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message matching 'alice@example.com', got %d", len(msgs))
	}
}

func TestSearchMessagesByTo(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	userID := ensureUser(t, db, "user@example.com", "hash")
	mboxID := ensureMailbox(t, db, userID, "INBOX")

	ensureMessage(t, db, mboxID, "alice@example.com", "bob@example.com", "Subject A", 0)
	ensureMessage(t, db, mboxID, "carol@example.com", "alice@example.com", "Subject B", 0)

	msgs, err := SearchMessages(ctx, db, mboxID, "bob@example.com", 10)
	if err != nil {
		t.Fatalf("SearchMessages(bob@example.com): %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message matching 'bob@example.com', got %d", len(msgs))
	}
	if msgs[0].Subject != "Subject A" {
		t.Fatalf("expected subject 'Subject A', got %q", msgs[0].Subject)
	}
}

func TestSearchMessagesWithSpecialChars(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	userID := ensureUser(t, db, "user@example.com", "hash")
	mboxID := ensureMailbox(t, db, userID, "INBOX")

	ensureMessage(t, db, mboxID, "alice@example.com", "bob@example.com", "Price: $100 - 50% off!", 0)
	ensureMessage(t, db, mboxID, "carol@example.com", "dave@example.com", "Re: [urgent] meeting", 0)
	ensureMessage(t, db, mboxID, "eve@example.com", "frank@example.com", "C++ compiler update", 0)

	// Search with dollar sign and percent.
	msgs, err := SearchMessages(ctx, db, mboxID, "$100", 10)
	if err != nil {
		t.Fatalf("SearchMessages($100): %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message matching '$100', got %d", len(msgs))
	}

	// Search with brackets (FTS5 special chars).
	msgs, err = SearchMessages(ctx, db, mboxID, "urgent", 10)
	if err != nil {
		t.Fatalf("SearchMessages(urgent): %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message matching 'urgent', got %d", len(msgs))
	}

	// Search with plus signs (FTS5 special chars).
	msgs, err = SearchMessages(ctx, db, mboxID, "C++", 10)
	if err != nil {
		t.Fatalf("SearchMessages(C++): %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message matching 'C++', got %d", len(msgs))
	}
}

func TestSearchMessagesAll(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	userID := ensureUser(t, db, "user@example.com", "hash")
	mbox1 := ensureMailbox(t, db, userID, "INBOX")
	mbox2 := ensureMailbox(t, db, userID, "Sent")

	ensureMessage(t, db, mbox1, "alice@example.com", "bob@example.com", "Hello World", 0)
	ensureMessage(t, db, mbox2, "bob@example.com", "carol@example.com", "Hello Again", 0)

	// Search across all mailboxes.
	msgs, err := SearchMessagesAll(ctx, db, "Hello", 10)
	if err != nil {
		t.Fatalf("SearchMessagesAll(Hello): %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages matching 'Hello' across all mailboxes, got %d", len(msgs))
	}
}

func TestSearchMessagesAfterInsert(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	userID := ensureUser(t, db, "user@example.com", "hash")
	mboxID := ensureMailbox(t, db, userID, "INBOX")

	// Insert messages and verify they appear in search.
	id1, _ := ensureMessage(t, db, mboxID, "alice@example.com", "bob@example.com", "Alpha Message", 0)
	id2, _ := ensureMessage(t, db, mboxID, "carol@example.com", "dave@example.com", "Beta Message", 0)

	msgs, err := SearchMessages(ctx, db, mboxID, "Message", 10)
	if err != nil {
		t.Fatalf("SearchMessages(Message): %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages matching 'Message', got %d", len(msgs))
	}

	// Delete a message and verify it's removed from search.
	err = DeleteMessage(ctx, db, id1)
	if err != nil {
		t.Fatalf("DeleteMessage(%d): %v", id1, err)
	}

	msgs, err = SearchMessages(ctx, db, mboxID, "Message", 10)
	if err != nil {
		t.Fatalf("SearchMessages after delete: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message after delete, got %d", len(msgs))
	}
	if msgs[0].ID != id2 {
		t.Fatalf("expected remaining message ID %d, got %d", id2, msgs[0].ID)
	}

	// Update message subject and verify search finds the new value.
	// Move the message to "update" it (we use UpdateFlags as a simple update).
	// Instead, let's update via an UPDATE directly to test the AU trigger.
	_, err = db.ExecContext(ctx,
		`UPDATE messages SET subject = 'Gamma Message', from_addr = 'updated@example.com' WHERE id = ?`,
		id2,
	)
	if err != nil {
		t.Fatalf("update message: %v", err)
	}

	// Old query should no longer match subject.
	msgs, err = SearchMessages(ctx, db, mboxID, "Beta", 10)
	if err != nil {
		t.Fatalf("SearchMessages(Beta) after update: %v", err)
	}
	if len(msgs) != 0 {
		t.Fatalf("expected 0 messages matching 'Beta' after update, got %d", len(msgs))
	}

	// New query should match.
	msgs, err = SearchMessages(ctx, db, mboxID, "Gamma", 10)
	if err != nil {
		t.Fatalf("SearchMessages(Gamma) after update: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message matching 'Gamma' after update, got %d", len(msgs))
	}
}

func TestSearchMessagesScopedToMailbox(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	userID := ensureUser(t, db, "user@example.com", "hash")
	mbox1 := ensureMailbox(t, db, userID, "INBOX")
	mbox2 := ensureMailbox(t, db, userID, "Sent")

	ensureMessage(t, db, mbox1, "alice@example.com", "bob@example.com", "Hello", 0)
	ensureMessage(t, db, mbox2, "alice@example.com", "bob@example.com", "Hello", 0)

	// Search only in inbox.
	msgs, err := SearchMessages(ctx, db, mbox1, "Hello", 10)
	if err != nil {
		t.Fatalf("SearchMessages inbox: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message in inbox, got %d", len(msgs))
	}

	// Search only in sent.
	msgs, err = SearchMessages(ctx, db, mbox2, "Hello", 10)
	if err != nil {
		t.Fatalf("SearchMessages sent: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message in sent, got %d", len(msgs))
	}
}

func TestSearchMessagesEmptyQuery(t *testing.T) {
	db := migrateTestDB(t)
	ctx := context.Background()

	userID := ensureUser(t, db, "user@example.com", "hash")
	mboxID := ensureMailbox(t, db, userID, "INBOX")

	ensureMessage(t, db, mboxID, "alice@example.com", "bob@example.com", "Hello", 0)

	// Empty query should not cause an error (FTS5 MATCH '' would fail).
	msgs, err := SearchMessages(ctx, db, mboxID, "", 10)
	if err != nil {
		t.Fatalf("SearchMessages empty: %v", err)
	}
	if len(msgs) != 0 {
		t.Fatalf("expected 0 messages for empty query, got %d", len(msgs))
	}
}
