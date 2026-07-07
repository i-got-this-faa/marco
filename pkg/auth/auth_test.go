package auth

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/i-got-this-faa/marco/pkg/storage"
	_ "modernc.org/sqlite"
)

func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	if err := storage.Migrate(db); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestHashPasswordRoundTrip(t *testing.T) {
	password := "correct-horse-battery-staple"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}
	if hash == "" {
		t.Fatal("HashPassword returned empty hash")
	}

	ok, err := VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if !ok {
		t.Fatal("VerifyPassword returned false for correct password")
	}
}

func TestVerifyWrongPassword(t *testing.T) {
	hash, _ := HashPassword("correct-password")
	ok, err := VerifyPassword("wrong-password", hash)
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if ok {
		t.Fatal("VerifyPassword should return false for wrong password")
	}
}

func TestVerifyInvalidHash(t *testing.T) {
	_, err := VerifyPassword("password", "not-a-valid-hash")
	if err == nil {
		t.Fatal("expected error for invalid hash format")
	}
}

func TestHashPasswordDifferentSalts(t *testing.T) {
	h1, _ := HashPassword("same-password")
	h2, _ := HashPassword("same-password")
	if h1 == h2 {
		t.Fatal("two hashes of same password should be different (different salts)")
	}
}

func TestValidatePasswordStrength(t *testing.T) {
	if err := ValidatePasswordStrength("short"); err == nil {
		t.Fatal("expected error for short password")
	}
	if err := ValidatePasswordStrength("longenough"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestManagerAuthenticate(t *testing.T) {
	db := setupTestDB(t)
	m := NewManager(db)

	// Create a user.
	userID, err := m.CreateUser(context.Background(, false), "test@example.com", "secure-password")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	if userID == 0 {
		t.Fatal("expected non-zero user ID")
	}

	// Authenticate with correct credentials.
	id, err := m.Authenticate(context.Background(), "test@example.com", "secure-password")
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}
	if id != userID {
		t.Errorf("authenticated userID = %d, want %d", id, userID)
	}

	// Authenticate with wrong password.
	_, err = m.Authenticate(context.Background(), "test@example.com", "wrong-password")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}

	// Authenticate non-existent user.
	_, err = m.Authenticate(context.Background(), "nonexistent@example.com", "password")
	if err == nil {
		t.Fatal("expected error for non-existent user")
	}
}

func TestManagerAuthenticateInactiveUser(t *testing.T) {
	db := setupTestDB(t)
	m := NewManager(db)

	userID, _ := m.CreateUser(context.Background(, false), "user@example.com", "password")

	// Deactivate the user.
	active := false
	if err := storage.UpdateUser(context.Background(), db, userID, nil, nil, &active, nil); err != nil {
		t.Fatalf("UpdateUser failed: %v", err)
	}

	_, err := m.Authenticate(context.Background(), "user@example.com", "password")
	if err == nil {
		t.Fatal("expected error for inactive user")
	}
}

func TestManagerCreateUser(t *testing.T) {
	db := setupTestDB(t)
	m := NewManager(db)

	userID, err := m.CreateUser(context.Background(, false), "new@example.com", "strong-password")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// Default mailboxes should exist.
	mboxes, err := storage.ListMailboxes(context.Background(), db, userID)
	if err != nil {
		t.Fatalf("ListMailboxes failed: %v", err)
	}
	if len(mboxes) != len(storage.DefaultMailboxes) {
		t.Errorf("got %d mailboxes, want %d", len(mboxes), len(storage.DefaultMailboxes))
	}

	found := false
	for _, m := range mboxes {
		if m.Name == "INBOX" {
			found = true
			break
		}
	}
	if !found {
		t.Error("INBOX not found in default mailboxes")
	}

	// Duplicate email should fail.
	_, err = m.CreateUser(context.Background(, false), "new@example.com", "another-password")
	if err == nil {
		t.Fatal("expected error for duplicate email")
	}
}

func TestCreateSession(t *testing.T) {
	db := setupTestDB(t)

	// Create a user first.
	uid, _ := storage.CreateUser(context.Background(), db, "session@example.com", "hash", false)

	token, err := CreateSession(context.Background(), db, uid, time.Hour)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	if len(token) != 64 { // 32 bytes hex
		t.Errorf("token length = %d, want 64", len(token))
	}
}

func TestValidateSession(t *testing.T) {
	db := setupTestDB(t)
	uid, _ := storage.CreateUser(context.Background(), db, "validate@example.com", "hash", false)

	token, _ := CreateSession(context.Background(), db, uid, time.Hour)

	gotUID, err := ValidateSession(context.Background(), db, token)
	if err != nil {
		t.Fatalf("ValidateSession failed: %v", err)
	}
	if gotUID != uid {
		t.Errorf("got userID %d, want %d", gotUID, uid)
	}
}

func TestValidateSessionExpired(t *testing.T) {
	db := setupTestDB(t)
	uid, _ := storage.CreateUser(context.Background(), db, "expired@example.com", "hash", false)

	token, _ := CreateSession(context.Background(), db, uid, -time.Hour) // expired

	_, err := ValidateSession(context.Background(), db, token)
	if err == nil {
		t.Fatal("expected error for expired session")
	}
}

func TestValidateSessionInvalid(t *testing.T) {
	db := setupTestDB(t)
	_, err := ValidateSession(context.Background(), db, "invalid-token")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestRevokeSession(t *testing.T) {
	db := setupTestDB(t)
	uid, _ := storage.CreateUser(context.Background(), db, "revoke@example.com", "hash", false)

	token, _ := CreateSession(context.Background(), db, uid, time.Hour)

	if err := RevokeSession(context.Background(), db, token); err != nil {
		t.Fatalf("RevokeSession failed: %v", err)
	}

	_, err := ValidateSession(context.Background(), db, token)
	if err == nil {
		t.Fatal("expected error after revoke")
	}
}

func TestSMTPAuth(t *testing.T) {
	db := setupTestDB(t)
	m := NewManager(db)
	m.CreateUser(context.Background(, false), "smtp@example.com", "smtp-password")

	server := SMTPAuth(m)
	if server == nil {
		t.Fatal("SMTPAuth returned nil")
	}
}

func TestIMAPAuthAdapter(t *testing.T) {
	db := setupTestDB(t)
	m := NewManager(db)
	m.CreateUser(context.Background(, false), "imap@example.com", "imap-password")

	fn := AuthAdapter(m)
	if fn == nil {
		t.Fatal("AuthAdapter returned nil")
	}

	userID, err := fn(nil, "imap@example.com", "imap-password")
	if err != nil {
		t.Fatalf("AuthAdapter login failed: %v", err)
	}
	if userID.(int64) == 0 {
		t.Fatal("expected non-zero user ID")
	}

	_, err = fn(nil, "imap@example.com", "wrong")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}
