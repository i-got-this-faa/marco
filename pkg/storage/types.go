package storage

// User represents a mail user row.
type User struct {
	ID           int64  `json:"id"`
	Email        string `json:"email"`
	PasswordHash string `json:"-"`
	IsAdmin     bool   `json:"is_admin"`
	CreatedAt    int64  `json:"created_at"`
	IsActive     bool   `json:"is_active"`
}

// Mailbox represents a mailbox (folder) for a user.
type Mailbox struct {
	ID     int64  `json:"id"`
	UserID int64  `json:"user_id"`
	Name   string `json:"name"`
}

// Message represents a stored email message.
type Message struct {
	ID          int64  `json:"id"`
	MailboxID   int64  `json:"mailbox_id"`
	UID         uint32 `json:"uid"`
	BlobKey     string `json:"blob_key"`
	Size        int64  `json:"size"`
	Flags       int    `json:"flags"`
	InternalDate int64 `json:"internal_date"`
	FromAddr    string `json:"from_addr"`
	ToAddr      string `json:"to_addr"`
	Subject     string `json:"subject"`
}

// QueueItem represents a pending outbound delivery.
type QueueItem struct {
	ID           int64  `json:"id"`
	MessageID    int64  `json:"message_id"`
	RcptTo       string `json:"rcpt_to"`
	NextAttempt  int64  `json:"next_attempt"`
	AttemptCount int    `json:"attempt_count"`
	Status       string `json:"status"`
}

// Alias represents an email alias (forwarder).
type Alias struct {
	ID          int64  `json:"id"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Domain      string `json:"domain"`
}
