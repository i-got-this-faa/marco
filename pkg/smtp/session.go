package smtp

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/mail"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/i-got-this-faa/marco/pkg/spf"
	"github.com/i-got-this-faa/marco/pkg/storage"
)
// Session implements smtp.Session for a single SMTP transaction.
type Session struct {
	backend    *Backend
	conn       *smtp.Conn
	from       string
	recipients []string
	authed     bool
	authedUser string
	userID     int64
}

// Mail handles the MAIL FROM command.
func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	if !strings.Contains(from, "@") {
		return &smtp.SMTPError{
			Code:    553,
			Message: "Invalid from address",
		}
	}
	s.from = from
	return nil
}
// Auth handles the AUTH command for SMTP authentication.
func (s *Session) Auth(mech string) (sasl.Server, error) {
	return sasl.NewPlainServer(func(identity, username, password string) error {
		userID, err := s.backend.auth.Authenticate(context.Background(), username, password)
		if err != nil {
			return fmt.Errorf("auth failed: %w", err)
		}
		s.authed = true
		s.authedUser = username
		s.userID = userID
		return nil
	}), nil
}

// Rcpt handles the RCPT TO command.
func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error {
	if len(s.recipients) >= s.backend.cfg.MaxRecipients {
		return &smtp.SMTPError{
			Code:    552,
			Message: fmt.Sprintf("Too many recipients (max %d)", s.backend.cfg.MaxRecipients),
		}
	}

	if !s.authed {
		parts := strings.Split(to, "@")
		if len(parts) != 2 {
			return &smtp.SMTPError{Code: 553, Message: "Invalid recipient address"}
		}
		domain := parts[1]
		if !s.isLocalDomain(domain) {
			return &smtp.SMTPError{
				Code:    550,
				Message: "Relay not permitted",
			}
		}
	}

	// Greylisting: temporarily reject unauthenticated senders on first attempt.
	if !s.authed && s.from != "" && s.conn != nil && s.backend.cfg.GreylistingDelay > 0 {
		if err := s.checkGreylist(to); err != nil {
			return err
		}
	}
	s.recipients = append(s.recipients, to)
	return nil
}

// checkGreylist performs greylisting for the given recipient.
func (s *Session) checkGreylist(to string) error {
	// Extract client IP.
	ip := ""
	if conn := s.conn.Conn(); conn != nil {
		if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			ip = addr.IP.String()
		}
	}
	if ip == "" {
		return nil
	}

	ctx := context.Background()

	whitelisted, err := storage.IsWhitelisted(ctx, s.backend.db, ip, s.from, to)
	if err != nil {
		s.backend.log.Warn("greylist check failed", "error", err)
		return nil
	}
	if whitelisted {
		return nil
	}

	// Record the attempt (creates or updates the triplet).
	if err := storage.RecordAttempt(ctx, s.backend.db, ip, s.from, to); err != nil {
		s.backend.log.Warn("greylist record failed", "error", err)
		return nil
	}

	// Retrieve first_seen to check the delay.
	var firstSeen int64
	err = s.backend.db.QueryRowContext(ctx,
		`SELECT first_seen FROM greylist WHERE ip = ? AND from_addr = ? AND to_addr = ?`,
		ip, s.from, to,
	).Scan(&firstSeen)
	if err != nil {
		s.backend.log.Warn("greylist first_seen query failed", "error", err)
		return nil
	}
	// If the greylisting delay hasn't passed since the first attempt, reject.
	delay := int(s.backend.cfg.GreylistingDelay.Seconds())
	if time.Now().Unix()-firstSeen < int64(delay) {
		return &smtp.SMTPError{
			Code:    451,
			Message: "Greylisted, try again later",
		}
	}

	// Enough time has passed; mark as passed and proceed.
	if err := storage.MarkPassed(ctx, s.backend.db, ip, s.from, to); err != nil {
		s.backend.log.Warn("greylist mark passed failed", "error", err)
	}
	return nil
}

// Data handles the DATA command.
func (s *Session) Data(r io.Reader) error {
	bufReader := bufio.NewReaderSize(r, 64<<10) // 64KB buffer

	headersBuf, err := readHeaders(bufReader)
	if err != nil {
		return &smtp.SMTPError{
			Code:    552,
			Message: "Error reading message data",
		}
	}

	// Parse headers from the header bytes.
	fromAddr, _, subject := parseMessageHeaders(headersBuf)

	// Run SPF check on the connecting IP against the envelope from domain.
	if s.from != "" && s.conn != nil {
		parts := strings.SplitN(s.from, "@", 2)
		if len(parts) == 2 && parts[1] != "" {
			domain := parts[1]
			ip := net.IP{}
			if conn := s.conn.Conn(); conn != nil {
				if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
					ip = addr.IP
				}
			}
			spfResult, spfErr := spf.NewChecker().Check(ip, domain, "")
			if spfErr == nil {
				slog.Debug("spf check",
					"domain", domain,
					"ip", ip,
					"result", spfResult.Code.String(),
					"text", spfResult.Text,
					"from", s.from,
				)
			}
		}
	}

	// Reconstruct full message stream: headers + remaining buffered body.
	combined := io.MultiReader(bytes.NewReader(headersBuf), bufReader)

	// Stream to blob store while counting bytes.
	counted := &countingReader{r: combined}
	ctx := context.Background()
	blobKey, _, err := s.backend.blob.Put(ctx, counted, nil)
	if err != nil {
		return &smtp.SMTPError{Code: 554, Message: "Transaction failed"}
	}

	// Size check after the fact.
	size := counted.n
	if size > s.backend.cfg.MaxMessageSize {
		_ = s.backend.blob.Delete(ctx, blobKey)
		return &smtp.SMTPError{
			Code:    552,
			Message: fmt.Sprintf("Message too large (max %d bytes)", s.backend.cfg.MaxMessageSize),
		}
	}

	// Batch user lookup in one query.
	localUsers, err := storage.GetUsersByEmail(ctx, s.backend.db, s.recipients)
	if err != nil {
		localUsers = make(map[string]*storage.User)
	}

	// For each local recipient, insert into their INBOX.
	for _, rcpt := range s.recipients {
		user, ok := localUsers[rcpt]
		if !ok {
			continue
		}
		mbox, err := storage.GetMailbox(ctx, s.backend.db, user.ID, "INBOX")
		if err != nil {
			continue
		}
		_, _, err = storage.InsertMessage(ctx, s.backend.db, mbox.ID, blobKey,
			size, fromAddr, rcpt, subject, 0)
		if err != nil {
			continue
		}
	}

	// For recipients not found locally: enqueue for outbound delivery
	// or generate NDR for local-domain recipients without a mailbox.
	for _, rcpt := range s.recipients {
		if _, ok := localUsers[rcpt]; ok {
			continue
		}
		parts := strings.SplitN(rcpt, "@", 2)
		if len(parts) != 2 {
			continue
		}
		domain := parts[1]

		if s.isLocalDomain(domain) {
			// Local domain but no mailbox -- generate NDR bounce.
			ndrBytes := generateNDR(s.backend.cfg.Hostname, s.from, rcpt)
			ndrKey, ndrSize, err := s.backend.blob.Put(ctx, bytes.NewReader(ndrBytes), nil)
			if err != nil {
				continue
			}
			ndrMsgID, _, err := enqueueOutbound(ctx, s, ndrKey, "",
				s.from, "Undelivered Mail Returned to Sender", ndrSize)
			if err != nil {
				continue
			}
			if err := s.backend.queue.Enqueue(ndrMsgID, s.from); err != nil {
				continue
			}
			s.backend.metrics.MessagesBounced.Inc()
		} else {
			// Remote domain -- enqueue for outbound delivery.
			msgID, _, err := enqueueOutbound(ctx, s, blobKey, fromAddr, rcpt, subject, size)
			if err != nil {
				continue
			}
			if err := s.backend.queue.Enqueue(msgID, rcpt); err != nil {
				continue
			}
		}
	}

	s.backend.metrics.MessagesReceived.Inc()
	return nil
}

// enqueueOutbound creates a message record for outbound delivery.
func enqueueOutbound(ctx context.Context, s *Session, blobKey, from, rcpt, subject string, size int64) (int64, uint32, error) {
	mbox, err := storage.GetMailbox(ctx, s.backend.db, 0, "OUTBOUND")
	if err != nil {
		return 0, 0, err
	}
	return storage.InsertMessage(ctx, s.backend.db, mbox.ID, blobKey,
		size, from, rcpt, subject, 0)
}

// Reset clears the transaction state.
func (s *Session) Reset() {
	s.from = ""
	s.recipients = nil
}

// Logout cleans up when the session ends.
func (s *Session) Logout() error {
	s.backend.metrics.ActiveConnections.Dec()
	return nil
}

func (s *Session) isLocalDomain(domain string) bool {
	return s.backend.cfg.Hostname == domain
}

func parseMessageHeaders(data []byte) (from, to, subject string) {
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return "", "", ""
	}
	return msg.Header.Get("From"), msg.Header.Get("To"), msg.Header.Get("Subject")
}

// countingReader wraps io.Reader, counting bytes read.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// readHeaders reads from a bufio.Reader up to the header terminator "\r\n\r\n".
// Returns all bytes read (headers + blank line). Max 64KB to bound memory.
func readHeaders(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	maxHeaders := 64 << 10 // 64KB
	for len(buf) < maxHeaders {
		line, err := r.ReadBytes('\n')
		buf = append(buf, line...)
		if err != nil {
			if err == io.EOF {
				return buf, nil
			}
			return nil, err
		}
		if len(line) == 2 && line[0] == '\r' && line[1] == '\n' {
			return buf, nil
		}
	}
	return buf, nil
}

// generateNDR creates a standard plain-text bounce/NDR message.
func generateNDR(hostname, originalFrom, originalTo string) []byte {
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("From: MAILER-DAEMON@%s\r\n", hostname))
	buf.WriteString(fmt.Sprintf("To: %s\r\n", originalFrom))
	buf.WriteString("Subject: Undelivered Mail Returned to Sender\r\n")
	buf.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	buf.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	buf.WriteString("\r\n")
	buf.WriteString(fmt.Sprintf("Your message to %s could not be delivered.\r\n", originalTo))
	buf.WriteString("\r\n")
	buf.WriteString("The recipient mailbox does not exist on this server.\r\n")
	return buf.Bytes()
}
