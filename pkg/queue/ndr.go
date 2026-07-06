package queue

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/i-got-this-faa/marco/pkg/storage"
)

// GenerateNDR creates a non-delivery report (bounce) message body.
func GenerateNDR(originalFrom, originalTo, reason string, originalMsg []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("From: MAILER-DAEMON\r\n")
	buf.WriteString(fmt.Sprintf("To: %s\r\n", originalFrom))
	buf.WriteString(fmt.Sprintf("Subject: Mail delivery failed: %s\r\n", reason))
	buf.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	buf.WriteString("MIME-Version: 1.0\r\n")
	buf.WriteString("Content-Type: multipart/report; report-type=delivery-status; boundary=ndrboundary\r\n")
	buf.WriteString("\r\n")
	buf.WriteString("--ndrboundary\r\n")
	buf.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	buf.WriteString("\r\n")
	buf.WriteString(fmt.Sprintf("Your message to %s could not be delivered.\n", originalTo))
	buf.WriteString(fmt.Sprintf("Reason: %s\n\n", reason))
	buf.WriteString("--ndrboundary\r\n")
	buf.WriteString("Content-Type: message/delivery-status\r\n")
	buf.WriteString("\r\n")
	buf.WriteString("Original-Recipient: " + originalTo + "\r\n")
	buf.WriteString(fmt.Sprintf("Diagnostic-Code: smtp; %s\r\n", reason))
	buf.WriteString("Action: failed\r\n")
	buf.WriteString("Status: 5.0.0\r\n")
	buf.WriteString("\r\n")
	buf.WriteString("--ndrboundary\r\n")
	buf.WriteString("Content-Type: message/rfc822\r\n")
	buf.WriteString("\r\n")
	if len(originalMsg) > 0 {
		buf.Write(originalMsg)
	} else {
		buf.WriteString("Original message not available\r\n")
	}
	buf.WriteString("\r\n--ndrboundary--\r\n")
	return buf.Bytes()
}

// BounceMessage creates a bounce message and stores it in the sender's mailbox.
func (m *Manager) BounceMessage(originalFrom, originalTo, reason string, originalMsg []byte) error {
	ndr := GenerateNDR(originalFrom, originalTo, reason, originalMsg)

	ctx := context.Background()
	blobKey, _, err := m.blob.Put(ctx, bytes.NewReader(ndr), nil)
	if err != nil {
		return fmt.Errorf("queue: bounce store blob: %w", err)
	}

	user, err := storage.GetUserByEmail(ctx, m.db, originalFrom)
	if err != nil {
		m.log.Warn("bounce sender not found locally", "from", originalFrom)
		return nil
	}

	mbox, err := storage.GetMailbox(ctx, m.db, user.ID, "INBOX")
	if err != nil {
		return fmt.Errorf("queue: bounce get inbox: %w", err)
	}

	_, _, err = storage.InsertMessage(ctx, m.db, mbox.ID, blobKey,
		int64(len(ndr)), "", originalFrom,
		fmt.Sprintf("Mail delivery failed: %s", reason), 0)
	if err != nil {
		return fmt.Errorf("queue: bounce insert: %w", err)
	}

	m.metrics.MessagesBounced.Inc()
	m.log.Info("bounce sent", "from", originalFrom, "to", originalTo, "reason", reason)
	return nil
}
