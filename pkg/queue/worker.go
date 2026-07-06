package queue

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/i-got-this-faa/marco/pkg/storage"
)

// worker runs the delivery loop for a single goroutine.
func (m *Manager) worker(ctx context.Context) {
	defer m.wg.Done()
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.deliverNext(ctx)
		}
	}
}

// deliverNext claims one pending queue item and attempts delivery.
func (m *Manager) deliverNext(ctx context.Context) {
	item, err := storage.ClaimNext(ctx, m.db)
	if err != nil {
		m.log.Error("claim failed", "error", err)
		return
	}
	if item == nil {
		return // nothing to do
	}

	m.log.Debug("delivering", "queue_id", item.ID, "rcpt", item.RcptTo)

	// 1. Look up message to get blob key and envelope from.
	msg, err := storage.GetMessageByID(ctx, m.db, item.MessageID)
	if err != nil {
		m.log.Error("get message failed", "queue_id", item.ID, "error", err)
		_ = storage.Fail(ctx, m.db, item.ID, nextAttempt(item.AttemptCount), m.maxRetries)
		return
	}

	// 2. Read message blob into memory (we need it for DKIM and multiple MX attempts).
	rc, err := m.blob.Get(ctx, msg.BlobKey)
	if err != nil {
		m.log.Error("get blob failed", "queue_id", item.ID, "blob_key", msg.BlobKey, "error", err)
		if ferr := storage.Fail(ctx, m.db, item.ID, nextAttempt(item.AttemptCount), m.maxRetries); ferr != nil {
			m.log.Error("requeue failed", "error", ferr)
		}
		return
	}
	raw, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		m.log.Error("read blob failed", "error", err)
		_ = storage.Fail(ctx, m.db, item.ID, nextAttempt(item.AttemptCount), m.maxRetries)
		return
	}

	// 3. DKIM sign if configured.
	var msgData []byte
	if m.dkim != nil {
		signed, err := m.dkim.Sign(ctx, bytes.NewReader(raw))
		if err != nil {
			m.log.Warn("dkim sign failed", "error", err)
			msgData = raw
		} else {
			msgData = signed
		}
	} else {
		msgData = raw
	}

	// 4. Extract recipient domain.
	parts := strings.SplitN(item.RcptTo, "@", 2)
	if len(parts) != 2 {
		m.log.Error("invalid recipient address", "rcpt", item.RcptTo)
		_ = storage.Fail(ctx, m.db, item.ID, nextAttempt(item.AttemptCount), m.maxRetries)
		return
	}
	domain := parts[1]

	// 5. MX lookup.
	mxes, err := net.LookupMX(domain)
	if err != nil || len(mxes) == 0 {
		m.log.Error("mx lookup failed", "domain", domain, "error", err)
		ferr := storage.Fail(ctx, m.db, item.ID, nextAttempt(item.AttemptCount), m.maxRetries)
		if errors.Is(ferr, storage.ErrMaxRetries) {
			reason := "mx lookup failed"
			if err != nil {
				reason += ": " + err.Error()
			}
			_ = m.BounceMessage(msg.FromAddr, item.RcptTo, reason, nil)
		}
		return
	}

	// 6. Try each MX (sorted by priority, lowest first).
	var lastErr error
	for _, mx := range mxes {
		lastErr = deliverToMX(bytes.NewReader(msgData), mx.Host, msg.FromAddr, item.RcptTo, m.ipVersion)
		if lastErr == nil {
			// Success.
			if cerr := storage.Complete(ctx, m.db, item.ID); cerr != nil {
				m.log.Error("complete failed", "queue_id", item.ID, "error", cerr)
			}
			m.metrics.QueuePending.Dec()
			m.metrics.MessagesDelivered.Inc()
			m.log.Info("delivered", "queue_id", item.ID, "rcpt", item.RcptTo, "mx", mx.Host)
			return
		}
		m.log.Warn("delivery attempt failed", "mx", mx.Host, "error", lastErr)
	}

	// All MX attempts failed.
	m.log.Error("delivery failed", "queue_id", item.ID, "rcpt", item.RcptTo, "error", lastErr)
	ferr := storage.Fail(ctx, m.db, item.ID, nextAttempt(item.AttemptCount), m.maxRetries)
	if errors.Is(ferr, storage.ErrMaxRetries) {
		_ = m.BounceMessage(msg.FromAddr, item.RcptTo, "delivery failed: "+lastErr.Error(), nil)
	} else if ferr != nil {
		m.log.Error("requeue failed", "error", ferr)
	}
}

// deliverToMX connects to a remote MX server and delivers a message.
func deliverToMX(r io.Reader, mxHost, mailFrom, rcptTo, ipVersion string) error {
	conn, err := dialForIPVersion(mxHost, "25", ipVersion, 30*time.Second)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	c, err := smtp.NewClient(conn, mxHost)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	// HELO
	parts := strings.SplitN(mailFrom, "@", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid mail from address: %s", mailFrom)
	}
	heloDomain := parts[1]
	if err := c.Hello(heloDomain); err != nil {
		return fmt.Errorf("helo: %w", err)
	}

	// STARTTLS — upgrade to encrypted connection if the server supports it.
	if ok, _ := c.Extension("STARTTLS"); ok {
		tlsCfg := &tls.Config{
			ServerName: mxHost,
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
		// Re-EHLO on the encrypted channel; some servers require it.
		if err := c.Hello(heloDomain); err != nil {
			return fmt.Errorf("helo after starttls: %w", err)
		}
	}

	// MAIL FROM
	if err := c.Mail(mailFrom); err != nil {
		return fmt.Errorf("mail from: %w", err)
	}

	// RCPT TO
	if err := c.Rcpt(rcptTo); err != nil {
		return fmt.Errorf("rcpt to: %w", err)
	}

	// DATA
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("data: %w", err)
	}
	if _, err := io.Copy(w, r); err != nil {
		return fmt.Errorf("copy: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close data: %w", err)
	}

	return c.Quit()
}

// dialForIPVersion resolves mxHost to IP addresses filtered by the preferred
// IP version and dials each until one succeeds.
// ipVersion "ipv4" resolves to A records only, "ipv6" to AAAA only,
// any other value falls back to Go's default dual-stack dial.
func dialForIPVersion(mxHost, port, ipVersion string, timeout time.Duration) (net.Conn, error) {
	if ipVersion == "" || ipVersion == "any" {
		return net.DialTimeout("tcp", net.JoinHostPort(mxHost, port), timeout)
	}

	// Resolve hostname to IPs.
	ips, err := net.DefaultResolver.LookupHost(context.Background(), mxHost)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", mxHost, err)
	}

	wantV4 := ipVersion == "ipv4"
	var dialErrs []error
	for _, ipStr := range ips {
		parsed := net.ParseIP(ipStr)
		if parsed == nil {
			continue
		}
		isV4 := parsed.To4() != nil
		if isV4 != wantV4 {
			continue
		}

		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ipStr, port), timeout)
		if err == nil {
			return conn, nil
		}
		dialErrs = append(dialErrs, err)
	}

	if len(dialErrs) > 0 {
		return nil, dialErrs[0]
	}
	return nil, fmt.Errorf("no %s addresses found for %s", ipVersion, mxHost)
}

// nextAttempt computes the next attempt time based on backoff schedule.
func nextAttempt(attempt int) time.Time {
	delays := []time.Duration{
		1 * time.Minute,
		5 * time.Minute,
		15 * time.Minute,
		1 * time.Hour,
		4 * time.Hour,
		12 * time.Hour,
		24 * time.Hour,
	}
	if attempt >= len(delays) {
		return time.Now().Add(24 * time.Hour)
	}
	return time.Now().Add(delays[attempt])
}
