package marco

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/emersion/go-msgauth/dmarc"
	"github.com/i-got-this-faa/marco/pkg/config"
	"github.com/i-got-this-faa/marco/pkg/storage"
)

// AuditResult holds a single check result.
type AuditResult struct {
	Check   string
	Status  string // "PASS", "FAIL", "WARN"
	Message string
}

// Audit runs a series of health and configuration checks and returns the results.
func Audit(cfgPath string) []AuditResult {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return []AuditResult{{
			Check: "config-load", Status: "FAIL",
			Message: fmt.Sprintf("Cannot load config: %v", err),
		}}
	}

	var results []AuditResult

	results = append(results, auditConfig(cfg)...)
	results = append(results, auditDNS(cfg)...)
	results = append(results, auditDatabase(cfg)...)
	results = append(results, auditBlobStore(cfg)...)
	results = append(results, auditStorageHealth(cfg)...)

	return results
}

// ---------------------------------------------------------------------------
// Config checks
// ---------------------------------------------------------------------------

func auditConfig(cfg *config.Config) []AuditResult {
	var results []AuditResult

	if cfg.Hostname == "" {
		results = append(results, AuditResult{"hostname", "FAIL", "Hostname is not set"})
	} else {
		results = append(results, AuditResult{"hostname", "PASS", cfg.Hostname})
	}

	// IP version.
	switch cfg.IPVersion {
	case "any":
		results = append(results, AuditResult{"ip-version", "PASS", "Dual-stack (IPv4 + IPv6)"})
	case "ipv4":
		results = append(results, AuditResult{"ip-version", "PASS", "IPv4 only"})
	case "ipv6":
		results = append(results, AuditResult{"ip-version", "PASS", "IPv6 only"})
	default:
		results = append(results, AuditResult{"ip-version", "FAIL", fmt.Sprintf("Invalid: %q", cfg.IPVersion)})
	}

	if cfg.Storage.Path == "" {
		results = append(results, AuditResult{"db-path", "FAIL", "Database path is not set"})
	} else {
		if fi, err := os.Stat(cfg.Storage.Path); err == nil {
			if fi.Size() == 0 {
				results = append(results, AuditResult{"db-path", "WARN", fmt.Sprintf("Database file exists but is empty: %s", cfg.Storage.Path)})
			} else {
				results = append(results, AuditResult{"db-path", "PASS", fmt.Sprintf("%s (%d bytes)", cfg.Storage.Path, fi.Size())})
			}
		} else if os.IsNotExist(err) {
			results = append(results, AuditResult{"db-path", "WARN", "Database file does not exist yet (will be created on first run)"})
		} else {
			results = append(results, AuditResult{"db-path", "FAIL", fmt.Sprintf("Cannot stat: %v", err)})
		}
	}

	if cfg.Storage.BlobBackend == "filesystem" {
		if cfg.Storage.BlobPath == "" {
			results = append(results, AuditResult{"blob-path", "FAIL", "Blob path is not set"})
		} else if fi, err := os.Stat(cfg.Storage.BlobPath); err == nil {
			if fi.IsDir() {
				results = append(results, AuditResult{"blob-path", "PASS", cfg.Storage.BlobPath})
			} else {
				results = append(results, AuditResult{"blob-path", "FAIL", "Blob path is not a directory"})
			}
		} else {
			results = append(results, AuditResult{"blob-path", "WARN", fmt.Sprintf("Blob path does not exist (will be created): %s", cfg.Storage.BlobPath)})
		}
	} else {
		results = append(results, AuditResult{"blob-backend", "PASS", cfg.Storage.BlobBackend})
	}

	// Listeners.
	checkListenAddr := func(name, addr string) {
		if addr == "" {
			results = append(results, AuditResult{name, "WARN", "Not configured"})
			return
		}
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			results = append(results, AuditResult{name, "FAIL", fmt.Sprintf("Invalid address %q: %v", addr, err)})
			return
		}
		priv := port == "25" || port == "465" || port == "587"
		if priv && cfg.IPVersion == "ipv4" {
			results = append(results, AuditResult{name, "WARN", fmt.Sprintf("Port %s on IPv4 may be blocked by ISP", port)})
		} else {
			results = append(results, AuditResult{name, "PASS", fmt.Sprintf("Listening on %s", addr)})
		}
	}
	checkListenAddr("smtp", cfg.SMTP.ListenAddr)
	checkListenAddr("smtp-submission", cfg.SMTP.SubmissionAddr)
	checkListenAddr("smtp-submissions", cfg.SMTP.SubmissionsAddr)
	checkListenAddr("imap", cfg.IMAP.ListenAddr)
	checkListenAddr("imaps", cfg.IMAP.ImapsAddr)
	checkListenAddr("admin-api", cfg.Admin.ListenAddr)

	// DKIM.
	if cfg.DKIM.Domain != "" && cfg.DKIM.Selector != "" {
		results = append(results, AuditResult{"dkim", "PASS", fmt.Sprintf("Domain=%s Selector=%s", cfg.DKIM.Domain, cfg.DKIM.Selector)})
		if cfg.DKIM.PrivateKeyPath != "" {
			if _, err := os.Stat(cfg.DKIM.PrivateKeyPath); err == nil {
				results = append(results, AuditResult{"dkim-key", "PASS", cfg.DKIM.PrivateKeyPath})
			} else {
				results = append(results, AuditResult{"dkim-key", "FAIL", fmt.Sprintf("Key file not found: %s", cfg.DKIM.PrivateKeyPath)})
			}
		} else {
			results = append(results, AuditResult{"dkim-key", "WARN", "Private key path not configured"})
		}
	} else {
		results = append(results, AuditResult{"dkim", "WARN", "DKIM not configured"})
	}

	// TLS.
	if cfg.TLS.CertFile != "" && cfg.TLS.KeyFile != "" {
		if _, err := os.Stat(cfg.TLS.CertFile); err == nil {
			results = append(results, AuditResult{"tls-cert", "PASS", cfg.TLS.CertFile})
		} else {
			results = append(results, AuditResult{"tls-cert", "FAIL", fmt.Sprintf("Not found: %s", cfg.TLS.CertFile)})
		}
		if _, err := os.Stat(cfg.TLS.KeyFile); err == nil {
			results = append(results, AuditResult{"tls-key", "PASS", cfg.TLS.KeyFile})
		} else {
			results = append(results, AuditResult{"tls-key", "FAIL", fmt.Sprintf("Not found: %s", cfg.TLS.KeyFile)})
		}
	} else if cfg.ACME.Enabled {
		results = append(results, AuditResult{"tls", "PASS", "Using ACME (Let's Encrypt)"})
	} else {
		results = append(results, AuditResult{"tls", "WARN", "TLS not configured (insecure without encryption)"})
	}

	// ACME.
	if cfg.ACME.Enabled {
		if cfg.ACME.Email == "" {
			results = append(results, AuditResult{"acme-email", "FAIL", "Email required for ACME registration"})
		} else {
			results = append(results, AuditResult{"acme-email", "PASS", cfg.ACME.Email})
		}
		if len(cfg.ACME.Domains) == 0 {
			results = append(results, AuditResult{"acme-domains", "WARN", "No domains configured for ACME"})
		} else {
			results = append(results, AuditResult{"acme-domains", "PASS", strings.Join(cfg.ACME.Domains, ", ")})
		}
	}

	// Queue.
	if cfg.Queue.Workers <= 0 {
		results = append(results, AuditResult{"queue-workers", "FAIL", fmt.Sprintf("Workers must be > 0, got %d", cfg.Queue.Workers)})
	} else {
		results = append(results, AuditResult{"queue-workers", "PASS", fmt.Sprintf("%d workers", cfg.Queue.Workers)})
	}
	if cfg.Queue.MaxRetries <= 0 {
		results = append(results, AuditResult{"queue-retries", "FAIL", fmt.Sprintf("MaxRetries must be > 0, got %d", cfg.Queue.MaxRetries)})
	} else {
		results = append(results, AuditResult{"queue-retries", "PASS", fmt.Sprintf("%d max retries", cfg.Queue.MaxRetries)})
	}

	// Auth session expiry.
	if cfg.Auth.SessionExpiry <= 0 {
		results = append(results, AuditResult{"session-expiry", "FAIL", "Session expiry must be positive"})
	} else {
		results = append(results, AuditResult{"session-expiry", "PASS", cfg.Auth.SessionExpiry.String()})
	}

	return results
}

// ---------------------------------------------------------------------------
// DNS checks
// ---------------------------------------------------------------------------

func auditDNS(cfg *config.Config) []AuditResult {
	var results []AuditResult
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r := net.DefaultResolver

	hostname := cfg.Hostname
	if hostname == "" {
		return []AuditResult{{"dns", "FAIL", "Hostname not set, skipping DNS checks"}}
	}

	// A/AAAA resolution.
	ips, err := r.LookupHost(ctx, hostname)
	if err != nil {
		results = append(results, AuditResult{"dns-a", "FAIL", fmt.Sprintf("Cannot resolve %s: %v", hostname, err)})
	} else {
		var v4, v6 int
		for _, ip := range ips {
			if net.ParseIP(ip).To4() != nil {
				v4++
			} else {
				v6++
			}
		}
		msg := fmt.Sprintf("%s resolves to %d IPv4, %d IPv6", hostname, v4, v6)
		if v4 == 0 && v6 == 0 {
			results = append(results, AuditResult{"dns-a", "FAIL", msg})
		} else if cfg.IPVersion == "ipv6" && v6 == 0 {
			results = append(results, AuditResult{"dns-a", "WARN", msg + " (no AAAA record for IPv6-only mode)"})
		} else if cfg.IPVersion == "ipv4" && v4 == 0 {
			results = append(results, AuditResult{"dns-a", "WARN", msg + " (no A record for IPv4-only mode)"})
		} else {
			results = append(results, AuditResult{"dns-a", "PASS", msg})
		}
	}

	// MX records.
	mxes, err := r.LookupMX(ctx, hostname)
	if err != nil {
		results = append(results, AuditResult{"dns-mx", "FAIL", fmt.Sprintf("MX lookup for %s: %v", hostname, err)})
	} else if len(mxes) == 0 {
		results = append(results, AuditResult{"dns-mx", "FAIL", fmt.Sprintf("No MX records for %s (mail will not be delivered)", hostname)})
	} else {
		var mxDescs []string
		for _, mx := range mxes {
			mxDescs = append(mxDescs, fmt.Sprintf("%s (priority %d)", mx.Host, mx.Pref))
		}
		results = append(results, AuditResult{"dns-mx", "PASS", strings.Join(mxDescs, ", ")})
	}

	// PTR / reverse DNS for the first resolved IP.
	if len(ips) > 0 {
		ptrIP := ips[0]
		ptrs, err := r.LookupAddr(ctx, ptrIP)
		if err != nil {
			results = append(results, AuditResult{"dns-ptr", "WARN", fmt.Sprintf("No PTR record for %s: %v", ptrIP, err)})
		} else if len(ptrs) == 0 {
			results = append(results, AuditResult{"dns-ptr", "WARN", fmt.Sprintf("No PTR record for %s", ptrIP)})
		} else {
			match := false
			for _, ptr := range ptrs {
				if strings.TrimSuffix(ptr, ".") == hostname {
					match = true
					break
				}
			}
			if match {
				results = append(results, AuditResult{"dns-ptr", "PASS", fmt.Sprintf("%s → %s", ptrIP, strings.Join(ptrs, ", "))})
			} else {
				results = append(results, AuditResult{"dns-ptr", "WARN", fmt.Sprintf("%s → %s (does not match hostname %s)", ptrIP, strings.Join(ptrs, ", "), hostname)})
			}
		}
	}

	// SPF record.
	txts, err := r.LookupTXT(ctx, hostname)
	if err != nil {
		results = append(results, AuditResult{"dns-spf", "FAIL", fmt.Sprintf("TXT lookup for %s: %v", hostname, err)})
	} else {
		found := false
		for _, txt := range txts {
			if strings.HasPrefix(txt, "v=spf1") {
				results = append(results, AuditResult{"dns-spf", "PASS", txt})
				found = true
				break
			}
		}
		if !found {
			results = append(results, AuditResult{"dns-spf", "WARN", fmt.Sprintf("No SPF record for %s", hostname)})
		}
	}

	// DKIM DNS record (if configured).
	if cfg.DKIM.Domain != "" && cfg.DKIM.Selector != "" {
		dkimDomain := cfg.DKIM.Selector + "._domainkey." + cfg.DKIM.Domain
		dkimTxts, err := r.LookupTXT(ctx, dkimDomain)
		if err != nil {
			results = append(results, AuditResult{"dns-dkim", "FAIL", fmt.Sprintf("DKIM lookup %s: %v", dkimDomain, err)})
		} else {
			found := false
			for _, txt := range dkimTxts {
				if strings.HasPrefix(txt, "v=DKIM1") {
					results = append(results, AuditResult{"dns-dkim", "PASS", fmt.Sprintf("DKIM record found at %s", dkimDomain)})
					found = true
					break
				}
			}
			if !found {
				results = append(results, AuditResult{"dns-dkim", "FAIL", fmt.Sprintf("No DKIM record at %s (found %d TXT records)", dkimDomain, len(dkimTxts))})
			}
		}
	}

	// DMARC record.
	dmarcDomain := "_dmarc." + hostname
	dmarcTxts, err := r.LookupTXT(ctx, dmarcDomain)
	if err != nil {
		results = append(results, AuditResult{"dns-dmarc", "WARN", fmt.Sprintf("DMARC lookup %s: %v", dmarcDomain, err)})
	} else {
		found := false
		for _, txt := range dmarcTxts {
			if strings.HasPrefix(txt, "v=DMARC1") {
				record, err := dmarc.Parse(txt)
				if err != nil {
					results = append(results, AuditResult{"dns-dmarc", "FAIL", fmt.Sprintf("Invalid DMARC record: %v", err)})
					found = true
					break
				}
				pct := "<nil>"
				if record.Percent != nil {
					pct = fmt.Sprintf("%d%%", *record.Percent)
				}
				rua := strings.Join(record.ReportURIAggregate, ", ")
				if rua == "" {
					rua = "none"
				}
				results = append(results, AuditResult{"dns-dmarc", "PASS", fmt.Sprintf("Policy=%s pct=%s rua=%s", record.Policy, pct, rua)})
				found = true
				break
			}
		}
		if !found {
			results = append(results, AuditResult{"dns-dmarc", "WARN", fmt.Sprintf("No DMARC record at %s", dmarcDomain)})
		}
	}

	return results
}

// ---------------------------------------------------------------------------
// Database checks
// ---------------------------------------------------------------------------

func auditDatabase(cfg *config.Config) []AuditResult {
	db, err := storage.Open(cfg.Storage.Path)
	if err != nil {
		return []AuditResult{{"db-connect", "FAIL", fmt.Sprintf("Cannot open database: %v", err)}}
	}
	defer db.Close()

	var results []AuditResult
	results = append(results, AuditResult{"db-connect", "PASS", "Database opened successfully"})

	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		results = append(results, AuditResult{"db-version", "FAIL", fmt.Sprintf("Cannot read schema version: %v", err)})
	} else {
		if version > 0 {
			results = append(results, AuditResult{"db-version", "PASS", fmt.Sprintf("Schema version %d", version)})
		} else {
			results = append(results, AuditResult{"db-version", "WARN", "Schema version 0 (database may be empty)"})
		}
	}

	var userCount int
	_ = db.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount)
	results = append(results, AuditResult{"users", "PASS", fmt.Sprintf("%d users", userCount)})

	var domainCount int
	_ = db.QueryRow("SELECT COUNT(*) FROM domains").Scan(&domainCount)
	results = append(results, AuditResult{"domains", "PASS", fmt.Sprintf("%d domains", domainCount)})

	var aliasCount int
	_ = db.QueryRow("SELECT COUNT(*) FROM aliases").Scan(&aliasCount)
	results = append(results, AuditResult{"aliases", "PASS", fmt.Sprintf("%d aliases", aliasCount)})

	var mailboxCount int
	_ = db.QueryRow("SELECT COUNT(*) FROM mailboxes").Scan(&mailboxCount)
	results = append(results, AuditResult{"mailboxes", "PASS", fmt.Sprintf("%d mailboxes", mailboxCount)})

	var msgCount int
	_ = db.QueryRow("SELECT COUNT(*) FROM messages").Scan(&msgCount)
	results = append(results, AuditResult{"messages", "PASS", fmt.Sprintf("%d messages", msgCount)})

	var queueCount int
	_ = db.QueryRow("SELECT COUNT(*) FROM queue WHERE status='pending'").Scan(&queueCount)
	results = append(results, AuditResult{"queue-pending", "PASS", fmt.Sprintf("%d pending", queueCount)})

	var blobCount int
	_ = db.QueryRow("SELECT COUNT(*) FROM blobs").Scan(&blobCount)
	results = append(results, AuditResult{"blobs", "PASS", fmt.Sprintf("%d blobs", blobCount)})

	return results
}

// ---------------------------------------------------------------------------
// Blob store integrity
// ---------------------------------------------------------------------------

func auditBlobStore(cfg *config.Config) []AuditResult {
	ctx := context.Background()
	db, err := storage.Open(cfg.Storage.Path)
	if err != nil {
		return []AuditResult{{"blob-check", "FAIL", fmt.Sprintf("Cannot open database for blob check: %v", err)}}
	}
	defer db.Close()

	var results []AuditResult

	// Orphaned blob references (messages referencing blobs that don't exist).
	rows, err := db.QueryContext(ctx, `
		SELECT DISTINCT m.blob_key FROM messages m
		LEFT JOIN blobs b ON m.blob_key = b.key
		WHERE b.key IS NULL
	`)
	if err != nil {
		results = append(results, AuditResult{"blob-orphans", "FAIL", fmt.Sprintf("Query failed: %v", err)})
		return results
	}
	defer rows.Close()

	var orphanCount int
	for rows.Next() {
		orphanCount++
	}
	if orphanCount > 0 {
		results = append(results, AuditResult{"blob-orphans", "FAIL", fmt.Sprintf("%d orphaned blob references found", orphanCount)})
	} else {
		results = append(results, AuditResult{"blob-orphans", "PASS", "No orphaned blob references"})
	}

	return results
}

// ---------------------------------------------------------------------------
// Storage health checks
// ---------------------------------------------------------------------------

func auditStorageHealth(cfg *config.Config) []AuditResult {
	db, err := storage.Open(cfg.Storage.Path)
	if err != nil {
		return []AuditResult{{"storage-health", "FAIL", fmt.Sprintf("Cannot open database: %v", err)}}
	}
	defer db.Close()

	var results []AuditResult
	ctx := context.Background()

	// Expired sessions.
	var expiredSessions int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE expires_at < ?`, time.Now().Unix()).Scan(&expiredSessions); err != nil {
		results = append(results, AuditResult{"expired-sessions", "WARN", fmt.Sprintf("Cannot check: %v", err)})
	} else if expiredSessions > 0 {
		results = append(results, AuditResult{"expired-sessions", "WARN", fmt.Sprintf("%d expired sessions (consider running session cleanup)", expiredSessions)})
	} else {
		results = append(results, AuditResult{"expired-sessions", "PASS", "No expired sessions"})
	}

	// Stuck queue items (in 'failed' or 'delivering' state for too long).
	var stuck int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM queue WHERE status NOT IN ('pending','complete') AND attempt_count >= ?`, 3).Scan(&stuck); err != nil {
		results = append(results, AuditResult{"stuck-queue", "WARN", fmt.Sprintf("Cannot check: %v", err)})
	} else if stuck > 0 {
		results = append(results, AuditResult{"stuck-queue", "WARN", fmt.Sprintf("%d stuck queue items (attempted 3+ times)", stuck)})
	} else {
		results = append(results, AuditResult{"stuck-queue", "PASS", "No stuck queue items"})
	}

	// Messages without blobs (just in case blob_orphans missed something).
	var missing int
	if err := db.QueryRowContext(ctx, `
	SELECT COUNT(*) FROM messages m
	WHERE NOT EXISTS (SELECT 1 FROM blobs b WHERE b.key = m.blob_key)
	`).Scan(&missing); err != nil {
		results = append(results, AuditResult{"missing-blobs", "WARN", fmt.Sprintf("Cannot check: %v", err)})
	} else if missing > 0 {
		results = append(results, AuditResult{"missing-blobs", "FAIL", fmt.Sprintf("%d messages reference missing blobs", missing)})
	} else {
		results = append(results, AuditResult{"missing-blobs", "PASS", "All messages have blob data"})
	}

	// Attachment consistency (blobs referenced by attachments but missing).
	var orphanedAttachments int
	if err := db.QueryRowContext(ctx, `
	SELECT COUNT(*) FROM attachments a
	LEFT JOIN blobs b ON a.blob_key = b.key
	WHERE b.key IS NULL
	`).Scan(&orphanedAttachments); err != nil {
		results = append(results, AuditResult{"orphan-attachments", "WARN", fmt.Sprintf("Cannot check: %v", err)})
	} else if orphanedAttachments > 0 {
		results = append(results, AuditResult{"orphan-attachments", "FAIL", fmt.Sprintf("%d orphaned attachment blobs", orphanedAttachments)})
	} else {
		results = append(results, AuditResult{"orphan-attachments", "PASS", "No orphaned attachments"})
	}

	return results
}
