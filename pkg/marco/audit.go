package marco

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/i-got-this-faa/marco/pkg/config"
	"github.com/i-got-this-faa/marco/pkg/storage"
)

// AuditResult holds a single check result.
type AuditResult struct {
	Check   string
	Status string // "PASS", "FAIL", "WARN"
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
	results = append(results, auditDatabase(cfg)...)
	results = append(results, auditBlobStore(cfg)...)

	return results
}

func auditConfig(cfg *config.Config) []AuditResult {
	var results []AuditResult

	if cfg.Hostname == "" {
		results = append(results, AuditResult{"hostname", "FAIL", "Hostname is not set"})
	} else {
		results = append(results, AuditResult{"hostname", "PASS", cfg.Hostname})
	}

	if cfg.Storage.Path == "" {
		results = append(results, AuditResult{"db-path", "FAIL", "Database path is not set"})
	} else {
		if _, err := os.Stat(cfg.Storage.Path); err == nil {
			results = append(results, AuditResult{"db-path", "PASS", cfg.Storage.Path})
		} else {
			results = append(results, AuditResult{"db-path", "FAIL", fmt.Sprintf("Database file not found: %s", cfg.Storage.Path)})
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
	}

	if cfg.SMTP.ListenAddr != "" {
		results = append(results, checkPort("smtp", cfg.SMTP.ListenAddr))
	}
	if cfg.IMAP.ListenAddr != "" {
		results = append(results, checkPort("imap", cfg.IMAP.ListenAddr))
	}
	if cfg.POP3.ListenAddr != "" {
		results = append(results, checkPort("pop3", cfg.POP3.ListenAddr))
	}
	if cfg.Admin.ListenAddr != "" {
		results = append(results, checkPort("admin-api", cfg.Admin.ListenAddr))
	}

	if cfg.DKIM.Domain != "" && cfg.DKIM.Selector != "" {
		results = append(results, AuditResult{"dkim", "PASS", fmt.Sprintf("Domain=%s Selector=%s", cfg.DKIM.Domain, cfg.DKIM.Selector)})
		if cfg.DKIM.PrivateKeyPath != "" {
			if _, err := os.Stat(cfg.DKIM.PrivateKeyPath); err == nil {
				results = append(results, AuditResult{"dkim-key", "PASS", cfg.DKIM.PrivateKeyPath})
			} else {
				results = append(results, AuditResult{"dkim-key", "FAIL", fmt.Sprintf("Key file not found: %s", cfg.DKIM.PrivateKeyPath)})
			}
		}
	} else {
		results = append(results, AuditResult{"dkim", "WARN", "DKIM not configured"})
	}

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
	} else {
		results = append(results, AuditResult{"tls", "WARN", "TLS not configured"})
	}

	return results
}

func checkPort(name, addr string) AuditResult {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return AuditResult{name, "FAIL", fmt.Sprintf("Invalid address %q: %v", addr, err)}
	}
	return AuditResult{name, "PASS", fmt.Sprintf("Listening on port %s", port)}
}

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
		if version >= 5 {
			results = append(results, AuditResult{"db-version", "PASS", fmt.Sprintf("Schema version %d", version)})
		} else {
			results = append(results, AuditResult{"db-version", "WARN", fmt.Sprintf("Schema version %d (migrations may be incomplete)", version)})
		}
	}

	var userCount int
	_ = db.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount)
	results = append(results, AuditResult{"users", "PASS", fmt.Sprintf("%d users", userCount)})

	var msgCount int
	_ = db.QueryRow("SELECT COUNT(*) FROM messages").Scan(&msgCount)
	results = append(results, AuditResult{"messages", "PASS", fmt.Sprintf("%d messages", msgCount)})

	var queueCount int
	_ = db.QueryRow("SELECT COUNT(*) FROM queue WHERE status='pending'").Scan(&queueCount)
	results = append(results, AuditResult{"queue-pending", "PASS", fmt.Sprintf("%d pending", queueCount)})

	return results
}

func auditBlobStore(cfg *config.Config) []AuditResult {
	ctx := context.Background()
	db, err := storage.Open(cfg.Storage.Path)
	if err != nil {
		return []AuditResult{{"blob-check", "FAIL", fmt.Sprintf("Cannot open database for blob check: %v", err)}}
	}
	defer db.Close()

	var results []AuditResult

	// Check for orphaned blob keys (blobs referenced in messages but missing from blobs table).
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
