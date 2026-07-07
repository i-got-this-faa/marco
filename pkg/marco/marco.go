package marco

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/i-got-this-faa/marco/pkg/api"
	"github.com/i-got-this-faa/marco/pkg/auth"
	"github.com/i-got-this-faa/marco/pkg/blobstore"
	"github.com/i-got-this-faa/marco/pkg/config"
	"github.com/i-got-this-faa/marco/pkg/dkim"
	"github.com/i-got-this-faa/marco/pkg/imap"
	"github.com/i-got-this-faa/marco/pkg/metrics"
	"github.com/i-got-this-faa/marco/pkg/queue"
	"github.com/i-got-this-faa/marco/pkg/smtp"
	"github.com/i-got-this-faa/marco/pkg/storage"
	"github.com/i-got-this-faa/marco/pkg/tls"
	"github.com/i-got-this-faa/marco/pkg/pop3"
	"github.com/i-got-this-faa/marco/pkg/util"
)


// listenNetwork returns the Go network string to use for a given IP version.
// "ipv4" → "tcp4", "ipv6" → "tcp6", anything else → "tcp" (dual-stack).
func listenNetwork(ipVersion string) string {
	switch ipVersion {
	case "ipv4":
		return "tcp4"
	case "ipv6":
		return "tcp6"
	default:
		return "tcp"
	}
}

// ensureOutboundMailbox creates the system user (id=0) and OUTBOUND mailbox
// used for outbound delivery routing and NDR generation. Safe to call on
// every startup; uses INSERT OR IGNORE / id=0 override via raw SQL because
// sqlite AUTOINCREMENT still allows explicit zero ids.
func ensureOutboundMailbox(db *sql.DB) error {
	ctx := context.Background()
	// Create system user with explicit id=0 if not present.
	_, err := db.ExecContext(ctx,
		`INSERT OR IGNORE INTO users (id, email, password_hash, created_at) VALUES (0, 'system@outbound.local', '', ?)`,
		time.Now().Unix())
	if err != nil {
		return fmt.Errorf("create system user: %w", err)
	}
	// Create OUTBOUND mailbox for the system user if not present.
	_, err = storage.CreateMailbox(ctx, db, 0, "OUTBOUND")
	if err != nil && !errors.Is(err, storage.ErrAlreadyExists) {
		return fmt.Errorf("create outbound mailbox: %w", err)
	}
	return nil
}
// Run is the main entry point. It loads configuration, initializes
// all services, starts listeners, and blocks until a shutdown signal.
func Run() {
	cfg, err := config.Load(config.DefaultPath())
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	if err := util.InitLogging(cfg.Logging.Level, cfg.Logging.Format); err != nil {
		slog.Error("failed to init logging", "error", err)
		os.Exit(1)
	}

	slog.Info("marco mail server starting",
		"hostname", cfg.Hostname,
		"version", "0.1.0",
	)

	if cfg.Hostname == "" {
		slog.Error("hostname is required")
		os.Exit(1)
	}
	if cfg.Storage.Path == "" {
		slog.Error("storage path is required")
		os.Exit(1)
	}

	// Open database and run migrations.
	db, err := storage.Open(cfg.Storage.Path)
	if err != nil {
		slog.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	if err := storage.Migrate(db); err != nil {
		slog.Error("failed to run migrations", "error", err)
		os.Exit(1)
	}

	// Ensure the system user (id=0) and OUTBOUND mailbox exist
	// for outbound delivery routing and NDR generation.
	if err := ensureOutboundMailbox(db); err != nil {
		slog.Error("failed to set up outbound mailbox", "error", err)
		os.Exit(1)
	}

	// Init blob store.
	var blob blobstore.Store
	switch cfg.Storage.BlobBackend {
	case "filesystem":
		blob = blobstore.NewFSStore(cfg.Storage.BlobPath)
	case "sqlite":
		blob = blobstore.NewSQLiteStore(db)
	default:
		slog.Error("unknown blob backend", "backend", cfg.Storage.BlobBackend)
		os.Exit(1)
	}

	// Auth manager.
	am := auth.NewManager(db)

	// DKIM signer (optional).
	var dk *dkim.Signer
	if cfg.DKIM.PrivateKeyPath != "" {
		keyData, err := os.ReadFile(cfg.DKIM.PrivateKeyPath)
		if err != nil {
			slog.Error("failed to read DKIM private key", "error", err)
			os.Exit(1)
		}
		block, _ := pem.Decode(keyData)
		if block == nil {
			slog.Error("failed to decode DKIM private key PEM")
			os.Exit(1)
		}
		privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			slog.Error("failed to parse DKIM private key", "error", err)
			os.Exit(1)
		}
		signer, ok := privKey.(*rsa.PrivateKey)
		if !ok {
			slog.Error("DKIM private key is not RSA")
			os.Exit(1)
		}
		dk = dkim.NewSigner(cfg.DKIM.Domain, cfg.DKIM.Selector, signer)
	}

	// Queue manager.
	qm := queue.NewManager(db, blob, cfg.Queue.Workers, cfg.Queue.MaxRetries, cfg.Queue.Interval, cfg.IPVersion)

	// Prometheus metrics registry.
	m := metrics.NewRegistry()

	// TLS / ACME setup.
	acmeMgr, err := tls.NewACMManager(&cfg.ACME, cfg.Hostname)
	if err != nil {
		slog.Error("failed to init ACME", "error", err)
		os.Exit(1)
	}

	tlsCfg, err := tls.ServerConfig(&cfg.TLS, cfg.Hostname, acmeMgr)
	if err != nil {
		slog.Error("failed to init TLS config", "error", err)
		os.Exit(1)
	}

	// Create servers.
	smtpSrv := smtp.NewServer(&cfg.SMTP, db, blob, qm, am, dk, m, tlsCfg)
	imapBe := imap.NewBackend(db, blob, am)
	imapSrv := imap.NewServer(&cfg.IMAP, imapBe, tlsCfg)
	apiSrv := api.NewServer(&cfg.Admin, db, blob, qm, am, dk, tlsCfg, m, cfg.DKIM, cfg.DKIM.PrivateKeyPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup

	// Start queue manager workers.
	if err := qm.Start(ctx); err != nil {
		slog.Error("failed to start queue manager", "error", err)
		os.Exit(1)
	}

	// startListener creates a TCP listener and serves on it in a goroutine.
	startListener := func(name, addr string, srv interface{ Serve(net.Listener) error }) {
		if addr == "" {
			return
		}
		l, err := net.Listen(listenNetwork(cfg.IPVersion), addr)
		if err != nil {
			slog.Error("failed to listen", "service", name, "addr", addr, "error", err)
			os.Exit(1)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			slog.Info("listening", "service", name, "addr", addr)
			if err := srv.Serve(l); err != nil {
				slog.Error("serve stopped", "service", name, "error", err)
			}
		}()
	}

	// SMTP listeners (the same server handles all three).
	startListener("smtp", cfg.SMTP.ListenAddr, smtpSrv)
	startListener("smtp submission", cfg.SMTP.SubmissionAddr, smtpSrv)
	startListener("smtps", cfg.SMTP.SubmissionsAddr, smtpSrv)

	// IMAP listeners (the same server handles both).
	startListener("imap", cfg.IMAP.ListenAddr, imapSrv)
	startListener("imaps", cfg.IMAP.ImapsAddr, imapSrv)

	// POP3 listeners.
	var pop3Srv *pop3.Server
	if cfg.POP3.ListenAddr != "" || cfg.POP3.POP3sAddr != "" {
		pop3Srv = pop3.NewServer(&cfg.POP3, db, blob, am, tlsCfg)
		startListener("pop3", cfg.POP3.ListenAddr, pop3Srv)
	}
	if cfg.POP3.POP3sAddr != "" {
		// For POP3S, we need to use TLS-wrapped listener.
		// The Server.ServeTLS method wraps the listener.
		l, err := net.Listen(listenNetwork(cfg.IPVersion), cfg.POP3.POP3sAddr)
		if err != nil {
			slog.Error("failed to listen", "service", "pop3s", "addr", cfg.POP3.POP3sAddr, "error", err)
			os.Exit(1)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			slog.Info("listening", "service", "pop3s", "addr", l.Addr())
			if err := pop3Srv.ServeTLS(l); err != nil {
				slog.Error("serve stopped", "service", "pop3s", "error", err)
			}
		}()
	}


	// Admin HTTP API server (separate Serve pattern).
	if cfg.Admin.ListenAddr != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			slog.Info("listening", "service", "admin api", "addr", cfg.Admin.ListenAddr)
			if err := apiSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("serve stopped", "service", "admin api", "error", err)
			}
		}()
	}

	// ACME HTTP-01 challenge server on port 80 (respects IP version config).
	if acmeMgr != nil {
		acmeListener, err := net.Listen(listenNetwork(cfg.IPVersion), ":80")
		if err != nil {
			slog.Error("failed to listen", "service", "acme http-01", "addr", ":80", "error", err)
			os.Exit(1)
		}
		acmeSrv := &http.Server{
			Handler: acmeMgr.HTTPHandler(nil),
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			slog.Info("listening", "service", "acme http-01", "addr", acmeListener.Addr())
			if err := acmeSrv.Serve(acmeListener); err != nil && err != http.ErrServerClosed {
				slog.Error("serve stopped", "service", "acme http-01", "error", err)
			}
		}()
	}
	// Wait for shutdown signal or SIGHUP for config reload.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

loop:
	for sig := range sigCh {
		switch sig {
		case syscall.SIGHUP:
			if err := reloadConfig(cfg); err != nil {
				slog.Error("config reload failed", "error", err)
			} else {
				slog.Info("configuration reloaded")
			}
		default:
			slog.Info("shutting down", "signal", sig)
			break loop
		}
	}
	cancel()
}

// reloadConfig reloads the configuration file and applies live-safe changes.
// Settings that require a full restart are logged as warnings.
func reloadConfig(cfg *config.Config) error {
	newCfg, err := config.Load(config.DefaultPath())
	if err != nil {
		return fmt.Errorf("reload: %w", err)
	}

	// Apply live-safe changes.
	if newCfg.Logging.Level != cfg.Logging.Level ||
		newCfg.Logging.Format != cfg.Logging.Format {
		if err := util.InitLogging(newCfg.Logging.Level, newCfg.Logging.Format); err != nil {
			slog.Error("reload: logging reinit failed", "error", err)
		} else {
			slog.Info("reload: logging updated")
		}
	}

	// Log warnings for settings that need restart.
	checkRestart := []struct {
		name  string
		old   interface{}
		new   interface{}
	}{
		{"smtp.listen_addr", cfg.SMTP.ListenAddr, newCfg.SMTP.ListenAddr},
		{"imap.listen_addr", cfg.IMAP.ListenAddr, newCfg.IMAP.ListenAddr},
		{"pop3.listen_addr", cfg.POP3.ListenAddr, newCfg.POP3.ListenAddr},
		{"admin.listen_addr", cfg.Admin.ListenAddr, newCfg.Admin.ListenAddr},
		{"storage.path", cfg.Storage.Path, newCfg.Storage.Path},
		{"storage.blob_backend", cfg.Storage.BlobBackend, newCfg.Storage.BlobBackend},
		{"tls.cert_file", cfg.TLS.CertFile, newCfg.TLS.CertFile},
		{"tls.key_file", cfg.TLS.KeyFile, newCfg.TLS.KeyFile},
	}
	for _, c := range checkRestart {
		if c.old != c.new {
			slog.Warn("reload: setting changed — full restart required",
				"setting", c.name, "old", c.old, "new", c.new,
			)
		}
	}

	*cfg = *newCfg
	return nil
}
