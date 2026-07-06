package smtp

import (
	"crypto/tls"
	"database/sql"
	"log/slog"

	"github.com/emersion/go-smtp"
	"github.com/i-got-this-faa/marco/pkg/auth"
	"github.com/i-got-this-faa/marco/pkg/blobstore"
	"github.com/i-got-this-faa/marco/pkg/config"
	"github.com/i-got-this-faa/marco/pkg/dkim"
	"github.com/i-got-this-faa/marco/pkg/metrics"
	"github.com/i-got-this-faa/marco/pkg/queue"
	"github.com/i-got-this-faa/marco/pkg/ratelimit"
)

// NewServer creates a new SMTP server.
func NewServer(cfg *config.SMTPConfig, db *sql.DB, blob blobstore.Store,
	qm *queue.Manager, am *auth.Manager, dk *dkim.Signer, m *metrics.Registry,
	tlsCfg *tls.Config) *smtp.Server {

	var lim *ratelimit.Limiter
	if cfg.RateLimit > 0 {
		lim = ratelimit.New(cfg.RateLimit, cfg.RateLimitBurst)
	}

	be := &Backend{
		db:      db,
		blob:    blob,
		queue:   qm,
		auth:    am,
		dkim:    dk,
		cfg:     cfg,
		metrics: m,
		log:     slog.With("service", "smtp"),
		limiter: lim,
	}

	s := smtp.NewServer(be)
	s.Addr = cfg.ListenAddr
	s.Domain = cfg.Hostname
	s.MaxMessageBytes = cfg.MaxMessageSize
	s.MaxRecipients = cfg.MaxRecipients
	s.TLSConfig = tlsCfg
	s.AllowInsecureAuth = false

	return s
}
