package smtp

import (
	"context"
	"database/sql"
	"log/slog"
	"net"
	"sync"

	"github.com/emersion/go-smtp"
	"github.com/i-got-this-faa/marco/pkg/auth"
	"github.com/i-got-this-faa/marco/pkg/blobstore"
	"github.com/i-got-this-faa/marco/pkg/config"
	"github.com/i-got-this-faa/marco/pkg/dkim"
	"github.com/i-got-this-faa/marco/pkg/metrics"
	"github.com/i-got-this-faa/marco/pkg/queue"
	"github.com/i-got-this-faa/marco/pkg/ratelimit"
	"github.com/i-got-this-faa/marco/pkg/util"
)

// Backend implements smtp.Backend.
type Backend struct {
	db           *sql.DB
	blob         blobstore.Store
	queue        *queue.Manager
	auth         *auth.Manager
	dkim         *dkim.Signer
	cfg          *config.SMTPConfig
	metrics      *metrics.Registry
	log          *slog.Logger
	limiter      *ratelimit.Limiter
	localDomains *sync.Map
}

// NewBackend creates a new SMTP Backend with initialized fields.
func NewBackend(cfg *config.SMTPConfig, db *sql.DB, blob blobstore.Store,
	qm *queue.Manager, am *auth.Manager, dk *dkim.Signer, m *metrics.Registry) *Backend {
	var lim *ratelimit.Limiter
	if cfg.RateLimit > 0 {
		lim = ratelimit.New(cfg.RateLimit, cfg.RateLimitBurst)
	}
	be := &Backend{
		db:           db,
		blob:         blob,
		queue:        qm,
		auth:         am,
		dkim:         dk,
		cfg:          cfg,
		metrics:      m,
		log:          slog.With("service", "smtp"),
		limiter:      lim,
		localDomains: &sync.Map{},
	}
	if cfg.Hostname != "" {
		be.localDomains.Store(cfg.Hostname, true)
	}
	return be
}

// ReloadDomains replaces the set of locally-served domains used for
// relay authorization. The configured hostname is always included.
func (b *Backend) ReloadDomains(domains []string) {
	m := &sync.Map{}
	if b.cfg.Hostname != "" {
		m.Store(b.cfg.Hostname, true)
	}
	for _, d := range domains {
		m.Store(d, true)
	}
	b.localDomains = m
}

// NewSession is called by the SMTP server for each new connection.
func (b *Backend) NewSession(conn *smtp.Conn) (smtp.Session, error) {
	if b.limiter != nil {
		remoteAddr := conn.Conn().RemoteAddr().String()
		ip, _, err := net.SplitHostPort(remoteAddr)
		if err != nil {
			ip = remoteAddr
		}
		if !b.limiter.Allow(ip) {
			b.metrics.SMTPConnections.Inc()
			b.log.Warn("rate limit exceeded", "remote_ip", ip)
			return nil, smtp.ErrAuthUnsupported // connection will be dropped
		}
	}

	b.metrics.SMTPConnections.Inc()
	b.metrics.ActiveConnections.Inc()
	ctx := util.NewContextWithCID(context.Background())
	return &Session{
		backend: b,
		conn:    conn,
		ctx:     ctx,
	}, nil
}
