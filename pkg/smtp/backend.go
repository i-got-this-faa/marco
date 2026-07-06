package smtp

import (
	"context"
	"database/sql"
	"log/slog"
	"net"

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
	db      *sql.DB
	blob    blobstore.Store
	queue   *queue.Manager
	auth    *auth.Manager
	dkim    *dkim.Signer
	cfg     *config.SMTPConfig
	metrics *metrics.Registry
	log     *slog.Logger
	limiter *ratelimit.Limiter
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
