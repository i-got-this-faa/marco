package pop3

import (
	"bufio"
	"crypto/tls"
	"database/sql"
	"log/slog"
	"net"

	"github.com/i-got-this-faa/marco/pkg/auth"
	"github.com/i-got-this-faa/marco/pkg/blobstore"
	"github.com/i-got-this-faa/marco/pkg/config"
)

// Server handles POP3 connections.
type Server struct {
	cfg    *config.POP3Config
	db     *sql.DB
	blob   blobstore.Store
	am     *auth.Manager
	tlsCfg *tls.Config
	log    *slog.Logger
}

// NewServer creates a new POP3 server.
func NewServer(cfg *config.POP3Config, db *sql.DB, blob blobstore.Store, am *auth.Manager, tlsCfg *tls.Config) *Server {
	return &Server{
		cfg:    cfg,
		db:     db,
		blob:   blob,
		am:     am,
		tlsCfg: tlsCfg,
		log:    slog.With("service", "pop3"),
	}
}

// Serve accepts connections on the given listener.
func (s *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go s.handleConn(conn)
	}
}

// ServeTLS wraps the listener with TLS and serves POP3S.
func (s *Server) ServeTLS(l net.Listener) error {
	if s.tlsCfg == nil {
		panic("pop3: ServeTLS called without TLS config")
	}
	tlsListener := tls.NewListener(l, s.tlsCfg)
	return s.Serve(tlsListener)
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)

	session := &Session{
		srv:  s,
		conn: conn,
		br:   br,
		bw:   bw,
		log:  s.log,
	}
	session.handle()
}
