package imap

import (
	"crypto/tls"

	imapserver "github.com/emersion/go-imap/server"
	"github.com/i-got-this-faa/marco/pkg/config"
)

// NewServer creates a new IMAP server.
func NewServer(cfg *config.IMAPConfig, be *Backend, tlsCfg *tls.Config) *imapserver.Server {
	s := imapserver.New(be)
	s.Addr = cfg.ListenAddr
	s.TLSConfig = tlsCfg
	s.AllowInsecureAuth = false
	return s
}
