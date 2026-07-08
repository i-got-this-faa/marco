package smtp

import (
	"crypto/tls"

	"github.com/emersion/go-smtp"
)

// NewServer creates a new SMTP server from a pre-built Backend.
func NewServer(be *Backend, tlsCfg *tls.Config) *smtp.Server {
	s := smtp.NewServer(be)
	s.Addr = be.cfg.ListenAddr
	s.Domain = be.cfg.Hostname
	s.MaxMessageBytes = be.cfg.MaxMessageSize
	s.MaxRecipients = be.cfg.MaxRecipients
	s.TLSConfig = tlsCfg
	s.AllowInsecureAuth = false

	return s
}
