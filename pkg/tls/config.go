package tls

import (
	"crypto/tls"
	"fmt"

	"golang.org/x/crypto/acme/autocert"
	"github.com/i-got-this-faa/marco/pkg/config"
)

// ServerConfig builds a *tls.Config suitable for TLS listeners.
func ServerConfig(cfg *config.TLSConfig, hostname string, acmeMgr *autocert.Manager) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if acmeMgr != nil {
		tlsCfg.GetCertificate = acmeMgr.GetCertificate
		return tlsCfg, nil
	}

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("tls: load cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	} else {
		// Self-signed fallback.
		cert, err := SelfSignedCert(hostname, "127.0.0.1", "::1")
		if err != nil {
			return nil, fmt.Errorf("tls: self-signed: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}
