package tls

import (
	"fmt"

	"github.com/i-got-this-faa/marco/pkg/config"
	"golang.org/x/crypto/acme/autocert"
)

// NewACMManager creates an ACME (Let's Encrypt) certificate manager.
func NewACMManager(cfg *config.ACMEConfig, hostname string) (*autocert.Manager, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	if len(cfg.Domains) == 0 && hostname == "" {
		return nil, fmt.Errorf("tls: ACME requires at least one domain")
	}

	domains := cfg.Domains
	if hostname != "" {
		// Ensure hostname is in the list.
		found := false
		for _, d := range domains {
			if d == hostname {
				found = true
				break
			}
		}
		if !found {
			domains = append(domains, hostname)
		}
	}

	mgr := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domains...),
		Cache:      autocert.DirCache(cfg.CacheDir),
		Email:      cfg.Email,
	}

	return mgr, nil
}
