package tls

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	ctls "crypto/tls"

	"github.com/i-got-this-faa/marco/pkg/config"
)

func TestSelfSignedCert(t *testing.T) {
	cert, err := SelfSignedCert("mail.example.com")
	if err != nil {
		t.Fatalf("SelfSignedCert: %v", err)
	}

	if len(cert.Certificate) == 0 {
		t.Fatal("SelfSignedCert returned empty certificate chain")
	}

	if cert.PrivateKey == nil {
		t.Fatal("SelfSignedCert returned nil private key")
	}

	// Verify the certificate parses correctly.
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	if x509Cert.Subject.CommonName != "mail.example.com" {
		t.Errorf("expected CommonName 'mail.example.com', got %q", x509Cert.Subject.CommonName)
	}

	if len(x509Cert.DNSNames) != 1 || x509Cert.DNSNames[0] != "mail.example.com" {
		t.Errorf("expected DNSNames [mail.example.com], got %v", x509Cert.DNSNames)
	}

	// Verify key usage.
	if x509Cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Error("expected KeyEncipherment key usage")
	}
	if x509Cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("expected DigitalSignature key usage")
	}
}

func TestSelfSignedCertEmptyHostname(t *testing.T) {
	// Should still work but with empty CommonName.
	cert, err := SelfSignedCert("")
	if err != nil {
		t.Fatalf("SelfSignedCert(''): %v", err)
	}

	if len(cert.Certificate) == 0 {
		t.Fatal("SelfSignedCert returned empty certificate chain")
	}
}

func TestSaveSelfSignedCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	err := SaveSelfSignedCert("mail.example.com", certPath, keyPath)
	if err != nil {
		t.Fatalf("SaveSelfSignedCert: %v", err)
	}

	// Verify files exist and have content.
	certInfo, err := os.Stat(certPath)
	if err != nil {
		t.Fatalf("stat cert.pem: %v", err)
	}
	if certInfo.Size() == 0 {
		t.Error("cert.pem is empty")
	}

	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key.pem: %v", err)
	}
	if keyInfo.Size() == 0 {
		t.Error("key.pem is empty")
	}

	// Verify the saved cert can be loaded.
	cert, err := LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Error("loaded cert has empty certificate chain")
	}
}

func TestLoadX509KeyPair(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	err := SaveSelfSignedCert("test.local", certPath, keyPath)
	if err != nil {
		t.Fatalf("SaveSelfSignedCert: %v", err)
	}

	cert, err := LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}

	if len(cert.Certificate) == 0 {
		t.Error("loaded cert has empty certificate chain")
	}
	if cert.PrivateKey == nil {
		t.Error("loaded cert has nil private key")
	}
}

func TestLoadX509KeyPairNonexistent(t *testing.T) {
	_, err := LoadX509KeyPair("/nonexistent/cert.pem", "/nonexistent/key.pem")
	if err == nil {
		t.Fatal("expected error for nonexistent cert files")
	}
}

func TestServerConfigWithStaticCerts(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	err := SaveSelfSignedCert("mail.example.com", certPath, keyPath)
	if err != nil {
		t.Fatalf("SaveSelfSignedCert: %v", err)
	}

	cfg := &config.TLSConfig{
		CertFile: certPath,
		KeyFile:  keyPath,
	}

	tlsCfg, err := ServerConfig(cfg, "mail.example.com", nil)
	if err != nil {
		t.Fatalf("ServerConfig: %v", err)
	}

	if tlsCfg == nil {
		t.Fatal("ServerConfig returned nil")
	}

	if tlsCfg.MinVersion != ctls.VersionTLS12 {
		t.Errorf("expected MinVersion TLS 1.2, got %d", tlsCfg.MinVersion)
	}

	if len(tlsCfg.Certificates) == 0 {
		t.Error("expected Certificates to be non-empty")
	}
}

func TestServerConfigSelfSignedFallback(t *testing.T) {
	// No cert files, no ACME manager — should generate self-signed.
	cfg := &config.TLSConfig{}

	tlsCfg, err := ServerConfig(cfg, "fallback.example.com", nil)
	if err != nil {
		t.Fatalf("ServerConfig: %v", err)
	}

	if tlsCfg == nil {
		t.Fatal("ServerConfig returned nil")
	}

	if len(tlsCfg.Certificates) == 0 {
		t.Error("expected Certificates to be non-empty (self-signed fallback)")
	}

	// Verify the cert is for the given hostname.
	cert, err := x509.ParseCertificate(tlsCfg.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if cert.Subject.CommonName != "fallback.example.com" {
		t.Errorf("expected CommonName 'fallback.example.com', got %q", cert.Subject.CommonName)
	}
}

func TestServerConfigTLSVersion(t *testing.T) {
	cfg := &config.TLSConfig{}
	tlsCfg, err := ServerConfig(cfg, "test.local", nil)
	if err != nil {
		t.Fatalf("ServerConfig: %v", err)
	}

	if tlsCfg.MinVersion < ctls.VersionTLS12 {
		t.Errorf("MinVersion should be at least TLS 1.2, got %d", tlsCfg.MinVersion)
	}
}

func TestNewACMManagerEnabled(t *testing.T) {
	cfg := &config.ACMEConfig{
		Enabled:  true,
		CacheDir: t.TempDir(),
		Domains:  []string{"mail.example.com"},
		Email:    "admin@example.com",
	}

	mgr, err := NewACMManager(cfg, "mail.example.com")
	if err != nil {
		t.Fatalf("NewACMManager: %v", err)
	}

	if mgr == nil {
		t.Fatal("NewACMManager returned nil")
	}
}

func TestNewACMManagerDisabled(t *testing.T) {
	cfg := &config.ACMEConfig{
		Enabled: false,
	}

	mgr, err := NewACMManager(cfg, "mail.example.com")
	if err != nil {
		t.Fatalf("NewACMManager: %v", err)
	}

	if mgr != nil {
		t.Fatal("expected nil when ACME is disabled")
	}
}

func TestNewACMManagerNoDomains(t *testing.T) {
	cfg := &config.ACMEConfig{
		Enabled:  true,
		CacheDir: t.TempDir(),
		// No Domains set and hostname is empty.
	}

	_, err := NewACMManager(cfg, "")
	if err == nil {
		t.Fatal("expected error when ACME is enabled with no domains")
	}
}

func TestNewACMManagerHostnameAdded(t *testing.T) {
	cfg := &config.ACMEConfig{
		Enabled:  true,
		CacheDir: t.TempDir(),
		Domains:  []string{"other.com"},
		Email:    "admin@other.com",
	}

	mgr, err := NewACMManager(cfg, "mail.example.com")
	if err != nil {
		t.Fatalf("NewACMManager: %v", err)
	}

	if mgr == nil {
		t.Fatal("NewACMManager returned nil")
	}
}

func TestServerConfigWithACME(t *testing.T) {
	cfg := &config.TLSConfig{}
	acmeCfg := &config.ACMEConfig{
		Enabled:  true,
		CacheDir: t.TempDir(),
		Domains:  []string{"mail.example.com"},
	}

	acmeMgr, err := NewACMManager(acmeCfg, "mail.example.com")
	if err != nil {
		t.Fatalf("NewACMManager: %v", err)
	}

	tlsCfg, err := ServerConfig(cfg, "mail.example.com", acmeMgr)
	if err != nil {
		t.Fatalf("ServerConfig: %v", err)
	}

	if tlsCfg == nil {
		t.Fatal("ServerConfig returned nil")
	}

	// When ACME is used, GetCertificate should be set.
	if tlsCfg.GetCertificate == nil {
		t.Error("expected GetCertificate to be set when ACME manager is provided")
	}
}
