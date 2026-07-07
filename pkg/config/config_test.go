package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := defaultConfig()
	if cfg.Hostname == "" {
		t.Error("default Hostname should not be empty")
	}
	if cfg.SMTP.MaxMessageSize != 25*1024*1024 {
		t.Errorf("default MaxMessageSize = %d, want %d", cfg.SMTP.MaxMessageSize, 25*1024*1024)
	}
	if cfg.Queue.MaxRetries != 7 {
		t.Errorf("default MaxRetries = %d, want 7", cfg.Queue.MaxRetries)
	}
	if cfg.Auth.SessionExpiry != 24*time.Hour {
		t.Errorf("default SessionExpiry = %v, want 24h", cfg.Auth.SessionExpiry)
	}
	if cfg.IPVersion != "any" {
		t.Errorf("default IPVersion = %q, want \"any\"", cfg.IPVersion)
	}
	if cfg.SMTP.ListenAddr != ":25" {
		t.Errorf("default SMTP ListenAddr = %q, want \":25\"", cfg.SMTP.ListenAddr)
	}
	if cfg.IMAP.ListenAddr != ":143" {
		t.Errorf("default IMAP ListenAddr = %q, want \":143\"", cfg.IMAP.ListenAddr)
	}
}

func TestLoadToml(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
hostname = "mail.example.com"
domains = ["example.com"]

[smtp]
listen_addr = "0.0.0.0:2525"
max_message_size = 10485760

[auth]
session_expiry = "1h"

[logging]
level = "debug"
format = "text"
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Hostname != "mail.example.com" {
		t.Errorf("Hostname = %q, want mail.example.com", cfg.Hostname)
	}
	if len(cfg.Domains) != 1 || cfg.Domains[0] != "example.com" {
		t.Errorf("Domains = %v, want [example.com]", cfg.Domains)
	}
	if cfg.SMTP.ListenAddr != "0.0.0.0:2525" {
		t.Errorf("SMTP.ListenAddr = %q, want 0.0.0.0:2525", cfg.SMTP.ListenAddr)
	}
	if cfg.SMTP.MaxMessageSize != 10485760 {
		t.Errorf("MaxMessageSize = %d, want 10485760", cfg.SMTP.MaxMessageSize)
	}
	if cfg.Auth.SessionExpiry != time.Hour {
		t.Errorf("SessionExpiry = %v, want 1h", cfg.Auth.SessionExpiry)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("Logging.Level = %q, want debug", cfg.Logging.Level)
	}
}

func TestLoadMissingFile(t *testing.T) {
	cfg, err := Load("/nonexistent/path/config.toml")
	if err != nil {
		t.Fatalf("Load missing file should not error: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load missing file should return default config")
	}
}

func TestDefaultPathEnv(t *testing.T) {
	t.Setenv("MARCO_CONFIG", "/custom/path/config.toml")
	if p := DefaultPath(); p != "/custom/path/config.toml" {
		t.Errorf("DefaultPath = %q, want /custom/path/config.toml", p)
	}
}

func TestDefaultPathNoEnv(t *testing.T) {
	t.Setenv("MARCO_CONFIG", "")
	if p := DefaultPath(); p != "/etc/marco/config.toml" {
		t.Errorf("DefaultPath = %q, want /etc/marco/config.toml", p)
	}
}

func TestSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "saved.toml")
	cfg := defaultConfig()
	cfg.Hostname = "test.example.com"

	if err := Save(path, cfg); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Reload failed: %v", err)
	}
	if loaded.Hostname != "test.example.com" {
		t.Errorf("Hostname after reload = %q, want test.example.com", loaded.Hostname)
	}
}

func TestIPVersionValidation(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name    string
		version string
		wantErr bool
	}{
		{"default", "any", false},
		{"ipv4", "ipv4", false},
		{"ipv6", "ipv6", false},
		{"invalid", "ipv5", true},
		{"empty", "", false}, // "any" is the default
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, tt.name+".toml")
			content := fmt.Sprintf("ip_version = %q", tt.version)
			if tt.version == "" {
				content = ""
			}
			if err := os.WriteFile(path, []byte(content), 0644); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			_, err := Load(path)
			if tt.wantErr && err == nil {
				t.Errorf("Load(%q) expected error", tt.version)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Load(%q) unexpected error: %v", tt.version, err)
			}
		})
	}
}
