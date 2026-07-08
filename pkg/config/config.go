package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
)

// Config is the top-level configuration for the mail server.
type Config struct {
	Hostname  string        `toml:"hostname"`
	Domains   []string      `toml:"domains"`
	IPVersion string        `toml:"ip_version"`
	Storage   StorageConfig `toml:"storage"`
	SMTP      SMTPConfig    `toml:"smtp"`
	IMAP      IMAPConfig    `toml:"imap"`
	POP3      POP3Config    `toml:"pop3"`
	TLS       TLSConfig     `toml:"tls"`
	ACME      ACMEConfig    `toml:"acme"`
	Auth      AuthConfig    `toml:"auth"`
	Queue     QueueConfig   `toml:"queue"`
	Relay     RelayConfig   `toml:"relay"`
	DKIM      DKIMConfig    `toml:"dkim"`
	DMARC     DMARCConfig   `toml:"dmarc"`
	Admin     AdminConfig   `toml:"admin"`
	Logging   LogConfig     `toml:"logging"`
}

// StorageConfig controls SQLite database and blob storage.
type StorageConfig struct {
	Path        string `toml:"path"`
	BlobBackend string `toml:"blob_backend"`
	BlobPath    string `toml:"blob_path"`
}

// SMTPConfig controls the SMTP listener(s).
type SMTPConfig struct {
	ListenAddr      string        `toml:"listen_addr"`
	SubmissionAddr  string        `toml:"submission_addr"`
	SubmissionsAddr string        `toml:"submissions_addr"`
	MaxMessageSize  int64         `toml:"max_message_size"`
	MaxRecipients   int           `toml:"max_recipients"`
	Hostname        string        `toml:"hostname"`
	RateLimit       float64       `toml:"rate_limit"`
	RateLimitBurst  int           `toml:"rate_limit_burst"`
	GreylistingDelay time.Duration `toml:"greylisting_delay"`
}

// IMAPConfig controls the IMAP listener(s).
type IMAPConfig struct {
	ListenAddr  string `toml:"listen_addr"`
	ImapsAddr   string `toml:"imaps_addr"`
}

// POP3Config controls the POP3 listener(s).
type POP3Config struct {
	ListenAddr string `toml:"listen_addr"`
	POP3sAddr  string `toml:"pop3s_addr"`
	APOPSecret string `toml:"apop_secret"`
}

// TLSConfig controls TLS certificate paths.
type TLSConfig struct {
	CertFile string `toml:"cert_file"`
	KeyFile  string `toml:"key_file"`
}

// ACMEConfig controls automatic certificate management.
type ACMEConfig struct {
	Enabled  bool     `toml:"enabled"`
	CacheDir string   `toml:"cache_dir"`
	Domains  []string `toml:"domains"`
	Email    string   `toml:"email"`
}

// AuthConfig controls authentication settings.
type AuthConfig struct {
	SessionExpiry time.Duration `toml:"session_expiry"`
}

// QueueConfig controls the outbound delivery queue.
type QueueConfig struct {
	Workers    int           `toml:"workers"`
	MaxRetries int           `toml:"max_retries"`
	Interval   time.Duration `toml:"interval"`
}

// DKIMConfig controls DKIM signing of outbound messages.
type DKIMConfig struct {
	Domain         string `toml:"domain"`
	Selector       string `toml:"selector"`
	PrivateKeyPath string `toml:"private_key_path"`
}

// AdminConfig controls the HTTP admin API.
type AdminConfig struct {
	ListenAddr      string        `toml:"listen_addr"`
	SessionExpiry   time.Duration `toml:"session_expiry"`
	RateLimit       float64       `toml:"rate_limit"`
	RateLimitBurst  int           `toml:"rate_limit_burst"`
}

// DMARCConfig controls DMARC aggregate report generation.
type DMARCConfig struct {
	OrgName        string        `toml:"org_name"`
	ReportInterval time.Duration `toml:"report_interval"`
	Email          string        `toml:"email"`
}
// RelayConfig controls outbound SMTP relay (smart host) settings.
type RelayConfig struct {
	Host     string `toml:"host"`
	Port     int    `toml:"port"`
	Username string `toml:"username"`
	Password string `toml:"password"`
}
// LogConfig controls structured logging.
type LogConfig struct {
	Level  string `toml:"level"`
	Format string `toml:"format"`
}

// DefaultPath returns the default config file path.
func DefaultPath() string {
	if p := os.Getenv("MARCO_CONFIG"); p != "" {
		return p
	}
	return "/etc/marco/config.toml"
}

// Load reads and parses a TOML config file, applying defaults for
// any fields not specified. Invalid IPVersion values return an error.
func Load(path string) (*Config, error) {
	cfg := defaultConfig()
	if _, err := toml.DecodeFile(path, cfg); err != nil {
		if os.IsNotExist(err) {
			// File not found is acceptable — use defaults.
			return cfg, nil
		}
		return nil, fmt.Errorf("config: load %s: %w", path, err)
	}
	switch cfg.IPVersion {
	case "any", "ipv4", "ipv6":
		// valid
	default:
		return nil, fmt.Errorf("config: invalid ip_version %q: must be \"any\", \"ipv4\", or \"ipv6\"", cfg.IPVersion)
	}
	return cfg, nil
}

// Save writes the config to a TOML file.
func Save(path string, cfg *Config) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("config: create %s: %w", path, err)
	}
	defer f.Close()
	return toml.NewEncoder(f).Encode(cfg)
}

func defaultConfig() *Config {
	hostname, _ := os.Hostname()
	return &Config{
		Hostname:  hostname,
		IPVersion: "any",
		Storage: StorageConfig{
			Path:        "/var/lib/marco/marco.db",
			BlobBackend: "filesystem",
			BlobPath:    "/var/lib/marco/blobs",
		},
		SMTP: SMTPConfig{
			ListenAddr:       ":25",
			SubmissionAddr:   ":587",
			SubmissionsAddr:  ":465",
			MaxMessageSize:   25 * 1024 * 1024, // 25 MB
			MaxRecipients:    100,
			Hostname:         hostname,
			RateLimit:        10,
			RateLimitBurst:   20,
			GreylistingDelay: 300 * time.Second, // 5 minutes
		},
		IMAP: IMAPConfig{
			ListenAddr: ":143",
			ImapsAddr:  ":993",
		},
		POP3: POP3Config{
			ListenAddr: ":110",
		},
		TLS: TLSConfig{},
		ACME: ACMEConfig{
			CacheDir: "/var/lib/marco/acme",
		},
		Auth: AuthConfig{
			SessionExpiry: 24 * time.Hour,
		},
		Queue: QueueConfig{
			Workers:    2,
			MaxRetries: 7,
			Interval:   5 * time.Second,
		},
		Relay: RelayConfig{
			Port: 587,
		},
		Admin: AdminConfig{
			ListenAddr:     ":8080",
			SessionExpiry:  24 * time.Hour,
			RateLimit:      10,
			RateLimitBurst: 20,
		},
		DMARC: DMARCConfig{
			OrgName:        hostname,
			ReportInterval: 24 * time.Hour,
		},
		Logging: LogConfig{
			Level:  "info",
			Format: "json",
		},
	}
}

// Template generates a default config template path.
func Template() string {
	return filepath.Join("/etc/marco", "config.toml")
}
