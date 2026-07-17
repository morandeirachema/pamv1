// Package config loads server configuration from PAM_* environment variables.
package config

import (
	"fmt"
	"os"
)

type Config struct {
	ListenAddr  string
	DatabaseURL string
	MasterKey   string
	APIKey      string
	// BreakGlassKeyHash is the hex SHA-256 of the sealed emergency key
	// (optional; empty disables the break-glass path). Only the hash lives
	// in config so the plaintext key can be kept sealed offline.
	BreakGlassKeyHash string

	// SSHAddr is the session-proxy listen address; "off" disables it.
	SSHAddr string
	// SSHHostKeyPath persists the proxy host key; empty = ephemeral key.
	SSHHostKeyPath string
	// RecordingDir is where session recordings are written.
	RecordingDir string

	// LogLevel is debug|info|warn|error (default info).
	LogLevel string
	// LogFormat is json|text (default json).
	LogFormat string
}

func Load() (*Config, error) {
	cfg := &Config{
		ListenAddr:        getenv("PAM_LISTEN_ADDR", ":8080"),
		DatabaseURL:       os.Getenv("PAM_DATABASE_URL"),
		MasterKey:         os.Getenv("PAM_MASTER_KEY"),
		APIKey:            os.Getenv("PAM_API_KEY"),
		BreakGlassKeyHash: os.Getenv("PAM_BREAK_GLASS_KEY_HASH"),
		SSHAddr:           getenv("PAM_SSH_ADDR", ":2222"),
		SSHHostKeyPath:    os.Getenv("PAM_SSH_HOST_KEY"),
		RecordingDir:      getenv("PAM_RECORDING_DIR", "recordings"),
		LogLevel:          getenv("PAM_LOG_LEVEL", "info"),
		LogFormat:         getenv("PAM_LOG_FORMAT", "json"),
	}
	if cfg.MasterKey == "" {
		return nil, fmt.Errorf("PAM_MASTER_KEY is required (generate one with: pam-server -genkey)")
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("PAM_API_KEY is required")
	}
	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf(`PAM_DATABASE_URL is required (postgres://... or "memory" for an ephemeral demo)`)
	}
	return cfg, nil
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
