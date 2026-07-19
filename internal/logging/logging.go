// Package logging configures pamv1's structured operational logs. Every
// component logs to stdout via slog tagged with a "service" attribute
// (server, api, proxy, store, vault, auth) so logs can be filtered per
// service and shipped to a SIEM. These operational logs are separate from the
// security audit trail, which is stored in the database.
package logging

import (
	"log/slog"
	"os"
	"strings"
)

// Setup installs the process-wide slog logger. level is one of
// debug|info|warn|error (default info); format is json|text (default json).
// It returns the root logger and also sets it as slog.Default so components
// constructed afterwards inherit it.
func Setup(level, format string) *slog.Logger {
	opts := &slog.HandlerOptions{Level: parseLevel(level)}
	var h slog.Handler
	if strings.EqualFold(format, "text") {
		h = slog.NewTextHandler(os.Stdout, opts)
	} else {
		h = slog.NewJSONHandler(os.Stdout, opts)
	}
	logger := slog.New(h)
	slog.SetDefault(logger)
	return logger
}

// Component returns the default logger tagged with service=name.
func Component(name string) *slog.Logger {
	return slog.Default().With("service", name)
}

// parseLevel maps a level name (debug|info|warn|error) to a slog.Level,
// defaulting to info for empty or unrecognized values.
func parseLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
