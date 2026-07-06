package util

import (
	"errors"
	"io"
	"log/slog"
	"os"
)

// InitLogging sets the slog default logger's level and output format.
func InitLogging(level, format string) error {
	var l slog.Level
	switch level {
	case "debug":
		l = slog.LevelDebug
	case "info":
		l = slog.LevelInfo
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		return errors.New("util: unknown log level: " + level)
	}

	var w io.Writer = os.Stderr
	var h slog.Handler
	switch format {
	case "json":
		h = slog.NewJSONHandler(w, &slog.HandlerOptions{Level: l})
	case "text":
		h = slog.NewTextHandler(w, &slog.HandlerOptions{Level: l})
	default:
		return errors.New("util: unknown log format: " + format)
	}

	slog.SetDefault(slog.New(h))
	return nil
}
