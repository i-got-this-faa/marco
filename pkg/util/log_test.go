package util

import (
	"log/slog"
	"testing"
)

func TestInitLoggingDebug(t *testing.T) {
	if err := InitLogging("debug", "text"); err != nil {
		t.Fatalf("InitLogging(debug, text): %v", err)
	}
	if !slog.Default().Enabled(nil, slog.LevelDebug) {
		t.Error("expected debug level to be enabled")
	}
}

func TestInitLoggingInfo(t *testing.T) {
	if err := InitLogging("info", "json"); err != nil {
		t.Fatalf("InitLogging(info, json): %v", err)
	}
	if !slog.Default().Enabled(nil, slog.LevelInfo) {
		t.Error("expected info level to be enabled")
	}
	if slog.Default().Enabled(nil, slog.LevelDebug) {
		t.Error("expected debug level to NOT be enabled at info level")
	}
}

func TestInitLoggingWarn(t *testing.T) {
	if err := InitLogging("warn", "json"); err != nil {
		t.Fatalf("InitLogging(warn, json): %v", err)
	}
}

func TestInitLoggingError(t *testing.T) {
	if err := InitLogging("error", "json"); err != nil {
		t.Fatalf("InitLogging(error, json): %v", err)
	}
}

func TestInitLoggingInvalidLevel(t *testing.T) {
	if err := InitLogging("invalid", "json"); err == nil {
		t.Fatal("expected error for invalid level")
	}
}

func TestInitLoggingInvalidFormat(t *testing.T) {
	if err := InitLogging("info", "xml"); err == nil {
		t.Fatal("expected error for invalid format")
	}
}
