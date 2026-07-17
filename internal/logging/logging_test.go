package logging

import (
	"log/slog"
	"testing"
)

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug": slog.LevelDebug, "DEBUG": slog.LevelDebug,
		"info": slog.LevelInfo, "": slog.LevelInfo, "nonsense": slog.LevelInfo,
		"warn": slog.LevelWarn, "warning": slog.LevelWarn,
		"error": slog.LevelError,
	}
	for in, want := range cases {
		if got := parseLevel(in); got != want {
			t.Errorf("parseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSetupAndComponent(t *testing.T) {
	Setup("debug", "json")
	if !slog.Default().Enabled(nil, slog.LevelDebug) {
		t.Fatal("debug level should be enabled after Setup(debug)")
	}
	if Component("api") == nil {
		t.Fatal("Component returned nil")
	}
}
