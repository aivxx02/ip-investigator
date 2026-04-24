package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadEnvFile(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	os.WriteFile(envPath, []byte("VIRUSTOTAL_KEY=abc123\nOPENROUTER_KEY=xyz\n"), 0600)

	cfg, err := LoadFrom(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VirusTotalKey != "abc123" {
		t.Errorf("VirusTotalKey = %q, want abc123", cfg.VirusTotalKey)
	}
	if cfg.OpenRouterKey != "xyz" {
		t.Errorf("OpenRouterKey = %q, want xyz", cfg.OpenRouterKey)
	}
}

func TestLoadEnvFile_Missing(t *testing.T) {
	// Missing .env should not error — just return empty config
	cfg, err := LoadFrom("/nonexistent/.env")
	if err != nil {
		t.Errorf("missing .env should not error, got: %v", err)
	}
	if cfg == nil {
		t.Error("expected non-nil config")
	}
}
