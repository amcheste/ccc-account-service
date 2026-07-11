package config

import "testing"

func TestLoadDefaults(t *testing.T) {
	cfg := Load()
	if cfg.HTTPAddr != ":8080" {
		t.Errorf("HTTPAddr = %q, want :8080", cfg.HTTPAddr)
	}
	if cfg.GRPCAddr != ":9090" {
		t.Errorf("GRPCAddr = %q, want :9090", cfg.GRPCAddr)
	}
	if cfg.OpsAddr != ":8081" {
		t.Errorf("OpsAddr = %q, want :8081", cfg.OpsAddr)
	}
}

func TestLoadEnvOverride(t *testing.T) {
	t.Setenv("CCC_HTTP_ADDR", ":18080")
	t.Setenv("CCC_HTTP_BASE_PATH", "/api/account")
	cfg := Load()
	if cfg.HTTPAddr != ":18080" {
		t.Errorf("HTTPAddr = %q, want :18080", cfg.HTTPAddr)
	}
	if cfg.HTTPBasePath != "/api/account" {
		t.Errorf("HTTPBasePath = %q, want /api/account", cfg.HTTPBasePath)
	}
}

func TestBasePathDefaultsEmpty(t *testing.T) {
	if got := Load().HTTPBasePath; got != "" {
		t.Errorf("HTTPBasePath default = %q, want empty", got)
	}
}

func TestDatabaseURL(t *testing.T) {
	if got := Load().DatabaseURL(); got != "" {
		t.Errorf("DatabaseURL with no DBHost = %q, want empty", got)
	}

	t.Setenv("CCC_DB_HOST", "postgres")
	t.Setenv("CCC_DB_PASSWORD", "p@ss/word")
	want := "postgres://ccc:p%40ss%2Fword@postgres:5432/account?sslmode=disable" //nolint:gosec // fixture, not a real credential
	if got := Load().DatabaseURL(); got != want {
		t.Errorf("DatabaseURL = %q, want %q", got, want)
	}
}
