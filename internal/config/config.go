// Package config loads service configuration from the environment.
// Non-secret defaults live here; secrets (database credentials, JWT
// signing key) arrive via environment variables sourced from a k8s
// Secret.
package config

import (
	"fmt"
	"net/url"
	"os"
)

// Config holds all runtime configuration for the account service.
type Config struct {
	// HTTPAddr serves the external REST API.
	HTTPAddr string
	// HTTPBasePath prefixes every REST route (e.g. "/api/account") so
	// the ingress can route by prefix without rewriting. Rewrites at
	// the ingress break cookie Path attributes; serving under the
	// externally visible path avoids that whole failure class. Empty
	// means routes mount at the root.
	HTTPBasePath string
	// GRPCAddr serves the internal gRPC API for other CCC services.
	GRPCAddr string
	// OpsAddr serves /healthz, /readyz, and /metrics.
	OpsAddr string

	// Database connection pieces (composed by DatabaseURL). An empty
	// DBHost disables persistence: the service runs in skeleton mode
	// with no store, and readiness does not gate on the database.
	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string
}

// DatabaseURL assembles a postgres:// DSN from the DB* fields, or
// returns empty when no database is configured. sslmode=disable is
// correct for both the in-cluster CNPG instance and local dev; TLS
// termination happens at the ingress, not between pods, per design §5.
func (c Config) DatabaseURL() string {
	if c.DBHost == "" {
		return ""
	}
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(c.DBUser, c.DBPassword),
		Host:     fmt.Sprintf("%s:%s", c.DBHost, c.DBPort),
		Path:     "/" + c.DBName,
		RawQuery: "sslmode=disable",
	}
	return u.String()
}

// Load reads configuration from the environment, applying defaults
// that match the ports documented in the design (§3, §5).
func Load() Config {
	return Config{
		HTTPAddr:     getenv("CCC_HTTP_ADDR", ":8080"),
		HTTPBasePath: getenv("CCC_HTTP_BASE_PATH", ""),
		GRPCAddr:     getenv("CCC_GRPC_ADDR", ":9090"),
		OpsAddr:      getenv("CCC_OPS_ADDR", ":8081"),
		DBHost:       getenv("CCC_DB_HOST", ""),
		DBPort:       getenv("CCC_DB_PORT", "5432"),
		DBUser:       getenv("CCC_DB_USER", "ccc"),
		DBPassword:   getenv("CCC_DB_PASSWORD", ""),
		DBName:       getenv("CCC_DB_NAME", "account"),
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
