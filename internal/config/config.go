// Package config loads service configuration from the environment.
// Non-secret defaults live here; secrets (database DSN, JWT signing
// key) arrive via environment variables sourced from a k8s Secret.
package config

import "os"

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
}

// Load reads configuration from the environment, applying defaults
// that match the ports documented in the design (§3, §5).
func Load() Config {
	return Config{
		HTTPAddr:     getenv("CCC_HTTP_ADDR", ":8080"),
		HTTPBasePath: getenv("CCC_HTTP_BASE_PATH", ""),
		GRPCAddr:     getenv("CCC_GRPC_ADDR", ":9090"),
		OpsAddr:      getenv("CCC_OPS_ADDR", ":8081"),
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
