// Command account-service runs the CCC account service: identity,
// credentials, and token issuance for the Command and Control Center.
//
// With a database (CCC_DB_HOST) and signing key (CCC_JWT_SIGNING_KEY)
// configured, the full REST API serves on CCC_HTTP_ADDR under
// CCC_HTTP_BASE_PATH. Without them the process runs in skeleton mode:
// ops listener only. The gRPC listener (:9090) lands with the
// grpcserver package. See docs/design/account-service.md.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/amcheste/ccc-account-service/internal/auth"
	"github.com/amcheste/ccc-account-service/internal/config"
	"github.com/amcheste/ccc-account-service/internal/httpserver"
	"github.com/amcheste/ccc-account-service/internal/service"
	"github.com/amcheste/ccc-account-service/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)
	if err := run(logger); err != nil {
		logger.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg := config.Load()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var st store.Store
	if dsn := cfg.DatabaseURL(); dsn != "" {
		if err := store.Migrate(dsn); err != nil {
			return err
		}
		pg, err := store.Connect(ctx, dsn)
		if err != nil {
			return err
		}
		defer pg.Close()
		st = pg
		logger.Info("database connected, migrations applied",
			"host", cfg.DBHost, "database", cfg.DBName)
	} else {
		logger.Warn("no database configured (CCC_DB_HOST empty); running in skeleton mode")
	}

	servers := make([]*http.Server, 0, 2)

	if st != nil && cfg.JWTSigningKey != "" {
		seed, err := auth.ParseSigningSeed(cfg.JWTSigningKey)
		if err != nil {
			return err
		}
		issuer, err := auth.NewTokenIssuer(seed, auth.DefaultAccessTokenTTL)
		if err != nil {
			return err
		}
		hasher := auth.NewHasher(auth.DefaultParams(), 4)
		svc := service.New(st, hasher, issuer, cfg.RefreshTTL, logger)

		if err := svc.Bootstrap(ctx, cfg.BootstrapAdmin, cfg.BootstrapAdminPassword); err != nil {
			return err
		}

		servers = append(servers, &http.Server{
			Addr: cfg.HTTPAddr,
			Handler: httpserver.New(svc, issuer, httpserver.Config{
				BasePath:     cfg.HTTPBasePath,
				CookieSecure: cfg.CookieSecure,
				RefreshTTL:   cfg.RefreshTTL,
			}),
			ReadHeaderTimeout: 5 * time.Second,
		})
		logger.Info("REST API enabled", "addr", cfg.HTTPAddr, "base_path", cfg.HTTPBasePath)
	} else if st != nil {
		logger.Warn("no signing key configured (CCC_JWT_SIGNING_KEY empty); REST API disabled")
	}

	opsMux := http.NewServeMux()
	opsMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	opsMux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if st != nil {
			pingCtx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			defer cancel()
			if err := st.Ping(pingCtx); err != nil {
				http.Error(w, "database unreachable", http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	servers = append(servers, &http.Server{
		Addr:              cfg.OpsAddr,
		Handler:           opsMux,
		ReadHeaderTimeout: 5 * time.Second,
	})

	errCh := make(chan error, len(servers))
	for _, srv := range servers {
		go func() {
			logger.Info("listener starting", "addr", srv.Addr)
			errCh <- srv.ListenAndServe()
		}()
	}

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(shutdownCtx)
	}
	logger.Info("stopped")
	return nil
}
