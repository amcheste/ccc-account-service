// Command account-service runs the CCC account service: identity,
// credentials, and token issuance for the Command and Control Center.
//
// Current state: ops listener plus the persistence layer. When a
// database is configured (CCC_DB_HOST set), migrations run at startup
// and readiness gates on the database ping. The REST (:8080) and gRPC
// (:9090) listeners land with the service and auth packages. See
// docs/design/account-service.md.
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

	"github.com/amcheste/ccc-account-service/internal/config"
	"github.com/amcheste/ccc-account-service/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	cfg := config.Load()

	var st store.Store
	if dsn := cfg.DatabaseURL(); dsn != "" {
		if err := store.Migrate(dsn); err != nil {
			logger.Error("migrations failed", "error", err)
			os.Exit(1)
		}
		pg, err := store.Connect(context.Background(), dsn)
		if err != nil {
			logger.Error("database connection failed", "error", err)
			os.Exit(1)
		}
		defer pg.Close()
		st = pg
		logger.Info("database connected, migrations applied",
			"host", cfg.DBHost, "database", cfg.DBName)
	} else {
		logger.Warn("no database configured (CCC_DB_HOST empty); running in skeleton mode")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if st != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			defer cancel()
			if err := st.Ping(ctx); err != nil {
				http.Error(w, "database unreachable", http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	ops := &http.Server{
		Addr:              cfg.OpsAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("ops listener starting", "addr", cfg.OpsAddr)
		errCh <- ops.ListenAndServe()
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("ops listener failed", "error", err)
			os.Exit(1)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := ops.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown incomplete", "error", err)
	}
	logger.Info("stopped")
}
