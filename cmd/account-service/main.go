// Command account-service runs the CCC account service: identity,
// credentials, and token issuance for the Command and Control Center.
//
// Skeleton state: only the ops listener (health endpoints) is wired.
// The REST (:8080) and gRPC (:9090) listeners land with the service,
// store, and auth packages. See docs/design/account-service.md.
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
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	cfg := config.Load()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		// TODO(design §5): fail readiness when the database ping fails
		// once the store package exists.
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
