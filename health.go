package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"
)

// Health tracks watcher liveness. The watcher loop calls MarkPoll after every
// successful poll cycle; the /healthz handler reports unhealthy if no poll has
// completed within staleAfter, which catches a hung k8s client or a deadlocked
// loop. Readiness is intentionally absent — nothing routes traffic to this pod.
type Health struct {
	lastPoll   atomic.Int64 // unix nanos
	staleAfter time.Duration
}

// NewHealth creates a Health tracker. staleAfter should be a small multiple of
// the poll interval so a single missed tick doesn't trip the probe.
func NewHealth(staleAfter time.Duration) *Health {
	h := &Health{staleAfter: staleAfter}
	h.MarkPoll()
	return h
}

// MarkPoll records that a poll cycle completed successfully.
func (h *Health) MarkPoll() {
	h.lastPoll.Store(time.Now().UnixNano())
}

// ServeHTTP implements the /healthz handler.
func (h *Health) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	last := time.Unix(0, h.lastPoll.Load())
	age := time.Since(last)
	if age > h.staleAfter {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, "stale: last poll %s ago (threshold %s)\n", age.Round(time.Second), h.staleAfter)
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "ok: last poll %s ago\n", age.Round(time.Second))
}

// RunHealthServer starts the health HTTP server and blocks until ctx is done.
// It performs a graceful shutdown so in-flight probes complete cleanly.
func RunHealthServer(ctx context.Context, addr string, h *Health) error {
	mux := http.NewServeMux()
	mux.Handle("/healthz", h)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("health server listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}
