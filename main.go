// Package main implements trivy-watcher, a tool that monitors Kubernetes
// VulnerabilityReports and uploads them to GitLab's Security Dashboard.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

func main() {
	// Structured logging to stderr (k8s collects both stdout and stderr).
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	cfg := LoadConfig()

	if err := cfg.Validate(); err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	client, err := createK8sClient()
	if err != nil {
		slog.Error("failed to create kubernetes client", "error", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		slog.Info("shutdown signal received")
		cancel()
	}()

	cfg.LogStartup()

	// Liveness threshold: 3x poll interval, with a 30s floor so very short
	// intervals don't make the probe flap on transient slow API calls.
	staleAfter := 3 * cfg.PollInterval
	if staleAfter < 30*time.Second {
		staleAfter = 30 * time.Second
	}
	health := NewHealth(staleAfter)

	go func() {
		if err := RunHealthServer(ctx, cfg.HealthAddr, health); err != nil {
			slog.Error("health server stopped", "error", err)
			cancel()
		}
	}()

	runWatcher(ctx, client, cfg, health)
}

// createK8sClient creates a Kubernetes dynamic client using in-cluster config.
func createK8sClient() (dynamic.Interface, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster config: %w", err)
	}
	return dynamic.NewForConfig(config)
}
