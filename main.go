// Package main implements trivy-watcher, a tool that monitors Kubernetes
// VulnerabilityReports and uploads them to GitLab's Security Dashboard.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

func main() {
	cfg := LoadConfig()

	if err := cfg.Validate(); err != nil {
		fmt.Printf("ERROR: %v\n", err)
		os.Exit(1)
	}

	client, err := createK8sClient()
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		cancel()
	}()

	cfg.PrintBanner()
	runWatcher(ctx, client, cfg)
}

// createK8sClient creates a Kubernetes dynamic client using in-cluster config.
func createK8sClient() (dynamic.Interface, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get k8s config: %w", err)
	}

	client, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s client: %w", err)
	}

	return client, nil
}
