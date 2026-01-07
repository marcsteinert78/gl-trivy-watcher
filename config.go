package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Config holds all configuration for the trivy-watcher.
type Config struct {
	// GitLab settings
	GitLabAPIURL         string
	GitLabGroupPath      string // e.g., "msteinert1/homeserver"
	GitLabDefaultProject string // Fallback project for unmatched namespaces
	GitLabRef            string

	// Authentication
	DeployToken       string // write_package_registry scope (group-level works for all projects)
	DeployTokenUser   string
	GitLabAccessToken string // PAT or Group Token with api scope (for multi-project pipeline triggers)
	TriggerToken      string // Legacy: project-specific pipeline trigger (single-project only)

	// Timing
	PollInterval  time.Duration
	StabilizeTime time.Duration
	MinTriggerGap time.Duration
	CacheTTL      time.Duration

	// Namespaces to always include (even without VulnerabilityReports)
	AlwaysIncludeNamespaces []string
}

// LoadConfig reads configuration from environment variables.
func LoadConfig() Config {
	return Config{
		GitLabAPIURL:            getEnv("GITLAB_API_URL", "https://gitlab.com/api/v4"),
		GitLabGroupPath:         os.Getenv("GITLAB_GROUP_PATH"),
		GitLabDefaultProject:    os.Getenv("GITLAB_DEFAULT_PROJECT"),
		GitLabRef:               getEnv("GITLAB_REF", "main"),
		DeployToken:             os.Getenv("DEPLOY_TOKEN"),
		DeployTokenUser:         os.Getenv("DEPLOY_TOKEN_USER"),
		GitLabAccessToken:       os.Getenv("GITLAB_ACCESS_TOKEN"),
		TriggerToken:            os.Getenv("TRIGGER_TOKEN"),
		PollInterval:            getDuration("POLL_INTERVAL", 10*time.Second),
		StabilizeTime:           getDuration("STABILIZE_TIME", 60*time.Second),
		MinTriggerGap:           getDuration("MIN_TRIGGER_GAP", 5*time.Minute),
		CacheTTL:                getDuration("CACHE_TTL", 5*time.Minute),
		AlwaysIncludeNamespaces: getStringSlice("ALWAYS_INCLUDE_NAMESPACES", []string{"default"}),
	}
}

// Validate checks that required configuration is present.
func (c Config) Validate() error {
	if c.GitLabDefaultProject == "" {
		return errors.New("GITLAB_DEFAULT_PROJECT is required")
	}
	if c.DeployToken == "" {
		return errors.New("DEPLOY_TOKEN is required")
	}
	if c.DeployTokenUser == "" {
		return errors.New("DEPLOY_TOKEN_USER is required")
	}
	if c.TriggerToken == "" && c.GitLabAccessToken == "" {
		return errors.New("either TRIGGER_TOKEN or GITLAB_ACCESS_TOKEN is required")
	}
	return nil
}

// PrintBanner outputs the startup configuration.
func (c Config) PrintBanner() {
	fmt.Println("=== Trivy Vulnerability Watcher ===")
	fmt.Println()
	fmt.Println("Configuration:")
	fmt.Printf("  GitLab API:        %s\n", c.GitLabAPIURL)
	if c.GitLabGroupPath != "" {
		fmt.Printf("  Group Path:        %s\n", c.GitLabGroupPath)
		fmt.Println("  Resolution:        namespace annotation → group/namespace → default")
	} else {
		fmt.Println("  Resolution:        namespace annotation → default")
	}
	fmt.Printf("  Default Project:   %s\n", c.GitLabDefaultProject)
	fmt.Printf("  Git Ref:           %s\n", c.GitLabRef)
	if len(c.AlwaysIncludeNamespaces) > 0 {
		fmt.Printf("  Always Include:    %v\n", c.AlwaysIncludeNamespaces)
	}
	fmt.Println()
	fmt.Println("Authentication:")
	fmt.Printf("  Deploy Token:      %s (upload)\n", c.DeployTokenUser)
	if c.GitLabAccessToken != "" {
		fmt.Println("  Pipeline Trigger:  Access Token (multi-project)")
	} else {
		fmt.Println("  Pipeline Trigger:  Trigger Token (single-project)")
	}
	fmt.Println()
	fmt.Println("Timing:")
	fmt.Printf("  Poll Interval:     %s\n", c.PollInterval)
	fmt.Printf("  Stabilize Time:    %s\n", c.StabilizeTime)
	fmt.Printf("  Min Trigger Gap:   %s\n", c.MinTriggerGap)
	fmt.Printf("  Cache TTL:         %s\n", c.CacheTTL)
	fmt.Println()
}

// getEnv returns environment variable or default value.
func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// getDuration parses duration from environment or returns default.
func getDuration(key string, defaultVal time.Duration) time.Duration {
	if val := os.Getenv(key); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			return d
		}
	}
	return defaultVal
}

// getStringSlice parses comma-separated string from environment or returns default.
func getStringSlice(key string, defaultVal []string) []string {
	if val := os.Getenv(key); val != "" {
		parts := strings.Split(val, ",")
		var result []string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				result = append(result, p)
			}
		}
		return result
	}
	return defaultVal
}
