package main

import (
	"errors"
	"log/slog"
	"os"
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

	// Timing
	PollInterval  time.Duration
	StabilizeTime time.Duration
	MinTriggerGap time.Duration
	CacheTTL      time.Duration

	// HealthAddr is the listen address for the /healthz endpoint.
	HealthAddr string
}

// LoadConfig reads configuration from environment variables.
func LoadConfig() Config {
	return Config{
		GitLabAPIURL:         getEnv("GITLAB_API_URL", "https://gitlab.com/api/v4"),
		GitLabGroupPath:      os.Getenv("GITLAB_GROUP_PATH"),
		GitLabDefaultProject: os.Getenv("GITLAB_DEFAULT_PROJECT"),
		GitLabRef:            getEnv("GITLAB_REF", "main"),
		DeployToken:          os.Getenv("DEPLOY_TOKEN"),
		DeployTokenUser:      os.Getenv("DEPLOY_TOKEN_USER"),
		GitLabAccessToken:    os.Getenv("GITLAB_ACCESS_TOKEN"),
		PollInterval:         getDuration("POLL_INTERVAL", 10*time.Second),
		StabilizeTime:        getDuration("STABILIZE_TIME", 60*time.Second),
		MinTriggerGap:        getDuration("MIN_TRIGGER_GAP", 5*time.Minute),
		CacheTTL:             getDuration("CACHE_TTL", 5*time.Minute),
		HealthAddr:           getEnv("HEALTH_ADDR", ":8080"),
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
	if c.GitLabAccessToken == "" {
		return errors.New("GITLAB_ACCESS_TOKEN is required")
	}
	return nil
}

// LogStartup logs the effective configuration as a structured slog record.
// Keeping startup output on the same stream as the rest of the logs makes
// log aggregation in k8s simpler and avoids interleaving stdout/stderr.
func (c Config) LogStartup() {
	resolution := "namespace annotation → default"
	if c.GitLabGroupPath != "" {
		resolution = "namespace annotation → group/namespace → default"
	}
	slog.Info("trivy-watcher starting",
		"gitlab_api", c.GitLabAPIURL,
		"group_path", c.GitLabGroupPath,
		"default_project", c.GitLabDefaultProject,
		"git_ref", c.GitLabRef,
		"resolution", resolution,
		"deploy_token_user", c.DeployTokenUser,
		"poll_interval", c.PollInterval,
		"stabilize_time", c.StabilizeTime,
		"min_trigger_gap", c.MinTriggerGap,
		"cache_ttl", c.CacheTTL,
		"health_addr", c.HealthAddr,
	)
}

// getEnv returns environment variable or default value.
func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// getDuration parses duration from environment or returns default. If the
// value is set but unparseable, log a warning so misconfigurations don't
// silently fall back to defaults.
func getDuration(key string, defaultVal time.Duration) time.Duration {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		slog.Warn("invalid duration env var, using default",
			"var", key,
			"value", val,
			"error", err,
			"default", defaultVal,
		)
		return defaultVal
	}
	return d
}
