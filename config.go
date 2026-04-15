package main

import (
	"errors"
	"fmt"
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

	// AutoResolveEnabled turns on the auto-resolution of stale vulnerabilities
	// in GitLab. When enabled, after each successful namespace upload the watcher
	// queries GitLab for all "detected" vulnerabilities in that project and
	// marks any that are NOT in the current cluster scan as "resolved".
	//
	// Matching key: (CVE-ID, namespace, container, package). This deliberately
	// ignores the image tag so image bumps (2.20.7 -> 2.20.14) correctly
	// resolve the old findings.
	AutoResolveEnabled bool

	// AutoResolveDryRun logs what would be resolved without calling the GitLab
	// resolution API. Use to validate matching logic before enabling writes.
	AutoResolveDryRun bool

	// AutoResolveMaxPerRun caps the number of vulnerabilities resolved per
	// namespace upload cycle, so a bulk-reset accident can't wipe the entire
	// GitLab vulnerability list in one go.
	AutoResolveMaxPerRun int
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
		AutoResolveEnabled:   getBool("AUTO_RESOLVE_ENABLED", false),
		AutoResolveDryRun:    getBool("AUTO_RESOLVE_DRY_RUN", true),
		AutoResolveMaxPerRun: getInt("AUTO_RESOLVE_MAX_PER_RUN", 500),
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
		"auto_resolve_enabled", c.AutoResolveEnabled,
		"auto_resolve_dry_run", c.AutoResolveDryRun,
		"auto_resolve_max_per_run", c.AutoResolveMaxPerRun,
	)
}

// getEnv returns environment variable or default value.
func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// getBool parses a bool from environment. Accepts "1", "true", "yes" (any case).
func getBool(key string, defaultVal bool) bool {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	switch val {
	case "1", "true", "TRUE", "True", "yes", "YES", "Yes":
		return true
	case "0", "false", "FALSE", "False", "no", "NO", "No":
		return false
	}
	slog.Warn("invalid bool env var, using default", "var", key, "value", val, "default", defaultVal)
	return defaultVal
}

// getInt parses an int from environment or returns default.
func getInt(key string, defaultVal int) int {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	var n int
	if _, err := fmt.Sscanf(val, "%d", &n); err != nil {
		slog.Warn("invalid int env var, using default", "var", key, "value", val, "error", err, "default", defaultVal)
		return defaultVal
	}
	return n
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
