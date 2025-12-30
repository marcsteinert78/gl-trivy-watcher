package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

// GitLab Security Report format
type SecurityReport struct {
	Version         string          `json:"version"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Scan            ScanInfo        `json:"scan"`
}

type Vulnerability struct {
	ID          string   `json:"id"`
	Category    string   `json:"category"`
	Name        string   `json:"name"`
	Message     string   `json:"message"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Location    Location `json:"location"`
	Identifiers []Ident  `json:"identifiers"`
	Links       []Link   `json:"links,omitempty"`
}

type Location struct {
	Image           string `json:"image"`
	OperatingSystem string `json:"operating_system,omitempty"`
}

type Ident struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	URL   string `json:"url,omitempty"`
}

type Link struct {
	URL string `json:"url"`
}

type ScanInfo struct {
	Scanner Scanner `json:"scanner"`
	Type    string  `json:"type"`
	Status  string  `json:"status"`
	StartAt string  `json:"start_time"`
	EndAt   string  `json:"end_time"`
}

type Scanner struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	URL     string `json:"url"`
}

type Config struct {
	GitLabProjectID  string
	GitLabRef        string
	GitLabAPIURL     string
	// Separate tokens for minimal permissions
	DeployToken      string // write_package_registry scope only
	DeployTokenUser  string // Deploy token username
	TriggerToken     string // Pipeline trigger token (can only trigger)
	PollInterval     time.Duration
	StabilizeTime    time.Duration
	MinTriggerGap    time.Duration
}

func main() {
	cfg := Config{
		GitLabProjectID: os.Getenv("GITLAB_PROJECT_ID"),
		GitLabRef:       getEnvOrDefault("GITLAB_REF", "main"),
		GitLabAPIURL:    getEnvOrDefault("GITLAB_API_URL", "https://gitlab.com/api/v4"),
		// Minimal permission tokens
		DeployToken:     os.Getenv("DEPLOY_TOKEN"),      // write_package_registry only
		DeployTokenUser: os.Getenv("DEPLOY_TOKEN_USER"), // e.g., "gitlab+deploy-token-123"
		TriggerToken:    os.Getenv("TRIGGER_TOKEN"),     // pipeline trigger only
		PollInterval:    getDurationEnv("POLL_INTERVAL", 10*time.Second),
		StabilizeTime:   getDurationEnv("STABILIZE_TIME", 60*time.Second),
		MinTriggerGap:   getDurationEnv("MIN_TRIGGER_GAP", 5*time.Minute),
	}

	if cfg.GitLabProjectID == "" {
		fmt.Println("ERROR: GITLAB_PROJECT_ID required")
		os.Exit(1)
	}
	if cfg.DeployToken == "" || cfg.DeployTokenUser == "" {
		fmt.Println("ERROR: DEPLOY_TOKEN and DEPLOY_TOKEN_USER required")
		os.Exit(1)
	}
	if cfg.TriggerToken == "" {
		fmt.Println("ERROR: TRIGGER_TOKEN required")
		os.Exit(1)
	}

	// In-cluster Kubernetes config
	k8sConfig, err := rest.InClusterConfig()
	if err != nil {
		fmt.Printf("ERROR: Failed to get k8s config: %v\n", err)
		os.Exit(1)
	}

	client, err := dynamic.NewForConfig(k8sConfig)
	if err != nil {
		fmt.Printf("ERROR: Failed to create k8s client: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		cancel()
	}()

	fmt.Println("=== Trivy Vulnerability Watcher ===")
	fmt.Printf("GitLab Project: %s\n", cfg.GitLabProjectID)
	fmt.Printf("Poll Interval: %s\n", cfg.PollInterval)
	fmt.Printf("Stabilization Time: %s\n", cfg.StabilizeTime)
	fmt.Printf("Min Change Interval: %s\n", cfg.MinTriggerGap)
	fmt.Printf("GitLab Ref: %s\n", cfg.GitLabRef)
	fmt.Println()

	runWatcher(ctx, client, cfg)
}

func runWatcher(ctx context.Context, client dynamic.Interface, cfg Config) {
	var lastHash string
	var stableSince time.Time
	var lastTriggeredHash string
	var lastTriggerTime time.Time

	vulnGVR := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "vulnerabilityreports",
	}

	fmt.Println("Starting metrics monitoring...")

	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reports, err := client.Resource(vulnGVR).List(ctx, metav1.ListOptions{})
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error fetching reports: %v\n", err)
				continue
			}

			// Generate report and hash (hash only vulns, not timestamps)
			secReport := convertToGitLabReport(reports.Items)
			vulnsJSON, _ := json.Marshal(secReport.Vulnerabilities)
			hash := fmt.Sprintf("%x", sha256.Sum256(vulnsJSON))[:16]

			now := time.Now()

			// First run
			if lastHash == "" {
				fmt.Printf("Initial metrics hash: %s...\n", hash)
				lastHash = hash
				stableSince = now
				continue
			}

			// Hash changed
			if hash != lastHash {
				fmt.Printf("Metrics changed: %s... → %s...\n", lastHash, hash)
				fmt.Println("  Waiting for scans to stabilize...")
				lastHash = hash
				stableSince = now
				continue
			}

			// Check stabilization
			stableFor := now.Sub(stableSince)
			stableSec := int(stableFor.Seconds())
			stabilizeSec := int(cfg.StabilizeTime.Seconds())

			if stableFor < cfg.StabilizeTime {
				remaining := stabilizeSec - stableSec
				fmt.Printf("Metrics stable for %ds, waiting %ds more...\n", stableSec, remaining)
				continue
			}

			// Already triggered this hash
			if hash == lastTriggeredHash {
				fmt.Printf("Metrics stable for %ds, but already triggered for this hash. Waiting for changes...\n", stableSec)
				continue
			}

			// Min gap between triggers
			timeSinceTrigger := now.Sub(lastTriggerTime)
			if lastTriggerTime.Unix() > 0 && timeSinceTrigger < cfg.MinTriggerGap {
				remaining := int((cfg.MinTriggerGap - timeSinceTrigger).Seconds())
				fmt.Printf("Metrics stable, but triggered %ds ago. Waiting %ds more...\n",
					int(timeSinceTrigger.Seconds()), remaining)
				continue
			}

			// Trigger!
			fmt.Printf("Metrics stable for %ds - triggering pipeline...\n", stableSec)

			reportJSON, _ := json.Marshal(secReport)
			reportURL, err := uploadToPackageRegistry(cfg, reportJSON)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error uploading report: %v\n", err)
				continue
			}

			status, err := triggerPipeline(cfg, reportURL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error triggering pipeline: %v\n", err)
				continue
			}

			fmt.Printf("✓ Pipeline triggered successfully at %s\n", time.Now().UTC().Format(time.RFC3339))
			fmt.Printf("  Response: %d\n", status)
			lastTriggeredHash = hash
			lastTriggerTime = now
		}
	}
}

func convertToGitLabReport(items []unstructured.Unstructured) SecurityReport {
	var vulns []Vulnerability
	now := time.Now().UTC().Format(time.RFC3339)

	for _, item := range items {
		report, _, _ := unstructured.NestedMap(item.Object, "report")
		if report == nil {
			continue
		}

		artifact, _, _ := unstructured.NestedMap(report, "artifact")
		image, _ := artifact["repository"].(string)
		tag, _ := artifact["tag"].(string)
		if tag == "" {
			tag = "latest"
		}
		fullImage := fmt.Sprintf("%s:%s", image, tag)

		vulnList, _, _ := unstructured.NestedSlice(report, "vulnerabilities")
		for _, v := range vulnList {
			vuln, ok := v.(map[string]interface{})
			if !ok {
				continue
			}

			vulnID, _ := vuln["vulnerabilityID"].(string)
			severity, _ := vuln["severity"].(string)
			pkgName, _ := vuln["resource"].(string)
			title, _ := vuln["title"].(string)
			primaryURL, _ := vuln["primaryLink"].(string)

			desc := title
			if d, ok := vuln["description"].(string); ok && d != "" {
				desc = d
			}

			vulns = append(vulns, Vulnerability{
				ID:          fmt.Sprintf("%s-%s-%s", vulnID, sanitize(image), pkgName),
				Category:    "container_scanning",
				Name:        vulnID,
				Message:     fmt.Sprintf("%s in %s (%s)", vulnID, pkgName, fullImage),
				Description: firstN(desc, 500),
				Severity:    mapSeverity(severity),
				Location:    Location{Image: fullImage},
				Identifiers: []Ident{{
					Type:  "cve",
					Name:  vulnID,
					Value: vulnID,
					URL:   primaryURL,
				}},
				Links: []Link{{URL: primaryURL}},
			})
		}
	}

	// Sort for consistent hashing
	sort.Slice(vulns, func(i, j int) bool {
		return vulns[i].ID < vulns[j].ID
	})

	return SecurityReport{
		Version:         "15.0.0",
		Vulnerabilities: vulns,
		Scan: ScanInfo{
			Scanner: Scanner{
				ID:      "trivy",
				Name:    "Trivy Operator",
				Version: "0.50.0",
				URL:     "https://github.com/aquasecurity/trivy-operator",
			},
			Type:    "container_scanning",
			Status:  "success",
			StartAt: now,
			EndAt:   now,
		},
	}
}

func uploadToPackageRegistry(cfg Config, report []byte) (string, error) {
	// Compress report
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(report); err != nil {
		return "", fmt.Errorf("gzip write: %w", err)
	}
	if err := gz.Close(); err != nil {
		return "", fmt.Errorf("gzip close: %w", err)
	}

	timestamp := time.Now().Unix()
	filename := fmt.Sprintf("trivy-report-%d.json.gz", timestamp)

	uploadURL := fmt.Sprintf("%s/projects/%s/packages/generic/trivy-reports/1.0.0/%s",
		cfg.GitLabAPIURL, url.PathEscape(cfg.GitLabProjectID), filename)

	fmt.Printf("DEBUG: Upload URL: %s\n", uploadURL)
	fmt.Printf("DEBUG: User: %s, Token length: %d\n", cfg.DeployTokenUser, len(cfg.DeployToken))

	req, err := http.NewRequest("PUT", uploadURL, &buf)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	// Use Deploy Token with Basic Auth (minimal permissions: write_package_registry)
	req.SetBasicAuth(cfg.DeployTokenUser, cfg.DeployToken)
	req.Header.Set("Content-Type", "application/gzip")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("upload: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("upload failed: %d - %s", resp.StatusCode, string(body))
	}

	// Return download URL
	downloadURL := fmt.Sprintf("%s/projects/%s/packages/generic/trivy-reports/1.0.0/%s",
		cfg.GitLabAPIURL, url.PathEscape(cfg.GitLabProjectID), filename)

	return downloadURL, nil
}

func triggerPipeline(cfg Config, reportURL string) (int, error) {
	triggerURL := fmt.Sprintf("%s/projects/%s/trigger/pipeline",
		cfg.GitLabAPIURL, url.PathEscape(cfg.GitLabProjectID))

	// Use Pipeline Trigger Token (minimal permissions: can only trigger pipelines)
	data := url.Values{
		"token":                       {cfg.TriggerToken},
		"ref":                         {cfg.GitLabRef},
		"variables[TRIVY_REPORT_URL]": {reportURL},
		"variables[TRIGGER_JOB]":      {"trivy:cluster-scan"},
	}

	resp, err := http.PostForm(triggerURL, data)
	if err != nil {
		return 0, fmt.Errorf("trigger: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, fmt.Errorf("trigger failed: %d - %s", resp.StatusCode, string(body))
	}
	return resp.StatusCode, nil
}

func mapSeverity(s string) string {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return "Critical"
	case "HIGH":
		return "High"
	case "MEDIUM":
		return "Medium"
	case "LOW":
		return "Low"
	default:
		return "Unknown"
	}
}

func sanitize(s string) string {
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, ":", "-")
	return s
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func getEnvOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getDurationEnv(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
