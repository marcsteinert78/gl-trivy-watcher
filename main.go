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
	GitLabProjectID string
	GitLabToken     string
	GitLabRef       string
	GitLabAPIURL    string
	PollInterval    time.Duration
	StabilizeTime   time.Duration
	MinTriggerGap   time.Duration
}

func main() {
	cfg := Config{
		GitLabProjectID: os.Getenv("GITLAB_PROJECT_ID"),
		GitLabToken:     os.Getenv("GITLAB_TOKEN"),
		GitLabRef:       getEnvOrDefault("GITLAB_REF", "main"),
		GitLabAPIURL:    getEnvOrDefault("GITLAB_API_URL", "https://gitlab.com/api/v4"),
		PollInterval:    getDurationEnv("POLL_INTERVAL", 10*time.Second),
		StabilizeTime:   getDurationEnv("STABILIZE_TIME", 60*time.Second),
		MinTriggerGap:   getDurationEnv("MIN_TRIGGER_GAP", 5*time.Minute),
	}

	if cfg.GitLabProjectID == "" || cfg.GitLabToken == "" {
		fmt.Println("ERROR: GITLAB_PROJECT_ID and GITLAB_TOKEN required")
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

	fmt.Println("=== Trivy GitLab Reporter ===")
	fmt.Printf("Project: %s, Ref: %s\n", cfg.GitLabProjectID, cfg.GitLabRef)
	fmt.Printf("Poll: %s, Stabilize: %s, MinGap: %s\n",
		cfg.PollInterval, cfg.StabilizeTime, cfg.MinTriggerGap)

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

	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reports, err := client.Resource(vulnGVR).List(ctx, metav1.ListOptions{})
			if err != nil {
				fmt.Printf("ERROR: Failed to list reports: %v\n", err)
				continue
			}

			// Generate report and hash
			secReport := convertToGitLabReport(reports.Items)
			reportJSON, _ := json.Marshal(secReport)
			hash := fmt.Sprintf("%x", sha256.Sum256(reportJSON))[:16]

			now := time.Now()

			// First run
			if lastHash == "" {
				fmt.Printf("Initial hash: %s (%d vulns)\n", hash, len(secReport.Vulnerabilities))
				lastHash = hash
				stableSince = now
				continue
			}

			// Hash changed
			if hash != lastHash {
				fmt.Printf("Changed: %s -> %s\n", lastHash, hash)
				lastHash = hash
				stableSince = now
				continue
			}

			// Check stabilization
			stableFor := now.Sub(stableSince)
			if stableFor < cfg.StabilizeTime {
				continue
			}

			// Already triggered this hash
			if hash == lastTriggeredHash {
				continue
			}

			// Min gap between triggers
			if now.Sub(lastTriggerTime) < cfg.MinTriggerGap {
				continue
			}

			// Trigger!
			fmt.Printf("Stable for %s - uploading report (%d vulns)...\n",
				stableFor.Round(time.Second), len(secReport.Vulnerabilities))

			reportURL, err := uploadToPackageRegistry(cfg, reportJSON)
			if err != nil {
				fmt.Printf("ERROR: Upload failed: %v\n", err)
				continue
			}

			if err := triggerPipeline(cfg, reportURL); err != nil {
				fmt.Printf("ERROR: Trigger failed: %v\n", err)
				continue
			}

			fmt.Println("Pipeline triggered successfully")
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

	req, err := http.NewRequest("PUT", uploadURL, &buf)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("PRIVATE-TOKEN", cfg.GitLabToken)
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

func triggerPipeline(cfg Config, reportURL string) error {
	triggerURL := fmt.Sprintf("%s/projects/%s/trigger/pipeline",
		cfg.GitLabAPIURL, url.PathEscape(cfg.GitLabProjectID))

	data := url.Values{
		"token":                        {cfg.GitLabToken},
		"ref":                          {cfg.GitLabRef},
		"variables[TRIVY_REPORT_URL]":  {reportURL},
		"variables[TRIGGER_JOB]":       {"trivy:cluster-scan"},
	}

	resp, err := http.PostForm(triggerURL, data)
	if err != nil {
		return fmt.Errorf("trigger: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("trigger failed: %d - %s", resp.StatusCode, string(body))
	}
	return nil
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
