package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Generic Package Registry coordinates for the uploaded report. We always
// publish to the same package/version/filename so consuming pipelines can
// fetch from a stable URL.
const (
	packageName    = "trivy-reports"
	packageVersion = "1.0.0"
	reportFilename = "trivy-report-latest.json.gz"

	// triggerVariable is set on triggered pipelines so CI rules can
	// distinguish trivy-watcher runs from regular branch/MR pipelines.
	triggerVariable = "TRIVY_TRIGGERED"
)

// uploadAndTrigger uploads a security report and triggers the CI pipeline.
func uploadAndTrigger(cfg Config, project string, report SecurityReport) error {
	reportJSON, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}

	if err := uploadToPackageRegistry(cfg, project, reportJSON); err != nil {
		return fmt.Errorf("upload: %w", err)
	}

	if err := triggerPipeline(cfg, project); err != nil {
		return fmt.Errorf("trigger: %w", err)
	}

	return nil
}

// uploadToPackageRegistry uploads a gzipped report to GitLab Package Registry.
func uploadToPackageRegistry(cfg Config, project string, report []byte) error {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(report); err != nil {
		return fmt.Errorf("gzip write: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("gzip close: %w", err)
	}

	uploadURL := fmt.Sprintf("%s/projects/%s/packages/generic/%s/%s/%s",
		cfg.GitLabAPIURL, url.PathEscape(project), packageName, packageVersion, reportFilename)

	req, err := http.NewRequest("PUT", uploadURL, &buf)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.SetBasicAuth(cfg.DeployTokenUser, cfg.DeployToken)
	req.Header.Set("Content-Type", "application/gzip")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// triggerPipeline triggers a GitLab CI pipeline for the project using the
// /pipeline API with PRIVATE-TOKEN. The TRIVY_TRIGGERED variable lets CI rules
// distinguish trivy-watcher pipelines from other API-triggered pipelines.
func triggerPipeline(cfg Config, project string) error {
	pipelineURL := fmt.Sprintf("%s/projects/%s/pipeline",
		cfg.GitLabAPIURL, url.PathEscape(project))

	body := fmt.Sprintf(`{"ref":"%s","variables":[{"key":"%s","value":"true"}]}`, cfg.GitLabRef, triggerVariable)
	req, err := http.NewRequest("POST", pipelineURL, strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("PRIVATE-TOKEN", cfg.GitLabAccessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
