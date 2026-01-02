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

	filename := "trivy-report-latest.json.gz"
	uploadURL := fmt.Sprintf("%s/projects/%s/packages/generic/trivy-reports/1.0.0/%s",
		cfg.GitLabAPIURL, url.PathEscape(project), filename)

	req, err := http.NewRequest("PUT", uploadURL, &buf)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.SetBasicAuth(cfg.DeployTokenUser, cfg.DeployToken)
	req.Header.Set("Content-Type", "application/gzip")

	resp, err := http.DefaultClient.Do(req)
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

// triggerPipeline triggers a GitLab CI pipeline for the project.
func triggerPipeline(cfg Config, project string) error {
	// Prefer GitLabAccessToken (works across projects) over TriggerToken (project-specific)
	if cfg.GitLabAccessToken != "" {
		return triggerPipelineWithAccessToken(cfg, project)
	}
	return triggerPipelineWithTriggerToken(cfg, project)
}

// triggerPipelineWithAccessToken uses the /pipeline API with PRIVATE-TOKEN.
func triggerPipelineWithAccessToken(cfg Config, project string) error {
	pipelineURL := fmt.Sprintf("%s/projects/%s/pipeline",
		cfg.GitLabAPIURL, url.PathEscape(project))

	// Pass TRIVY_TRIGGERED variable so CI can detect trivy-watcher triggers.
	// This is more elegant than checking CI_PIPELINE_SOURCE since it works
	// regardless of whether we use /pipeline (source=api) or /trigger/pipeline (source=trigger).
	body := fmt.Sprintf(`{"ref":"%s","variables":[{"key":"TRIVY_TRIGGERED","value":"true"}]}`, cfg.GitLabRef)
	req, err := http.NewRequest("POST", pipelineURL, strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("PRIVATE-TOKEN", cfg.GitLabAccessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
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

// triggerPipelineWithTriggerToken uses the /trigger/pipeline API (legacy).
func triggerPipelineWithTriggerToken(cfg Config, project string) error {
	triggerURL := fmt.Sprintf("%s/projects/%s/trigger/pipeline",
		cfg.GitLabAPIURL, url.PathEscape(project))

	data := url.Values{
		"token": {cfg.TriggerToken},
		"ref":   {cfg.GitLabRef},
	}

	resp, err := http.PostForm(triggerURL, data)
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
