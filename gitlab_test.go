package main

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUploadToPackageRegistry(t *testing.T) {
	var receivedBody []byte
	var receivedAuth string
	var receivedContentType string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check method
		if r.Method != "PUT" {
			t.Errorf("Expected PUT, got %s", r.Method)
		}

		// Check path
		if !strings.Contains(r.URL.Path, "/packages/generic/trivy-reports/") {
			t.Errorf("Unexpected path: %s", r.URL.Path)
		}

		// Read auth
		user, pass, ok := r.BasicAuth()
		if ok {
			receivedAuth = user + ":" + pass
		}

		receivedContentType = r.Header.Get("Content-Type")

		// Read body
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("Failed to read body: %v", err)
		}

		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	cfg := Config{
		GitLabAPIURL:    server.URL,
		DeployToken:     "test-token",
		DeployTokenUser: "test-user",
	}

	report := []byte(`{"version":"15.0.0","vulnerabilities":[]}`)
	err := uploadToPackageRegistry(cfg, "group/project", report)

	if err != nil {
		t.Fatalf("uploadToPackageRegistry failed: %v", err)
	}

	// Verify auth
	if receivedAuth != "test-user:test-token" {
		t.Errorf("Auth = %q, want 'test-user:test-token'", receivedAuth)
	}

	// Verify content type
	if receivedContentType != "application/gzip" {
		t.Errorf("Content-Type = %q, want 'application/gzip'", receivedContentType)
	}

	// Verify gzip content
	if len(receivedBody) == 0 {
		t.Error("Body should not be empty")
	}

	// Decompress and verify
	reader, err := gzip.NewReader(strings.NewReader(string(receivedBody)))
	if err != nil {
		t.Fatalf("Failed to create gzip reader: %v", err)
	}
	decompressed, _ := io.ReadAll(reader)
	if string(decompressed) != string(report) {
		t.Errorf("Decompressed content mismatch")
	}
}

func TestUploadToPackageRegistryError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
	}))
	defer server.Close()

	cfg := Config{
		GitLabAPIURL:    server.URL,
		DeployToken:     "token",
		DeployTokenUser: "user",
	}

	err := uploadToPackageRegistry(cfg, "group/project", []byte("{}"))

	if err == nil {
		t.Error("Expected error for 403 response")
	}

	if !strings.Contains(err.Error(), "403") {
		t.Errorf("Error should contain status code: %v", err)
	}
}

func TestTriggerPipeline(t *testing.T) {
	var receivedToken string
	var receivedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}

		if !strings.HasSuffix(r.URL.Path, "/pipeline") {
			t.Errorf("Unexpected path: %s", r.URL.Path)
		}

		receivedToken = r.Header.Get("PRIVATE-TOKEN")

		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedBody)

		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":123}`))
	}))
	defer server.Close()

	cfg := Config{
		GitLabAPIURL:      server.URL,
		GitLabAccessToken: "access-token-123",
		GitLabRef:         "main",
	}

	err := triggerPipeline(cfg, "group/project")

	if err != nil {
		t.Fatalf("triggerPipeline failed: %v", err)
	}

	if receivedToken != "access-token-123" {
		t.Errorf("Token = %q, want 'access-token-123'", receivedToken)
	}

	if receivedBody["ref"] != "main" {
		t.Errorf("ref = %v, want 'main'", receivedBody["ref"])
	}

	// Check TRIVY_TRIGGERED variable
	variables, ok := receivedBody["variables"].([]interface{})
	if !ok || len(variables) == 0 {
		t.Error("Expected variables array in request body")
	} else {
		v := variables[0].(map[string]interface{})
		if v["key"] != "TRIVY_TRIGGERED" || v["value"] != "true" {
			t.Errorf("Expected TRIVY_TRIGGERED=true, got %v", v)
		}
	}
}

func TestUploadAndTrigger(t *testing.T) {
	uploadCalled := false
	triggerCalled := false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/packages/") {
			uploadCalled = true
			w.WriteHeader(http.StatusCreated)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/pipeline") {
			triggerCalled = true
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cfg := Config{
		GitLabAPIURL:      server.URL,
		GitLabAccessToken: "token",
		DeployToken:       "deploy",
		DeployTokenUser:   "user",
		GitLabRef:         "main",
	}

	report := SecurityReport{Version: "15.0.0"}
	err := uploadAndTrigger(cfg, "group/project", report)

	if err != nil {
		t.Fatalf("uploadAndTrigger failed: %v", err)
	}

	if !uploadCalled {
		t.Error("Upload should be called")
	}

	if !triggerCalled {
		t.Error("Trigger should be called")
	}
}

func TestUploadAndTriggerUploadFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cfg := Config{
		GitLabAPIURL:    server.URL,
		DeployToken:     "token",
		DeployTokenUser: "user",
	}

	report := SecurityReport{Version: "15.0.0"}
	err := uploadAndTrigger(cfg, "group/project", report)

	if err == nil {
		t.Error("Expected error when upload fails")
	}

	if !strings.Contains(err.Error(), "upload") {
		t.Errorf("Error should mention upload: %v", err)
	}
}

