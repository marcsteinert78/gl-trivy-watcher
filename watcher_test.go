package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestCountTotalVulnerabilities(t *testing.T) {
	tests := []struct {
		name     string
		items    []unstructured.Unstructured
		expected int
	}{
		{
			name:     "empty items",
			items:    []unstructured.Unstructured{},
			expected: 0,
		},
		{
			name: "single report with 2 vulnerabilities",
			items: []unstructured.Unstructured{
				{
					Object: map[string]interface{}{
						"report": map[string]interface{}{
							"vulnerabilities": []interface{}{
								map[string]interface{}{"vulnerabilityID": "CVE-1"},
								map[string]interface{}{"vulnerabilityID": "CVE-2"},
							},
						},
					},
				},
			},
			expected: 2,
		},
		{
			name: "multiple reports",
			items: []unstructured.Unstructured{
				{
					Object: map[string]interface{}{
						"report": map[string]interface{}{
							"vulnerabilities": []interface{}{
								map[string]interface{}{"vulnerabilityID": "CVE-1"},
							},
						},
					},
				},
				{
					Object: map[string]interface{}{
						"report": map[string]interface{}{
							"vulnerabilities": []interface{}{
								map[string]interface{}{"vulnerabilityID": "CVE-2"},
								map[string]interface{}{"vulnerabilityID": "CVE-3"},
							},
						},
					},
				},
			},
			expected: 3,
		},
		{
			name: "report without vulnerabilities field",
			items: []unstructured.Unstructured{
				{
					Object: map[string]interface{}{
						"report": map[string]interface{}{
							"artifact": map[string]interface{}{"repository": "nginx"},
						},
					},
				},
			},
			expected: 0,
		},
		{
			name: "report without report field",
			items: []unstructured.Unstructured{
				{
					Object: map[string]interface{}{
						"metadata": map[string]interface{}{"name": "test"},
					},
				},
			},
			expected: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := countTotalVulnerabilities(tc.items)
			if result != tc.expected {
				t.Errorf("countTotalVulnerabilities() = %d, want %d", result, tc.expected)
			}
		})
	}
}

func TestComputeGlobalHash(t *testing.T) {
	items := []unstructured.Unstructured{
		{
			Object: map[string]interface{}{
				"metadata": map[string]interface{}{
					"name":            "report-1",
					"resourceVersion": "12345",
				},
			},
		},
		{
			Object: map[string]interface{}{
				"metadata": map[string]interface{}{
					"name":            "report-2",
					"resourceVersion": "67890",
				},
			},
		},
	}

	hash1 := computeGlobalHash(items)
	hash2 := computeGlobalHash(items)

	if hash1 != hash2 {
		t.Errorf("Hash should be deterministic: %s vs %s", hash1, hash2)
	}

	if len(hash1) != 16 {
		t.Errorf("Hash should be 16 chars, got %d", len(hash1))
	}
}

func TestComputeGlobalHashDifferentOrder(t *testing.T) {
	items1 := []unstructured.Unstructured{
		{Object: map[string]interface{}{"metadata": map[string]interface{}{"name": "a", "resourceVersion": "1"}}},
		{Object: map[string]interface{}{"metadata": map[string]interface{}{"name": "b", "resourceVersion": "2"}}},
	}

	items2 := []unstructured.Unstructured{
		{Object: map[string]interface{}{"metadata": map[string]interface{}{"name": "b", "resourceVersion": "2"}}},
		{Object: map[string]interface{}{"metadata": map[string]interface{}{"name": "a", "resourceVersion": "1"}}},
	}

	hash1 := computeGlobalHash(items1)
	hash2 := computeGlobalHash(items2)

	if hash1 != hash2 {
		t.Errorf("Hash should be order-independent: %s vs %s", hash1, hash2)
	}
}

func TestComputeGlobalHashDifferentVersions(t *testing.T) {
	items1 := []unstructured.Unstructured{
		{Object: map[string]interface{}{"metadata": map[string]interface{}{"name": "a", "resourceVersion": "1"}}},
	}

	items2 := []unstructured.Unstructured{
		{Object: map[string]interface{}{"metadata": map[string]interface{}{"name": "a", "resourceVersion": "2"}}},
	}

	hash1 := computeGlobalHash(items1)
	hash2 := computeGlobalHash(items2)

	if hash1 == hash2 {
		t.Error("Different resourceVersions should produce different hashes")
	}
}

func TestComputeGlobalHashEmpty(t *testing.T) {
	hash := computeGlobalHash([]unstructured.Unstructured{})

	if hash == "" {
		t.Error("Empty items should still produce a hash")
	}
}

// ============================================================================
// performNamespaceUploads Tests
// ============================================================================

// createTestReport creates a VulnerabilityReport for testing
func createTestReport(namespace, name, cveID string) unstructured.Unstructured {
	return unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace": namespace,
				"name":      name,
				"labels": map[string]interface{}{
					"trivy-operator.container.name": "main",
				},
			},
			"report": map[string]interface{}{
				"artifact": map[string]interface{}{
					"repository": "nginx",
					"tag":        "1.21",
				},
				"vulnerabilities": []interface{}{
					map[string]interface{}{
						"vulnerabilityID":  cveID,
						"severity":         "HIGH",
						"resource":         "libssl",
						"title":            "Test vulnerability",
						"installedVersion": "1.0.0",
						"primaryLink":      "https://example.com",
					},
				},
			},
		},
	}
}

// mockGitLabServer creates a test server that tracks uploads and triggers
type mockGitLabServer struct {
	server         *httptest.Server
	mu             sync.Mutex
	uploadedProjects []string
	triggeredProjects []string
}

func newMockGitLabServer() *mockGitLabServer {
	m := &mockGitLabServer{}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()

		// Extract project from URL path
		// Format: /projects/{project}/packages/... or /projects/{project}/pipeline
		// Use RawPath to preserve URL-encoded slashes (%2F)
		path := r.URL.RawPath
		if path == "" {
			path = r.URL.Path // Fallback if RawPath not set
		}
		parts := strings.Split(path, "/")
		if len(parts) >= 3 && parts[1] == "projects" {
			project := parts[2]
			// URL decode %2F -> /
			project = strings.ReplaceAll(project, "%2F", "/")

			if strings.Contains(path, "/packages/") {
				m.uploadedProjects = append(m.uploadedProjects, project)
			} else if strings.HasSuffix(path, "/pipeline") {
				m.triggeredProjects = append(m.triggeredProjects, project)
			}
		}

		w.WriteHeader(http.StatusCreated)
	}))
	return m
}

func (m *mockGitLabServer) close() {
	m.server.Close()
}

func (m *mockGitLabServer) getUploaded() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string{}, m.uploadedProjects...)
}

func (m *mockGitLabServer) getTriggered() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string{}, m.triggeredProjects...)
}

func (m *mockGitLabServer) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.uploadedProjects = nil
	m.triggeredProjects = nil
}

func TestPerformNamespaceUploadsFirstRun(t *testing.T) {
	mock := newMockGitLabServer()
	defer mock.close()

	cache := NewProjectCache(5*time.Minute, mock.server.URL, "token")
	cache.MarkExists("group/mediastack")
	cache.MarkExists("group/gitlab")

	resolver := NewProjectResolver("group", "group/default", cache, nil)
	tracker := NewNamespaceTracker()

	cfg := Config{
		GitLabAPIURL:         mock.server.URL,
		GitLabAccessToken:    "token",
		DeployToken:          "deploy",
		DeployTokenUser:      "user",
		GitLabRef:            "main",
		GitLabDefaultProject: "group/default",
	}

	byNamespace := map[string][]unstructured.Unstructured{
		"mediastack": {createTestReport("mediastack", "report-1", "CVE-2021-1111")},
		"gitlab":     {createTestReport("gitlab", "report-2", "CVE-2021-2222")},
	}

	ctx := context.Background()
	performNamespaceUploads(ctx, byNamespace, resolver, tracker, cfg, scannerInfo{})

	uploaded := mock.getUploaded()
	triggered := mock.getTriggered()

	// Both namespaces should be uploaded on first run
	if len(uploaded) != 2 {
		t.Errorf("Expected 2 uploads, got %d: %v", len(uploaded), uploaded)
	}
	if len(triggered) != 2 {
		t.Errorf("Expected 2 triggers, got %d: %v", len(triggered), triggered)
	}
}

func TestPerformNamespaceUploadsSkipsUnchanged(t *testing.T) {
	mock := newMockGitLabServer()
	defer mock.close()

	cache := NewProjectCache(5*time.Minute, mock.server.URL, "token")
	cache.MarkExists("group/mediastack")

	resolver := NewProjectResolver("group", "group/default", cache, nil)
	tracker := NewNamespaceTracker()

	cfg := Config{
		GitLabAPIURL:         mock.server.URL,
		GitLabAccessToken:    "token",
		DeployToken:          "deploy",
		DeployTokenUser:      "user",
		GitLabRef:            "main",
		GitLabDefaultProject: "group/default",
	}

	byNamespace := map[string][]unstructured.Unstructured{
		"mediastack": {createTestReport("mediastack", "report-1", "CVE-2021-1111")},
	}

	ctx := context.Background()

	// First run - should upload
	performNamespaceUploads(ctx, byNamespace, resolver, tracker, cfg, scannerInfo{})

	if len(mock.getUploaded()) != 1 {
		t.Fatalf("First run: expected 1 upload, got %d", len(mock.getUploaded()))
	}

	mock.reset()

	// Second run with same data - should skip
	performNamespaceUploads(ctx, byNamespace, resolver, tracker, cfg, scannerInfo{})

	if len(mock.getUploaded()) != 0 {
		t.Errorf("Second run: expected 0 uploads (unchanged), got %d", len(mock.getUploaded()))
	}
}

func TestPerformNamespaceUploadsDetectsChange(t *testing.T) {
	mock := newMockGitLabServer()
	defer mock.close()

	cache := NewProjectCache(5*time.Minute, mock.server.URL, "token")
	cache.MarkExists("group/mediastack")

	resolver := NewProjectResolver("group", "group/default", cache, nil)
	tracker := NewNamespaceTracker()

	cfg := Config{
		GitLabAPIURL:         mock.server.URL,
		GitLabAccessToken:    "token",
		DeployToken:          "deploy",
		DeployTokenUser:      "user",
		GitLabRef:            "main",
		GitLabDefaultProject: "group/default",
	}

	ctx := context.Background()

	// First run
	byNamespace1 := map[string][]unstructured.Unstructured{
		"mediastack": {createTestReport("mediastack", "report-1", "CVE-2021-1111")},
	}
	performNamespaceUploads(ctx, byNamespace1, resolver, tracker, cfg, scannerInfo{})

	mock.reset()

	// Second run with CHANGED vulnerability
	byNamespace2 := map[string][]unstructured.Unstructured{
		"mediastack": {createTestReport("mediastack", "report-1", "CVE-2021-9999")}, // Different CVE
	}
	performNamespaceUploads(ctx, byNamespace2, resolver, tracker, cfg, scannerInfo{})

	if len(mock.getUploaded()) != 1 {
		t.Errorf("Expected 1 upload (changed), got %d", len(mock.getUploaded()))
	}
}

func TestPerformNamespaceUploadsPartialChange(t *testing.T) {
	mock := newMockGitLabServer()
	defer mock.close()

	cache := NewProjectCache(5*time.Minute, mock.server.URL, "token")
	cache.MarkExists("group/mediastack")
	cache.MarkExists("group/gitlab")

	resolver := NewProjectResolver("group", "group/default", cache, nil)
	tracker := NewNamespaceTracker()

	cfg := Config{
		GitLabAPIURL:         mock.server.URL,
		GitLabAccessToken:    "token",
		DeployToken:          "deploy",
		DeployTokenUser:      "user",
		GitLabRef:            "main",
		GitLabDefaultProject: "group/default",
	}

	ctx := context.Background()

	// First run - both namespaces
	byNamespace1 := map[string][]unstructured.Unstructured{
		"mediastack": {createTestReport("mediastack", "report-1", "CVE-2021-1111")},
		"gitlab":     {createTestReport("gitlab", "report-2", "CVE-2021-2222")},
	}
	performNamespaceUploads(ctx, byNamespace1, resolver, tracker, cfg, scannerInfo{})

	if len(mock.getUploaded()) != 2 {
		t.Fatalf("First run: expected 2 uploads, got %d", len(mock.getUploaded()))
	}

	mock.reset()

	// Second run - only mediastack changed
	byNamespace2 := map[string][]unstructured.Unstructured{
		"mediastack": {createTestReport("mediastack", "report-1", "CVE-2021-9999")}, // Changed
		"gitlab":     {createTestReport("gitlab", "report-2", "CVE-2021-2222")},     // Same
	}
	performNamespaceUploads(ctx, byNamespace2, resolver, tracker, cfg, scannerInfo{})

	uploaded := mock.getUploaded()
	if len(uploaded) != 1 {
		t.Errorf("Second run: expected 1 upload, got %d: %v", len(uploaded), uploaded)
	}
	if len(uploaded) == 1 && uploaded[0] != "group/mediastack" {
		t.Errorf("Expected mediastack to be uploaded, got %s", uploaded[0])
	}
}

func TestPerformNamespaceUploadsConsolidated(t *testing.T) {
	mock := newMockGitLabServer()
	defer mock.close()

	// Only mark default project as existing (nothing else matches)
	cache := NewProjectCache(5*time.Minute, mock.server.URL, "token")
	resolver := NewProjectResolver("group", "group/default", cache, nil)
	tracker := NewNamespaceTracker()

	cfg := Config{
		GitLabAPIURL:         mock.server.URL,
		GitLabAccessToken:    "token",
		DeployToken:          "deploy",
		DeployTokenUser:      "user",
		GitLabRef:            "main",
		GitLabDefaultProject: "group/default",
	}

	ctx := context.Background()

	// Namespaces that don't have matching projects -> consolidated
	byNamespace := map[string][]unstructured.Unstructured{
		"kube-system": {createTestReport("kube-system", "report-1", "CVE-2021-1111")},
		"monitoring":  {createTestReport("monitoring", "report-2", "CVE-2021-2222")},
	}
	performNamespaceUploads(ctx, byNamespace, resolver, tracker, cfg, scannerInfo{})

	uploaded := mock.getUploaded()
	// Should upload to default project (consolidated)
	if len(uploaded) != 1 {
		t.Errorf("Expected 1 consolidated upload, got %d: %v", len(uploaded), uploaded)
	}
	if len(uploaded) == 1 && uploaded[0] != "group/default" {
		t.Errorf("Expected upload to default project, got %s", uploaded[0])
	}
}

func TestPerformNamespaceUploadsConsolidatedSkipsUnchanged(t *testing.T) {
	mock := newMockGitLabServer()
	defer mock.close()

	cache := NewProjectCache(5*time.Minute, mock.server.URL, "token")
	resolver := NewProjectResolver("group", "group/default", cache, nil)
	tracker := NewNamespaceTracker()

	cfg := Config{
		GitLabAPIURL:         mock.server.URL,
		GitLabAccessToken:    "token",
		DeployToken:          "deploy",
		DeployTokenUser:      "user",
		GitLabRef:            "main",
		GitLabDefaultProject: "group/default",
	}

	ctx := context.Background()

	byNamespace := map[string][]unstructured.Unstructured{
		"kube-system": {createTestReport("kube-system", "report-1", "CVE-2021-1111")},
	}

	// First run
	performNamespaceUploads(ctx, byNamespace, resolver, tracker, cfg, scannerInfo{})
	if len(mock.getUploaded()) != 1 {
		t.Fatalf("First run: expected 1 upload, got %d", len(mock.getUploaded()))
	}

	mock.reset()

	// Second run - same data, should skip
	performNamespaceUploads(ctx, byNamespace, resolver, tracker, cfg, scannerInfo{})
	if len(mock.getUploaded()) != 0 {
		t.Errorf("Second run: expected 0 uploads (unchanged), got %d", len(mock.getUploaded()))
	}
}

func TestPerformNamespaceUploadsEmptyVulns(t *testing.T) {
	mock := newMockGitLabServer()
	defer mock.close()

	cache := NewProjectCache(5*time.Minute, mock.server.URL, "token")
	cache.MarkExists("group/mediastack")

	resolver := NewProjectResolver("group", "group/default", cache, nil)
	tracker := NewNamespaceTracker()

	cfg := Config{
		GitLabAPIURL:         mock.server.URL,
		GitLabAccessToken:    "token",
		DeployToken:          "deploy",
		DeployTokenUser:      "user",
		GitLabRef:            "main",
		GitLabDefaultProject: "group/default",
	}

	ctx := context.Background()

	// Report with no vulnerabilities
	byNamespace := map[string][]unstructured.Unstructured{
		"mediastack": {
			{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"namespace": "mediastack",
						"name":      "empty-report",
					},
					"report": map[string]interface{}{
						"artifact": map[string]interface{}{
							"repository": "nginx",
							"tag":        "1.21",
						},
						"vulnerabilities": []interface{}{}, // Empty
					},
				},
			},
		},
	}

	performNamespaceUploads(ctx, byNamespace, resolver, tracker, cfg, scannerInfo{})

	// Should skip upload for empty vulnerabilities
	if len(mock.getUploaded()) != 0 {
		t.Errorf("Expected 0 uploads for empty vulns, got %d", len(mock.getUploaded()))
	}
}

func TestPerformNamespaceUploadsMixedMatchAndDefault(t *testing.T) {
	mock := newMockGitLabServer()
	defer mock.close()

	cache := NewProjectCache(5*time.Minute, mock.server.URL, "token")
	cache.MarkExists("group/mediastack") // Only mediastack exists

	resolver := NewProjectResolver("group", "group/default", cache, nil)
	tracker := NewNamespaceTracker()

	cfg := Config{
		GitLabAPIURL:         mock.server.URL,
		GitLabAccessToken:    "token",
		DeployToken:          "deploy",
		DeployTokenUser:      "user",
		GitLabRef:            "main",
		GitLabDefaultProject: "group/default",
	}

	ctx := context.Background()

	byNamespace := map[string][]unstructured.Unstructured{
		"mediastack":  {createTestReport("mediastack", "report-1", "CVE-2021-1111")},  // Matches
		"kube-system": {createTestReport("kube-system", "report-2", "CVE-2021-2222")}, // Consolidated
	}

	performNamespaceUploads(ctx, byNamespace, resolver, tracker, cfg, scannerInfo{})

	uploaded := mock.getUploaded()
	// Should have 2 uploads: mediastack + consolidated (default)
	if len(uploaded) != 2 {
		t.Errorf("Expected 2 uploads, got %d: %v", len(uploaded), uploaded)
	}

	// Check both projects were uploaded
	hasMediastack := false
	hasDefault := false
	for _, p := range uploaded {
		if p == "group/mediastack" {
			hasMediastack = true
		}
		if p == "group/default" {
			hasDefault = true
		}
	}
	if !hasMediastack {
		t.Error("Expected mediastack to be uploaded")
	}
	if !hasDefault {
		t.Error("Expected default (consolidated) to be uploaded")
	}
}
