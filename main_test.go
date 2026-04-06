package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// ============================================================================
// Helper Function Tests
// ============================================================================

func TestMapSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"CRITICAL", "Critical"},
		{"critical", "Critical"},
		{"Critical", "Critical"},
		{"HIGH", "High"},
		{"high", "High"},
		{"High", "High"},
		{"MEDIUM", "Medium"},
		{"medium", "Medium"},
		{"Medium", "Medium"},
		{"LOW", "Low"},
		{"low", "Low"},
		{"Low", "Low"},
		{"UNKNOWN", "Unknown"},
		{"unknown", "Unknown"},
		{"", "Unknown"},
		{"NEGLIGIBLE", "Unknown"},
		{"something", "Unknown"},
		{"  HIGH  ", "Unknown"}, // No trimming
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := mapSeverity(tc.input)
			if result != tc.expected {
				t.Errorf("mapSeverity(%q) = %q, want %q", tc.input, result, tc.expected)
			}
		})
	}
}

func TestSanitize(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"docker.io/library/nginx", "docker.io-library-nginx"},
		{"nginx:1.21", "nginx-1.21"},
		{"registry.gitlab.com/foo/bar:latest", "registry.gitlab.com-foo-bar-latest"},
		{"simple", "simple"},
		{"a/b/c/d:e:f", "a-b-c-d-e-f"},
		{"", ""},
		{"no-special-chars", "no-special-chars"},
		{"multiple///slashes", "multiple---slashes"},
		{"mixed/path:tag", "mixed-path-tag"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := sanitize(tc.input)
			if result != tc.expected {
				t.Errorf("sanitize(%q) = %q, want %q", tc.input, result, tc.expected)
			}
		})
	}
}

func TestFirstN(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		n        int
		expected string
	}{
		{"shorter than limit", "hello", 10, "hello"},
		{"truncated", "hello world", 5, "hello..."},
		{"exact length", "short", 5, "short"},
		{"empty string", "", 5, ""},
		{"exact match", "exactly8", 8, "exactly8"},
		{"zero limit", "test", 0, "..."},
		{"single char limit", "test", 1, "t..."},
		{"unicode bytes", "héllo", 3, "hé..."},  // 'é' is 2 bytes in UTF-8
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := firstN(tc.input, tc.n)
			if result != tc.expected {
				t.Errorf("firstN(%q, %d) = %q, want %q", tc.input, tc.n, result, tc.expected)
			}
		})
	}
}

func TestIsValidURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"https url", "https://example.com", true},
		{"http url", "http://example.com", true},
		{"https with path", "https://nvd.nist.gov/vuln/detail/CVE-2021-1234", true},
		{"empty string", "", false},
		{"no protocol", "example.com", false},
		{"ftp protocol", "ftp://example.com", false},
		{"just https", "https://", true}, // technically matches pattern
		{"spaces", "https:// example.com", true}, // matches prefix
		{"relative path", "/path/to/resource", false},
		{"mailto", "mailto:test@example.com", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isValidURL(tc.input)
			if result != tc.expected {
				t.Errorf("isValidURL(%q) = %v, want %v", tc.input, result, tc.expected)
			}
		})
	}
}

func TestGetEnv(t *testing.T) {
	// Test with existing env var
	t.Setenv("TEST_ENV_VAR", "test_value")

	result := getEnv("TEST_ENV_VAR", "default")
	if result != "test_value" {
		t.Errorf("Expected 'test_value', got %q", result)
	}

	// Test with non-existing env var
	result = getEnv("NON_EXISTING_VAR", "default_value")
	if result != "default_value" {
		t.Errorf("Expected 'default_value', got %q", result)
	}

	// Test with empty env var
	t.Setenv("EMPTY_VAR", "")
	result = getEnv("EMPTY_VAR", "default")
	if result != "default" {
		t.Errorf("Expected 'default' for empty var, got %q", result)
	}
}

func TestGetDuration(t *testing.T) {
	// Test with valid duration
	t.Setenv("TEST_DURATION", "30s")

	result := getDuration("TEST_DURATION", time.Minute)
	if result != 30*time.Second {
		t.Errorf("Expected 30s, got %v", result)
	}

	// Test with invalid duration
	t.Setenv("INVALID_DURATION", "not-a-duration")

	result = getDuration("INVALID_DURATION", time.Minute)
	if result != time.Minute {
		t.Errorf("Expected default 1m, got %v", result)
	}

	// Test with non-existing var
	result = getDuration("NON_EXISTING_DURATION", 5*time.Minute)
	if result != 5*time.Minute {
		t.Errorf("Expected default 5m, got %v", result)
	}
}

// ============================================================================
// Report Conversion Tests
// ============================================================================

func TestConvertToGitLabReport(t *testing.T) {
	item := unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "aquasecurity.github.io/v1alpha1",
			"kind":       "VulnerabilityReport",
			"metadata": map[string]interface{}{
				"name":      "test-report",
				"namespace": "default",
				"labels": map[string]interface{}{
					"trivy-operator.container.name": "nginx",
				},
			},
			"report": map[string]interface{}{
				"artifact": map[string]interface{}{
					"repository": "nginx",
					"tag":        "1.21",
				},
				"vulnerabilities": []interface{}{
					map[string]interface{}{
						"vulnerabilityID": "CVE-2021-12345",
						"severity":        "HIGH",
						"resource":        "libssl",
						"title":           "Buffer overflow in libssl",
						"primaryLink":     "https://nvd.nist.gov/vuln/detail/CVE-2021-12345",
					},
					map[string]interface{}{
						"vulnerabilityID": "CVE-2021-67890",
						"severity":        "CRITICAL",
						"resource":        "openssl",
						"title":           "Remote code execution",
						"description":     "A critical vulnerability in OpenSSL",
						"primaryLink":     "https://nvd.nist.gov/vuln/detail/CVE-2021-67890",
					},
				},
			},
		},
	}

	vulns := convertItemsToVulnerabilities([]unstructured.Unstructured{item})
	report := buildSecurityReport(vulns)

	// Check report structure
	if report.Version != "15.0.0" {
		t.Errorf("Version = %q, want %q", report.Version, "15.0.0")
	}

	if len(report.Vulnerabilities) != 2 {
		t.Fatalf("Expected 2 vulnerabilities, got %d", len(report.Vulnerabilities))
	}

	// Check analyzer info
	if report.Scan.Analyzer.ID != "trivy-operator" {
		t.Errorf("Analyzer ID = %q, want %q", report.Scan.Analyzer.ID, "trivy-operator")
	}
	if report.Scan.Analyzer.Vendor.Name != "Aqua Security" {
		t.Errorf("Analyzer Vendor = %q, want %q", report.Scan.Analyzer.Vendor.Name, "Aqua Security")
	}

	// Check scanner info
	if report.Scan.Scanner.ID != "trivy" {
		t.Errorf("Scanner ID = %q, want %q", report.Scan.Scanner.ID, "trivy")
	}
	if report.Scan.Scanner.Name != "Trivy" {
		t.Errorf("Scanner Name = %q, want %q", report.Scan.Scanner.Name, "Trivy")
	}
	if report.Scan.Scanner.Vendor.Name != "Aqua Security" {
		t.Errorf("Scanner Vendor = %q, want %q", report.Scan.Scanner.Vendor.Name, "Aqua Security")
	}
	if report.Scan.Type != "container_scanning" {
		t.Errorf("Scan Type = %q, want %q", report.Scan.Type, "container_scanning")
	}
	if report.Scan.Status != "success" {
		t.Errorf("Scan Status = %q, want %q", report.Scan.Status, "success")
	}

	// Check vulnerabilities are sorted (by ID)
	v1 := report.Vulnerabilities[0]
	v2 := report.Vulnerabilities[1]
	if v1.ID > v2.ID {
		t.Error("Vulnerabilities should be sorted by ID")
	}

	// Check category
	for _, v := range report.Vulnerabilities {
		if v.Category != "container_scanning" {
			t.Errorf("Category = %q, want 'container_scanning'", v.Category)
		}
	}

	// Check kubernetes_resource fields
	v := report.Vulnerabilities[0]
	if v.Location.KubernetesResource.Namespace != "default" {
		t.Errorf("Namespace = %q, want %q", v.Location.KubernetesResource.Namespace, "default")
	}
	if v.Location.KubernetesResource.Name != "test-report" {
		t.Errorf("Name = %q, want %q", v.Location.KubernetesResource.Name, "test-report")
	}
	if v.Location.KubernetesResource.ContainerName != "nginx" {
		t.Errorf("ContainerName = %q, want %q", v.Location.KubernetesResource.ContainerName, "nginx")
	}
	if v.Location.KubernetesResource.Kind != "Pod" {
		t.Errorf("Kind = %q, want %q", v.Location.KubernetesResource.Kind, "Pod")
	}

	// Check message format includes kubernetes context [namespace/name/container]
	expectedMsgSuffix := "[default/test-report/nginx]"
	if !strings.Contains(v.Message, expectedMsgSuffix) {
		t.Errorf("Message = %q, should contain %q", v.Message, expectedMsgSuffix)
	}
}

func TestConvertToGitLabReportWithDescription(t *testing.T) {
	item := unstructured.Unstructured{
		Object: map[string]interface{}{
			"report": map[string]interface{}{
				"artifact": map[string]interface{}{
					"repository": "nginx",
					"tag":        "1.21",
				},
				"vulnerabilities": []interface{}{
					map[string]interface{}{
						"vulnerabilityID": "CVE-2021-12345",
						"severity":        "HIGH",
						"resource":        "libssl",
						"title":           "Short title",
						"description":     "This is a longer description that should be used instead of the title",
						"primaryLink":     "https://example.com",
					},
				},
			},
		},
	}

	vulns := convertItemsToVulnerabilities([]unstructured.Unstructured{item})
	report := buildSecurityReport(vulns)

	if len(report.Vulnerabilities) != 1 {
		t.Fatalf("Expected 1 vulnerability, got %d", len(report.Vulnerabilities))
	}

	// Description should be used when available
	expected := "This is a longer description that should be used instead of the title"
	if report.Vulnerabilities[0].Description != expected {
		t.Errorf("Description = %q, want %q", report.Vulnerabilities[0].Description, expected)
	}
}

func TestConvertToGitLabReportLongDescription(t *testing.T) {
	// Create a very long description
	longDesc := ""
	for i := 0; i < 100; i++ {
		longDesc += "This is a very long description. "
	}

	item := unstructured.Unstructured{
		Object: map[string]interface{}{
			"report": map[string]interface{}{
				"artifact": map[string]interface{}{
					"repository": "nginx",
					"tag":        "1.21",
				},
				"vulnerabilities": []interface{}{
					map[string]interface{}{
						"vulnerabilityID": "CVE-2021-12345",
						"severity":        "HIGH",
						"resource":        "libssl",
						"title":           "Title",
						"description":     longDesc,
						"primaryLink":     "https://example.com",
					},
				},
			},
		},
	}

	vulns := convertItemsToVulnerabilities([]unstructured.Unstructured{item})
	report := buildSecurityReport(vulns)

	// Description should be truncated to 500 chars + "..."
	if len(report.Vulnerabilities[0].Description) > 504 {
		t.Errorf("Description should be truncated, got length %d", len(report.Vulnerabilities[0].Description))
	}
}

func TestHashStability(t *testing.T) {
	item := unstructured.Unstructured{
		Object: map[string]interface{}{
			"report": map[string]interface{}{
				"artifact": map[string]interface{}{
					"repository": "nginx",
					"tag":        "1.21",
				},
				"vulnerabilities": []interface{}{
					map[string]interface{}{
						"vulnerabilityID": "CVE-2021-12345",
						"severity":        "HIGH",
						"resource":        "libssl",
						"title":           "Test vuln",
						"primaryLink":     "https://example.com",
					},
				},
			},
		},
	}

	// Generate report twice (timestamps will differ)
	convertedVulns1 := convertItemsToVulnerabilities([]unstructured.Unstructured{item})
	report1 := buildSecurityReport(convertedVulns1)
	time.Sleep(10 * time.Millisecond) // Ensure different timestamp
	convertedVulns2 := convertItemsToVulnerabilities([]unstructured.Unstructured{item})
	report2 := buildSecurityReport(convertedVulns2)

	// Full report hash might differ (includes timestamps)
	json1, _ := json.Marshal(report1)
	json2, _ := json.Marshal(report2)
	hash1Full := fmt.Sprintf("%x", sha256.Sum256(json1))[:16]
	hash2Full := fmt.Sprintf("%x", sha256.Sum256(json2))[:16]
	t.Logf("Full hash 1: %s, Full hash 2: %s", hash1Full, hash2Full)

	// Vulnerabilities-only hash MUST be identical
	vulnsJson1, _ := json.Marshal(report1.Vulnerabilities)
	vulnsJson2, _ := json.Marshal(report2.Vulnerabilities)
	hash1Vulns := fmt.Sprintf("%x", sha256.Sum256(vulnsJson1))[:16]
	hash2Vulns := fmt.Sprintf("%x", sha256.Sum256(vulnsJson2))[:16]

	if hash1Vulns != hash2Vulns {
		t.Errorf("Vulnerability hashes should be identical: %s vs %s", hash1Vulns, hash2Vulns)
	}
}

func TestEmptyReport(t *testing.T) {
	vulns := convertItemsToVulnerabilities([]unstructured.Unstructured{})
	report := buildSecurityReport(vulns)

	if len(report.Vulnerabilities) != 0 {
		t.Errorf("Expected 0 vulnerabilities, got %d", len(report.Vulnerabilities))
	}

	if report.Scan.Status != "success" {
		t.Errorf("Scan status = %q, want %q", report.Scan.Status, "success")
	}

	if report.Version != "15.0.0" {
		t.Errorf("Version = %q, want %q", report.Version, "15.0.0")
	}
}

func TestVulnerabilityID(t *testing.T) {
	item := unstructured.Unstructured{
		Object: map[string]interface{}{
			"report": map[string]interface{}{
				"artifact": map[string]interface{}{
					"repository": "docker.io/library/nginx",
					"tag":        "latest",
				},
				"vulnerabilities": []interface{}{
					map[string]interface{}{
						"vulnerabilityID": "CVE-2021-12345",
						"severity":        "HIGH",
						"resource":        "libssl",
						"title":           "Test",
						"primaryLink":     "https://example.com",
					},
				},
			},
		},
	}

	vulns := convertItemsToVulnerabilities([]unstructured.Unstructured{item})
	report := buildSecurityReport(vulns)

	if len(report.Vulnerabilities) != 1 {
		t.Fatalf("Expected 1 vulnerability, got %d", len(report.Vulnerabilities))
	}

	// ID format: CVE-IMAGE-PACKAGE
	expectedID := "CVE-2021-12345-docker.io-library-nginx-libssl"
	if report.Vulnerabilities[0].ID != expectedID {
		t.Errorf("Vulnerability ID = %q, want %q", report.Vulnerabilities[0].ID, expectedID)
	}

	// Image should include tag
	expectedImage := "docker.io/library/nginx:latest"
	if report.Vulnerabilities[0].Location.Image != expectedImage {
		t.Errorf("Image = %q, want %q", report.Vulnerabilities[0].Location.Image, expectedImage)
	}
}

func TestMissingTag(t *testing.T) {
	item := unstructured.Unstructured{
		Object: map[string]interface{}{
			"report": map[string]interface{}{
				"artifact": map[string]interface{}{
					"repository": "nginx",
					// No tag field
				},
				"vulnerabilities": []interface{}{
					map[string]interface{}{
						"vulnerabilityID": "CVE-2021-12345",
						"severity":        "HIGH",
						"resource":        "libssl",
						"title":           "Test",
						"primaryLink":     "https://example.com",
					},
				},
			},
		},
	}

	vulns := convertItemsToVulnerabilities([]unstructured.Unstructured{item})
	report := buildSecurityReport(vulns)

	// Should default to "latest"
	expectedImage := "nginx:latest"
	if report.Vulnerabilities[0].Location.Image != expectedImage {
		t.Errorf("Image = %q, want %q (should default to latest)", report.Vulnerabilities[0].Location.Image, expectedImage)
	}
}

func TestMissingReport(t *testing.T) {
	// Item without report field
	item := unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "aquasecurity.github.io/v1alpha1",
			"kind":       "VulnerabilityReport",
			"metadata": map[string]interface{}{
				"name": "empty-report",
			},
		},
	}

	vulns := convertItemsToVulnerabilities([]unstructured.Unstructured{item})
	report := buildSecurityReport(vulns)

	// Should handle gracefully
	if len(report.Vulnerabilities) != 0 {
		t.Errorf("Expected 0 vulnerabilities for missing report, got %d", len(report.Vulnerabilities))
	}
}

func TestMissingMetadataDefaults(t *testing.T) {
	// Item without namespace, name or container label
	item := unstructured.Unstructured{
		Object: map[string]interface{}{
			"report": map[string]interface{}{
				"artifact": map[string]interface{}{
					"repository": "nginx",
					"tag":        "1.21",
				},
				"vulnerabilities": []interface{}{
					map[string]interface{}{
						"vulnerabilityID": "CVE-2021-12345",
						"severity":        "HIGH",
						"resource":        "libssl",
						"title":           "Test vuln",
						"primaryLink":     "https://example.com",
					},
				},
			},
			// No metadata at all
		},
	}

	vulns := convertItemsToVulnerabilities([]unstructured.Unstructured{item})
	report := buildSecurityReport(vulns)

	if len(report.Vulnerabilities) != 1 {
		t.Fatalf("Expected 1 vulnerability, got %d", len(report.Vulnerabilities))
	}

	v := report.Vulnerabilities[0]

	// Check defaults are applied
	if v.Location.KubernetesResource.Namespace != "unknown" {
		t.Errorf("Namespace = %q, want %q (default)", v.Location.KubernetesResource.Namespace, "unknown")
	}
	if v.Location.KubernetesResource.Name != "unknown" {
		t.Errorf("Name = %q, want %q (default)", v.Location.KubernetesResource.Name, "unknown")
	}
	if v.Location.KubernetesResource.ContainerName != "main" {
		t.Errorf("ContainerName = %q, want %q (default)", v.Location.KubernetesResource.ContainerName, "main")
	}

	// Message should contain the defaults
	expectedMsgSuffix := "[unknown/unknown/main]"
	if !strings.Contains(v.Message, expectedMsgSuffix) {
		t.Errorf("Message = %q, should contain %q", v.Message, expectedMsgSuffix)
	}
}

func TestMultipleReports(t *testing.T) {
	items := []unstructured.Unstructured{
		{
			Object: map[string]interface{}{
				"report": map[string]interface{}{
					"artifact": map[string]interface{}{
						"repository": "nginx",
						"tag":        "1.21",
					},
					"vulnerabilities": []interface{}{
						map[string]interface{}{
							"vulnerabilityID": "CVE-2021-11111",
							"severity":        "HIGH",
							"resource":        "pkg1",
							"title":           "Vuln 1",
							"primaryLink":     "https://example.com/1",
						},
					},
				},
			},
		},
		{
			Object: map[string]interface{}{
				"report": map[string]interface{}{
					"artifact": map[string]interface{}{
						"repository": "redis",
						"tag":        "7.0",
					},
					"vulnerabilities": []interface{}{
						map[string]interface{}{
							"vulnerabilityID": "CVE-2021-22222",
							"severity":        "CRITICAL",
							"resource":        "pkg2",
							"title":           "Vuln 2",
							"primaryLink":     "https://example.com/2",
						},
						map[string]interface{}{
							"vulnerabilityID": "CVE-2021-33333",
							"severity":        "LOW",
							"resource":        "pkg3",
							"title":           "Vuln 3",
							"primaryLink":     "https://example.com/3",
						},
					},
				},
			},
		},
	}

	vulns := convertItemsToVulnerabilities(items)
	report := buildSecurityReport(vulns)

	// Should have 3 vulnerabilities total
	if len(report.Vulnerabilities) != 3 {
		t.Errorf("Expected 3 vulnerabilities, got %d", len(report.Vulnerabilities))
	}

	// Should be sorted by ID
	for i := 1; i < len(report.Vulnerabilities); i++ {
		if report.Vulnerabilities[i-1].ID > report.Vulnerabilities[i].ID {
			t.Error("Vulnerabilities should be sorted by ID")
		}
	}
}

// ============================================================================
// Compression Tests
// ============================================================================

func TestGzipCompression(t *testing.T) {
	// Create a sample report
	report := SecurityReport{
		Version: "15.0.0",
		Vulnerabilities: []Vulnerability{
			{
				ID:       "test-id",
				Category: "container_scanning",
				Name:     "CVE-2021-12345",
				Severity: "High",
			},
		},
	}

	reportJSON, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("Failed to marshal report: %v", err)
	}

	// Compress
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, err = gz.Write(reportJSON)
	if err != nil {
		t.Fatalf("Failed to write gzip: %v", err)
	}
	err = gz.Close()
	if err != nil {
		t.Fatalf("Failed to close gzip: %v", err)
	}

	// Decompress and verify
	reader, err := gzip.NewReader(&buf)
	if err != nil {
		t.Fatalf("Failed to create gzip reader: %v", err)
	}
	defer func() { _ = reader.Close() }()

	decompressed, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("Failed to read decompressed data: %v", err)
	}

	if !bytes.Equal(decompressed, reportJSON) {
		t.Error("Decompressed data doesn't match original")
	}

	// Compressed should be smaller (for larger data)
	t.Logf("Original size: %d, Compressed size: %d", len(reportJSON), buf.Len())
}

// ============================================================================
// JSON Structure Tests
// ============================================================================

func TestSecurityReportJSON(t *testing.T) {
	report := SecurityReport{
		Version: "15.0.0",
		Vulnerabilities: []Vulnerability{
			{
				ID:          "test-id",
				Category:    "container_scanning",
				Name:        "CVE-2021-12345",
				Message:     "Test message",
				Description: "Test description",
				Severity:    "High",
				Location: Location{
					Image:           "nginx:1.21",
					OperatingSystem: "debian",
					Dependency: Dependency{
						Package: Package{Name: "libssl"},
						Version: "1.1.1",
					},
				},
				Identifiers: []Ident{
					{
						Type:  "cve",
						Name:  "CVE-2021-12345",
						Value: "CVE-2021-12345",
						URL:   "https://example.com",
					},
				},
				Links: []Link{
					{URL: "https://example.com"},
				},
			},
		},
		Scan: ScanInfo{
			Analyzer: Analyzer{
				ID:      "trivy-operator",
				Name:    "Trivy Operator",
				Version: "0.24.0",
				Vendor:  Vendor{Name: "Aqua Security"},
			},
			Scanner: Scanner{
				ID:      "trivy",
				Name:    "Trivy",
				Version: "0.58.0",
				Vendor:  Vendor{Name: "Aqua Security"},
			},
			Type:    "container_scanning",
			Status:  "success",
			StartAt: "2024-01-01T00:00:00",
			EndAt:   "2024-01-01T00:01:00",
		},
	}

	jsonData, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("Failed to marshal report: %v", err)
	}

	// Verify it can be unmarshaled back
	var decoded SecurityReport
	err = json.Unmarshal(jsonData, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal report: %v", err)
	}

	if decoded.Version != report.Version {
		t.Errorf("Version mismatch: got %q, want %q", decoded.Version, report.Version)
	}

	if len(decoded.Vulnerabilities) != len(report.Vulnerabilities) {
		t.Errorf("Vulnerability count mismatch: got %d, want %d", len(decoded.Vulnerabilities), len(report.Vulnerabilities))
	}
}

// ============================================================================
// Benchmark Tests
// ============================================================================

func BenchmarkConvertToGitLabReport(b *testing.B) {
	// Create 100 vulnerability reports
	items := make([]unstructured.Unstructured, 100)
	for i := 0; i < 100; i++ {
		vulns := make([]interface{}, 20)
		for j := 0; j < 20; j++ {
			vulns[j] = map[string]interface{}{
				"vulnerabilityID": fmt.Sprintf("CVE-2021-%05d", i*20+j),
				"severity":        "HIGH",
				"resource":        fmt.Sprintf("package-%d", j),
				"title":           "Test vulnerability",
				"primaryLink":     "https://example.com",
			}
		}
		items[i] = unstructured.Unstructured{
			Object: map[string]interface{}{
				"report": map[string]interface{}{
					"artifact": map[string]interface{}{
						"repository": fmt.Sprintf("image-%d", i),
						"tag":        "latest",
					},
					"vulnerabilities": vulns,
				},
			},
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vulns := convertItemsToVulnerabilities(items)
		buildSecurityReport(vulns)
	}
}

func BenchmarkMapSeverity(b *testing.B) {
	severities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mapSeverity(severities[i%len(severities)])
	}
}

// ============================================================================
// Namespace Grouping Tests
// ============================================================================

func TestGroupByNamespace(t *testing.T) {
	items := []unstructured.Unstructured{
		{
			Object: map[string]interface{}{
				"metadata": map[string]interface{}{
					"namespace": "mediastack",
					"name":      "report-1",
				},
			},
		},
		{
			Object: map[string]interface{}{
				"metadata": map[string]interface{}{
					"namespace": "mediastack",
					"name":      "report-2",
				},
			},
		},
		{
			Object: map[string]interface{}{
				"metadata": map[string]interface{}{
					"namespace": "gitlab",
					"name":      "report-3",
				},
			},
		},
		{
			Object: map[string]interface{}{
				"metadata": map[string]interface{}{
					"namespace": "kube-system",
					"name":      "report-4",
				},
			},
		},
	}

	groups := groupByNamespace(items)

	if len(groups) != 3 {
		t.Errorf("Expected 3 namespace groups, got %d", len(groups))
	}

	if len(groups["mediastack"]) != 2 {
		t.Errorf("Expected 2 items in mediastack, got %d", len(groups["mediastack"]))
	}

	if len(groups["gitlab"]) != 1 {
		t.Errorf("Expected 1 item in gitlab, got %d", len(groups["gitlab"]))
	}

	if len(groups["kube-system"]) != 1 {
		t.Errorf("Expected 1 item in kube-system, got %d", len(groups["kube-system"]))
	}
}

func TestGroupByNamespaceEmpty(t *testing.T) {
	groups := groupByNamespace([]unstructured.Unstructured{})
	if len(groups) != 0 {
		t.Errorf("Expected 0 groups for empty input, got %d", len(groups))
	}
}

func TestGroupByNamespaceMissingNamespace(t *testing.T) {
	items := []unstructured.Unstructured{
		{
			Object: map[string]interface{}{
				"metadata": map[string]interface{}{
					"name": "report-no-ns",
				},
			},
		},
	}

	groups := groupByNamespace(items)

	// Should default to "default" namespace
	if len(groups["default"]) != 1 {
		t.Errorf("Expected 1 item in 'default', got %d", len(groups["default"]))
	}
}

// ============================================================================
// Namespace Tracker Tests
// ============================================================================

func TestNamespaceTrackerBasic(t *testing.T) {
	tracker := NewNamespaceTracker()

	// Initial state
	state := tracker.GetState("test-ns")
	if state.Hash != "" {
		t.Error("Initial hash should be empty")
	}

	// Update hash
	changed, oldHash := tracker.UpdateHash("test-ns", "abc123")
	if !changed {
		t.Error("First update should return changed=true")
	}
	if oldHash != "" {
		t.Errorf("First update oldHash should be empty, got %q", oldHash)
	}

	state = tracker.GetState("test-ns")
	if state.Hash != "abc123" {
		t.Errorf("Hash should be 'abc123', got %q", state.Hash)
	}

	// Same hash - no change
	changed, oldHash = tracker.UpdateHash("test-ns", "abc123")
	if changed {
		t.Error("Same hash should return changed=false")
	}
	if oldHash != "abc123" {
		t.Errorf("oldHash should be 'abc123', got %q", oldHash)
	}

	// Different hash
	changed, oldHash = tracker.UpdateHash("test-ns", "def456")
	if !changed {
		t.Error("Different hash should return changed=true")
	}
	if oldHash != "abc123" {
		t.Errorf("oldHash should be 'abc123', got %q", oldHash)
	}
}

func TestNamespaceTrackerMarkTriggered(t *testing.T) {
	tracker := NewNamespaceTracker()

	// Setup initial state
	tracker.UpdateHash("test-ns", "hash1")
	tracker.MarkTriggered("test-ns", "hash1")

	state := tracker.GetState("test-ns")
	if state.LastTriggerHash != "hash1" {
		t.Errorf("LastTriggerHash should be 'hash1', got %q", state.LastTriggerHash)
	}
	if state.LastTriggerTime.IsZero() {
		t.Error("LastTriggerTime should not be zero")
	}
}

func TestNamespaceTrackerConcurrentAccess(t *testing.T) {
	tracker := NewNamespaceTracker()
	done := make(chan bool)

	// Concurrent writes
	for i := 0; i < 100; i++ {
		go func(n int) {
			ns := fmt.Sprintf("ns-%d", n%10)
			tracker.UpdateHash(ns, fmt.Sprintf("hash-%d", n))
			tracker.GetState(ns)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}
}

// ============================================================================
// Hash Computation Tests
// ============================================================================

func TestComputeVulnHash(t *testing.T) {
	vulns1 := []Vulnerability{
		{ID: "vuln-1", Name: "CVE-1"},
		{ID: "vuln-2", Name: "CVE-2"},
	}

	vulns2 := []Vulnerability{
		{ID: "vuln-1", Name: "CVE-1"},
		{ID: "vuln-2", Name: "CVE-2"},
	}

	vulns3 := []Vulnerability{
		{ID: "vuln-1", Name: "CVE-1"},
		{ID: "vuln-3", Name: "CVE-3"},
	}

	hash1 := computeVulnHash(vulns1)
	hash2 := computeVulnHash(vulns2)
	hash3 := computeVulnHash(vulns3)

	if hash1 != hash2 {
		t.Errorf("Identical vulns should produce same hash: %s vs %s", hash1, hash2)
	}

	if hash1 == hash3 {
		t.Errorf("Different vulns should produce different hash: %s vs %s", hash1, hash3)
	}

	// Hash should be 16 chars (first 16 of sha256 hex)
	if len(hash1) != 16 {
		t.Errorf("Hash should be 16 chars, got %d", len(hash1))
	}
}

func TestComputeVulnHashEmpty(t *testing.T) {
	hash := computeVulnHash([]Vulnerability{})

	if hash == "" {
		t.Error("Empty vulns should still produce a hash")
	}
}

// ============================================================================
// Build Security Report Tests
// ============================================================================

func TestBuildSecurityReport(t *testing.T) {
	vulns := []Vulnerability{
		{ID: "test-1", Name: "CVE-1", Severity: "High"},
	}

	report := buildSecurityReport(vulns)

	if report.Version != "15.0.0" {
		t.Errorf("Version = %q, want '15.0.0'", report.Version)
	}

	if len(report.Vulnerabilities) != 1 {
		t.Errorf("Expected 1 vulnerability, got %d", len(report.Vulnerabilities))
	}

	if report.Scan.Type != "container_scanning" {
		t.Errorf("Scan.Type = %q, want 'container_scanning'", report.Scan.Type)
	}

	if report.Scan.Status != "success" {
		t.Errorf("Scan.Status = %q, want 'success'", report.Scan.Status)
	}

	// Timestamps should be set
	if report.Scan.StartAt == "" {
		t.Error("StartAt should not be empty")
	}
}

// ============================================================================
// Config Validation Tests
// ============================================================================

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: Config{
				GitLabDefaultProject: "group/project",
				DeployToken:          "token",
				DeployTokenUser:      "user",
				TriggerToken:         "trigger",
			},
			wantErr: false,
		},
		{
			name: "missing default project",
			cfg: Config{
				DeployToken:     "token",
				DeployTokenUser: "user",
				TriggerToken:    "trigger",
			},
			wantErr: true,
		},
		{
			name: "missing deploy token",
			cfg: Config{
				GitLabDefaultProject: "group/project",
				DeployTokenUser:      "user",
				TriggerToken:         "trigger",
			},
			wantErr: true,
		},
		{
			name: "missing deploy token user",
			cfg: Config{
				GitLabDefaultProject: "group/project",
				DeployToken:          "token",
				TriggerToken:         "trigger",
			},
			wantErr: true,
		},
		{
			name: "missing trigger token",
			cfg: Config{
				GitLabDefaultProject: "group/project",
				DeployToken:          "token",
				DeployTokenUser:      "user",
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
