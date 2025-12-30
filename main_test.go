package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestMapSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"CRITICAL", "Critical"},
		{"critical", "Critical"},
		{"HIGH", "High"},
		{"high", "High"},
		{"MEDIUM", "Medium"},
		{"medium", "Medium"},
		{"LOW", "Low"},
		{"low", "Low"},
		{"UNKNOWN", "Unknown"},
		{"", "Unknown"},
		{"something", "Unknown"},
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
		input    string
		n        int
		expected string
	}{
		{"hello", 10, "hello"},
		{"hello world", 5, "hello..."},
		{"short", 5, "short"},
		{"", 5, ""},
		{"exactly5", 8, "exactly5"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := firstN(tc.input, tc.n)
			if result != tc.expected {
				t.Errorf("firstN(%q, %d) = %q, want %q", tc.input, tc.n, result, tc.expected)
			}
		})
	}
}

func TestConvertToGitLabReport(t *testing.T) {
	// Create a mock VulnerabilityReport
	item := unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "aquasecurity.github.io/v1alpha1",
			"kind":       "VulnerabilityReport",
			"metadata": map[string]interface{}{
				"name":      "test-report",
				"namespace": "default",
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

	report := convertToGitLabReport([]unstructured.Unstructured{item})

	// Check report structure
	if report.Version != "15.0.0" {
		t.Errorf("Version = %q, want %q", report.Version, "15.0.0")
	}

	if len(report.Vulnerabilities) != 2 {
		t.Fatalf("Expected 2 vulnerabilities, got %d", len(report.Vulnerabilities))
	}

	// Check scanner info
	if report.Scan.Scanner.ID != "trivy" {
		t.Errorf("Scanner ID = %q, want %q", report.Scan.Scanner.ID, "trivy")
	}

	// Check vulnerabilities are sorted (by ID)
	v1 := report.Vulnerabilities[0]
	v2 := report.Vulnerabilities[1]
	if v1.ID > v2.ID {
		t.Error("Vulnerabilities should be sorted by ID")
	}

	// Check severity mapping
	for _, v := range report.Vulnerabilities {
		if v.Severity != "High" && v.Severity != "Critical" {
			t.Errorf("Unexpected severity %q", v.Severity)
		}
	}
}

func TestHashStability(t *testing.T) {
	// Create same vulnerability report twice with different timestamps
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
	report1 := convertToGitLabReport([]unstructured.Unstructured{item})
	report2 := convertToGitLabReport([]unstructured.Unstructured{item})

	// Full report hash should differ (includes timestamps)
	json1, _ := json.Marshal(report1)
	json2, _ := json.Marshal(report2)
	hash1Full := fmt.Sprintf("%x", sha256.Sum256(json1))[:16]
	hash2Full := fmt.Sprintf("%x", sha256.Sum256(json2))[:16]

	// Note: This might pass if executed fast enough, but timestamps should differ
	t.Logf("Full hash 1: %s, Full hash 2: %s", hash1Full, hash2Full)

	// Vulnerabilities-only hash should be identical
	vulns1, _ := json.Marshal(report1.Vulnerabilities)
	vulns2, _ := json.Marshal(report2.Vulnerabilities)
	hash1Vulns := fmt.Sprintf("%x", sha256.Sum256(vulns1))[:16]
	hash2Vulns := fmt.Sprintf("%x", sha256.Sum256(vulns2))[:16]

	if hash1Vulns != hash2Vulns {
		t.Errorf("Vulnerability hashes should be identical: %s vs %s", hash1Vulns, hash2Vulns)
	}
}

func TestEmptyReport(t *testing.T) {
	report := convertToGitLabReport([]unstructured.Unstructured{})

	if len(report.Vulnerabilities) != 0 {
		t.Errorf("Expected 0 vulnerabilities, got %d", len(report.Vulnerabilities))
	}

	if report.Scan.Status != "success" {
		t.Errorf("Scan status = %q, want %q", report.Scan.Status, "success")
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

	report := convertToGitLabReport([]unstructured.Unstructured{item})

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

	report := convertToGitLabReport([]unstructured.Unstructured{item})

	// Should default to "latest"
	expectedImage := "nginx:latest"
	if report.Vulnerabilities[0].Location.Image != expectedImage {
		t.Errorf("Image = %q, want %q (should default to latest)", report.Vulnerabilities[0].Location.Image, expectedImage)
	}
}
