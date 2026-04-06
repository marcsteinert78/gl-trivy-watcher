package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/xeipuuv/gojsonschema"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// TestReportMatchesGitLabSchema validates that the SecurityReport produced by
// the converter matches the official GitLab Container Scanning report schema.
//
// This is the build-time guard against schema drift: if GitLab updates the
// schema (new required fields, renamed properties, ...), this test fails in
// CI before a broken image gets pushed.
//
// To update the schema:
//
//	curl -sSLo testdata/container-scanning-report-format.json \
//	  https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/master/dist/container-scanning-report-format.json
func TestReportMatchesGitLabSchema(t *testing.T) {
	schemaBytes, err := os.ReadFile("testdata/container-scanning-report-format.json")
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	schemaLoader := gojsonschema.NewBytesLoader(schemaBytes)

	cases := []struct {
		name string
		item unstructured.Unstructured
	}{
		{
			name: "typical report with HIGH and CRITICAL CVEs",
			item: sampleVulnerabilityReport(),
		},
		{
			name: "report without optional fields",
			item: minimalVulnerabilityReport(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vulns := convertItemsToVulnerabilities([]unstructured.Unstructured{tc.item})
			report := buildSecurityReport(vulns)

			data, err := json.Marshal(report)
			if err != nil {
				t.Fatalf("marshal report: %v", err)
			}

			result, err := gojsonschema.Validate(schemaLoader, gojsonschema.NewBytesLoader(data))
			if err != nil {
				t.Fatalf("schema validation: %v", err)
			}

			if !result.Valid() {
				var msgs []string
				for _, e := range result.Errors() {
					msgs = append(msgs, e.String())
				}
				t.Fatalf("report does not match GitLab schema:\n  - %s", strings.Join(msgs, "\n  - "))
			}
		})
	}
}

// TestEmptyReportMatchesSchema verifies that an empty report (no findings) is
// still schema-valid — important because we upload empty reports too, to clear
// resolved vulnerabilities from the dashboard.
func TestEmptyReportMatchesSchema(t *testing.T) {
	schemaBytes, err := os.ReadFile("testdata/container-scanning-report-format.json")
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}

	report := buildSecurityReport(nil)
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	result, err := gojsonschema.Validate(
		gojsonschema.NewBytesLoader(schemaBytes),
		gojsonschema.NewBytesLoader(data),
	)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !result.Valid() {
		var msgs []string
		for _, e := range result.Errors() {
			msgs = append(msgs, e.String())
		}
		t.Fatalf("empty report invalid:\n  - %s", strings.Join(msgs, "\n  - "))
	}
}

// sampleVulnerabilityReport returns a representative VulnerabilityReport with
// multiple CVEs of different severities, mirroring what trivy-operator emits
// in production.
func sampleVulnerabilityReport() unstructured.Unstructured {
	return unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "aquasecurity.github.io/v1alpha1",
			"kind":       "VulnerabilityReport",
			"metadata": map[string]interface{}{
				"name":      "pod-nginx-abc123",
				"namespace": "web",
				"labels": map[string]interface{}{
					"trivy-operator.container.name": "nginx",
				},
			},
			"report": map[string]interface{}{
				"artifact": map[string]interface{}{
					"repository": "library/nginx",
					"tag":        "1.27.0",
				},
				"os": map[string]interface{}{
					"family": "debian",
					"name":   "12.5",
				},
				"vulnerabilities": []interface{}{
					map[string]interface{}{
						"vulnerabilityID":  "CVE-2024-12345",
						"severity":         "HIGH",
						"resource":         "libssl3",
						"installedVersion": "3.0.11-1~deb12u2",
						"title":            "Buffer overflow in libssl",
						"description":      "A buffer overflow vulnerability in OpenSSL.",
						"primaryLink":      "https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
					},
					map[string]interface{}{
						"vulnerabilityID":  "CVE-2024-67890",
						"severity":         "CRITICAL",
						"resource":         "zlib1g",
						"installedVersion": "1:1.2.13.dfsg-1",
						"title":            "Remote code execution in zlib",
						"primaryLink":      "https://nvd.nist.gov/vuln/detail/CVE-2024-67890",
					},
					map[string]interface{}{
						"vulnerabilityID":  "CVE-2024-11111",
						"severity":         "MEDIUM",
						"resource":         "curl",
						"installedVersion": "7.88.1-10+deb12u5",
						"title":            "Information disclosure in curl",
					},
				},
			},
		},
	}
}

// minimalVulnerabilityReport tests the converter with the bare minimum of
// fields — no description, no primaryLink, no OS info — to ensure we still
// produce schema-valid output for sparse trivy-operator emissions.
func minimalVulnerabilityReport() unstructured.Unstructured {
	return unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "aquasecurity.github.io/v1alpha1",
			"kind":       "VulnerabilityReport",
			"metadata": map[string]interface{}{
				"name":      "pod-minimal",
				"namespace": "default",
			},
			"report": map[string]interface{}{
				"artifact": map[string]interface{}{
					"repository": "alpine",
				},
				"vulnerabilities": []interface{}{
					map[string]interface{}{
						"vulnerabilityID": "CVE-2024-99999",
						"severity":        "LOW",
						"resource":        "musl",
					},
				},
			},
		},
	}
}
