package main

import (
	"testing"

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
	// Test deterministic hash
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

	// Should be same due to sorting
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
