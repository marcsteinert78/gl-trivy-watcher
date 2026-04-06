package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// groupByNamespace groups VulnerabilityReports by their namespace.
func groupByNamespace(items []unstructured.Unstructured) map[string][]unstructured.Unstructured {
	groups := make(map[string][]unstructured.Unstructured)

	for _, item := range items {
		ns, _, _ := unstructured.NestedString(item.Object, "metadata", "namespace")
		if ns == "" {
			ns = "default"
		}
		groups[ns] = append(groups[ns], item)
	}

	return groups
}

// convertItemsToVulnerabilities converts VulnerabilityReports to GitLab format.
func convertItemsToVulnerabilities(items []unstructured.Unstructured) []Vulnerability {
	var vulns []Vulnerability

	for _, item := range items {
		report, _, _ := unstructured.NestedMap(item.Object, "report")
		if report == nil {
			continue
		}

		// Get metadata for kubernetes_resource
		metadata, _, _ := unstructured.NestedMap(item.Object, "metadata")
		namespace, _ := metadata["namespace"].(string)
		resourceName, _ := metadata["name"].(string)
		if namespace == "" {
			namespace = "unknown"
		}
		if resourceName == "" {
			resourceName = "unknown"
		}
		labels, _, _ := unstructured.NestedStringMap(item.Object, "metadata", "labels")
		containerName := labels["trivy-operator.container.name"]
		if containerName == "" {
			containerName = "main"
		}

		artifact, _, _ := unstructured.NestedMap(report, "artifact")
		image, _ := artifact["repository"].(string)
		tag, _ := artifact["tag"].(string)
		if tag == "" {
			tag = "latest"
		}
		fullImage := fmt.Sprintf("%s:%s", image, tag)

		// Get OS info
		osMap, _, _ := unstructured.NestedMap(report, "os")
		osFamily, _ := osMap["family"].(string)
		osName, _ := osMap["name"].(string)
		osInfo := osFamily
		if osName != "" {
			osInfo = fmt.Sprintf("%s %s", osFamily, osName)
		}
		if osInfo == "" {
			osInfo = "Unknown"
		}

		vulnList, _, _ := unstructured.NestedSlice(report, "vulnerabilities")
		for _, v := range vulnList {
			vuln, ok := v.(map[string]interface{})
			if !ok {
				continue
			}

			vulnID, _ := vuln["vulnerabilityID"].(string)
			severity, _ := vuln["severity"].(string)
			pkgName, _ := vuln["resource"].(string)
			installedVer, _ := vuln["installedVersion"].(string)
			title, _ := vuln["title"].(string)
			primaryURL, _ := vuln["primaryLink"].(string)

			desc := title
			if d, ok := vuln["description"].(string); ok && d != "" {
				desc = d
			}

			var links []Link
			if isValidURL(primaryURL) {
				links = []Link{{URL: primaryURL}}
			}

			ident := Ident{
				Type:  "cve",
				Name:  vulnID,
				Value: vulnID,
			}
			if isValidURL(primaryURL) {
				ident.URL = primaryURL
			}

			vulns = append(vulns, Vulnerability{
				ID:          fmt.Sprintf("%s-%s-%s", vulnID, sanitize(image), pkgName),
				Category:    "container_scanning",
				Name:        vulnID,
				Message:     fmt.Sprintf("%s in %s [%s/%s/%s]", vulnID, pkgName, namespace, resourceName, containerName),
				Description: firstN(desc, 500),
				Severity:    mapSeverity(severity),
				Location: Location{
					Image:           fullImage,
					OperatingSystem: osInfo,
					Dependency: Dependency{
						Package: Package{Name: pkgName},
						Version: installedVer,
					},
					KubernetesResource: KubernetesResource{
						Namespace:     namespace,
						Kind:          "Pod",
						Name:          resourceName,
						ContainerName: containerName,
					},
				},
				Identifiers: []Ident{ident},
				Links:       links,
			})
		}
	}

	// Sort for consistent hashing (stable sort with secondary key)
	sort.Slice(vulns, func(i, j int) bool {
		if vulns[i].ID != vulns[j].ID {
			return vulns[i].ID < vulns[j].ID
		}
		// Secondary sort by location for stability
		return vulns[i].Location.Image+vulns[i].Location.KubernetesResource.Name <
			vulns[j].Location.Image+vulns[j].Location.KubernetesResource.Name
	})

	return vulns
}

// buildSecurityReport creates a GitLab Security Report from vulnerabilities.
func buildSecurityReport(vulns []Vulnerability) SecurityReport {
	now := time.Now().UTC().Format("2006-01-02T15:04:05")

	// Schema requires vulnerabilities to be an array, never null.
	if vulns == nil {
		vulns = []Vulnerability{}
	}

	return SecurityReport{
		Version:         "15.0.0",
		Vulnerabilities: vulns,
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
			StartAt: now,
			EndAt:   now,
		},
	}
}

// computeVulnHash computes a hash of the vulnerability list.
func computeVulnHash(vulns []Vulnerability) string {
	data, _ := json.Marshal(vulns)
	return fmt.Sprintf("%x", sha256.Sum256(data))[:16]
}

// Helper functions

func isValidURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
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
