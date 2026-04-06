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

// scannerInfo holds metadata about the scanner that produced a report,
// extracted from the trivy-operator VulnerabilityReport CR. Used so the
// Analyzer/Scanner versions in the GitLab report reflect the actual operator
// in the cluster instead of being hardcoded.
type scannerInfo struct {
	Name    string
	Version string
	Vendor  string
}

// extractScannerInfo reads the scanner block from the first report that has
// one. All trivy-operator emissions in a single cluster come from the same
// operator instance, so picking the first non-empty scanner block is safe.
func extractScannerInfo(items []unstructured.Unstructured) scannerInfo {
	for _, item := range items {
		scanner, _, _ := unstructured.NestedMap(item.Object, "report", "scanner")
		if scanner == nil {
			continue
		}
		name, _ := scanner["name"].(string)
		version, _ := scanner["version"].(string)
		if name == "" && version == "" {
			continue
		}
		vendor, _ := scanner["vendor"].(string)
		return scannerInfo{Name: name, Version: version, Vendor: vendor}
	}
	return scannerInfo{}
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
		// trivy-operator attaches reports to the actual workload (ReplicaSet,
		// Deployment, DaemonSet, ...). Use the real kind from the label so the
		// GitLab UI shows what was scanned instead of an incorrect "Pod".
		resourceKind := labels["trivy-operator.resource.kind"]
		if resourceKind == "" {
			resourceKind = "Pod"
		}
		if name := labels["trivy-operator.resource.name"]; name != "" {
			resourceName = name
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
						Kind:          resourceKind,
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

// scannerVersionUnknown is reported when no source CR provided a scanner block.
const scannerVersionUnknown = "unknown"

// buildSecurityReport creates a GitLab Security Report from vulnerabilities.
// The scanner argument carries the actual scanner name/version extracted from
// trivy-operator CRs so the report metadata reflects the running operator
// instead of a hardcoded version.
func buildSecurityReport(vulns []Vulnerability, scanner scannerInfo) SecurityReport {
	now := time.Now().UTC().Format("2006-01-02T15:04:05")

	// Schema requires vulnerabilities to be an array, never null.
	if vulns == nil {
		vulns = []Vulnerability{}
	}

	scannerName := scanner.Name
	if scannerName == "" {
		scannerName = "Trivy"
	}
	scannerVersion := scanner.Version
	if scannerVersion == "" {
		scannerVersion = scannerVersionUnknown
	}
	vendorName := scanner.Vendor
	if vendorName == "" {
		vendorName = "Aqua Security"
	}

	return SecurityReport{
		Version:         "15.0.0",
		Vulnerabilities: vulns,
		Scan: ScanInfo{
			Analyzer: Analyzer{
				ID:      "trivy-operator",
				Name:    "Trivy Operator",
				Version: scannerVersion,
				Vendor:  Vendor{Name: vendorName},
			},
			Scanner: Scanner{
				ID:      "trivy",
				Name:    scannerName,
				Version: scannerVersion,
				Vendor:  Vendor{Name: vendorName},
			},
			Type:    "container_scanning",
			Status:  "success",
			StartAt: now,
			EndAt:   now,
		},
	}
}

// countUniqueCVEs returns the number of distinct CVE identifiers in the list.
// trivy-operator emits one finding per (CVE, container) pair, so the raw list
// inflates totals when the same image runs in multiple workloads. GitLab
// deduplicates server-side; this gives operators an honest count in the logs.
func countUniqueCVEs(vulns []Vulnerability) int {
	seen := make(map[string]struct{}, len(vulns))
	for _, v := range vulns {
		seen[v.Name] = struct{}{}
	}
	return len(seen)
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
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "..."
}
