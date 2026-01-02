package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// runWatcher starts the main vulnerability monitoring loop.
func runWatcher(ctx context.Context, client dynamic.Interface, cfg Config) {
	// DeployToken only has write_package_registry, can't read projects
	cacheToken := cfg.GitLabAccessToken
	if cacheToken == "" {
		cacheToken = cfg.DeployToken // Fallback, but project checks will fail
	}
	cache := NewProjectCache(cfg.CacheTTL, cfg.GitLabAPIURL, cacheToken)
	resolver := NewProjectResolver(cfg.GitLabGroupPath, cfg.GitLabDefaultProject, cache, client)
	tracker := NewNamespaceTracker()

	vulnGVR := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "vulnerabilityreports",
	}

	fmt.Println("Starting vulnerability monitoring...")
	fmt.Println()

	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()

	var pollCount int
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pollCount++
			processVulnerabilityReports(ctx, client, vulnGVR, resolver, tracker, cfg, pollCount)
		}
	}
}

// processVulnerabilityReports fetches and processes all vulnerability reports.
func processVulnerabilityReports(
	ctx context.Context,
	client dynamic.Interface,
	vulnGVR schema.GroupVersionResource,
	resolver *ProjectResolver,
	tracker *NamespaceTracker,
	cfg Config,
	pollCount int,
) {
	reports, err := client.Resource(vulnGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching reports: %v\n", err)
		return
	}

	if len(reports.Items) == 0 {
		// Heartbeat every 6 polls (~1 min at 10s interval)
		if pollCount%6 == 0 {
			fmt.Printf("[%s] No VulnerabilityReports found in cluster\n", time.Now().Format("15:04:05"))
		}
		return
	}

	// Count total vulnerabilities across all reports
	totalVulns := countTotalVulnerabilities(reports.Items)

	// Step 1: Compute hash of ALL reports (simple: count + resource versions)
	globalHash := computeGlobalHash(reports.Items)
	now := time.Now()

	// Step 2: Check if content changed
	const globalKey = "__global__"
	state := tracker.GetState(globalKey)

	changed, oldHash := tracker.UpdateHash(globalKey, globalHash)
	if changed {
		if oldHash == "" {
			fmt.Printf("[%s] Initial scan: %d VulnerabilityReports, %d vulnerabilities (hash: %s)\n",
				now.Format("15:04:05"), len(reports.Items), totalVulns, globalHash)
		} else {
			fmt.Printf("[%s] Content changed: %d VulnerabilityReports, %d vulnerabilities (hash: %s → %s)\n",
				now.Format("15:04:05"), len(reports.Items), totalVulns, oldHash, globalHash)
		}
		fmt.Printf("[%s] Waiting %s for stabilization...\n", now.Format("15:04:05"), cfg.StabilizeTime)
		return
	}

	// Step 3: Check if stable long enough
	stableFor := now.Sub(state.StableSince)
	if stableFor < cfg.StabilizeTime {
		// Show progress every 6 polls during stabilization
		if pollCount%6 == 0 {
			remaining := cfg.StabilizeTime - stableFor
			fmt.Printf("[%s] Stabilizing... %s remaining\n", now.Format("15:04:05"), remaining.Round(time.Second))
		}
		return
	}

	// Step 4: Check if already triggered for this hash
	if state.LastTriggerHash == globalHash {
		// Heartbeat every 6 polls when idle
		if pollCount%6 == 0 {
			fmt.Printf("[%s] Watching %d VulnerabilityReports, %d vulnerabilities (no changes)\n",
				now.Format("15:04:05"), len(reports.Items), totalVulns)
		}
		return
	}

	// Step 5: Check min gap between triggers
	if !state.LastTriggerTime.IsZero() && now.Sub(state.LastTriggerTime) < cfg.MinTriggerGap {
		remaining := cfg.MinTriggerGap - now.Sub(state.LastTriggerTime)
		if pollCount%6 == 0 {
			fmt.Printf("[%s] Rate limited, next trigger in %s\n", now.Format("15:04:05"), remaining.Round(time.Second))
		}
		return
	}

	// Step 6: Content stable - now split by namespace and upload
	fmt.Printf("\n[%s] === Processing Uploads (stable for %s) ===\n", now.Format("15:04:05"), stableFor.Round(time.Second))
	fmt.Printf("[%s] Total: %d VulnerabilityReports, %d vulnerabilities\n\n", now.Format("15:04:05"), len(reports.Items), totalVulns)

	byNamespace := groupByNamespace(reports.Items)
	performNamespaceUploads(ctx, byNamespace, resolver, cfg)

	// Mark as triggered
	tracker.MarkTriggered(globalKey, globalHash)
	fmt.Println()
}

// countTotalVulnerabilities counts all vulnerabilities across all reports.
func countTotalVulnerabilities(items []unstructured.Unstructured) int {
	total := 0
	for _, item := range items {
		report := item.Object
		if reportData, ok := report["report"].(map[string]interface{}); ok {
			if vulns, ok := reportData["vulnerabilities"].([]interface{}); ok {
				total += len(vulns)
			}
		}
	}
	return total
}

// computeGlobalHash computes a hash of all report resource versions.
func computeGlobalHash(items []unstructured.Unstructured) string {
	var versions []string
	for _, item := range items {
		versions = append(versions, item.GetName()+":"+item.GetResourceVersion())
	}
	sort.Strings(versions)
	data, _ := json.Marshal(versions)
	return fmt.Sprintf("%x", sha256.Sum256(data))[:16]
}

// performNamespaceUploads uploads vulnerabilities grouped by namespace.
func performNamespaceUploads(
	ctx context.Context,
	byNamespace map[string][]unstructured.Unstructured,
	resolver *ProjectResolver,
	cfg Config,
) {
	type nsUpload struct {
		namespace string
		project   string
		vulns     []Vulnerability
	}

	var matched []nsUpload
	var unmatchedNames []string
	var unmatchedVulns []Vulnerability

	for ns, items := range byNamespace {
		vulns := convertItemsToVulnerabilities(items)
		project, isDefault := resolver.Resolve(ctx, ns)

		if isDefault {
			unmatchedNames = append(unmatchedNames, ns)
			unmatchedVulns = append(unmatchedVulns, vulns...)
		} else {
			matched = append(matched, nsUpload{
				namespace: ns,
				project:   project,
				vulns:     vulns,
			})
		}
	}

	// Sort for consistent output
	sort.Slice(matched, func(i, j int) bool {
		return matched[i].namespace < matched[j].namespace
	})
	sort.Strings(unmatchedNames)

	// Upload matched namespaces
	uploadCount := 0
	for _, m := range matched {
		if len(m.vulns) == 0 {
			fmt.Printf("  ○ %s: 0 vulnerabilities (skipped)\n", m.namespace)
			continue
		}
		report := buildSecurityReport(m.vulns)
		fmt.Printf("  → %s: %d vulnerabilities → %s\n", m.namespace, len(m.vulns), m.project)
		if err := uploadAndTrigger(cfg, m.project, report); err != nil {
			fmt.Fprintf(os.Stderr, "    ERROR: %v\n", err)
		} else {
			uploadCount++
		}
	}

	// Upload consolidated unmatched
	if len(unmatchedVulns) > 0 {
		report := buildSecurityReport(unmatchedVulns)
		fmt.Printf("  → consolidated (%d namespaces): %d vulnerabilities → %s\n",
			len(unmatchedNames), len(unmatchedVulns), cfg.GitLabDefaultProject)
		fmt.Printf("    Namespaces: %v\n", unmatchedNames)
		if err := uploadAndTrigger(cfg, cfg.GitLabDefaultProject, report); err != nil {
			fmt.Fprintf(os.Stderr, "    ERROR: %v\n", err)
		} else {
			uploadCount++
		}
	}

	fmt.Printf("\nUploads complete: %d projects updated\n", uploadCount)
}
