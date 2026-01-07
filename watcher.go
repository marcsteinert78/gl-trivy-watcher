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
	progress := NewProgressDisplay(10 * time.Second)

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
			progress.Stop()
			return
		case <-ticker.C:
			pollCount++
			processVulnerabilityReports(ctx, client, vulnGVR, resolver, tracker, progress, cfg, pollCount)
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
	progress *ProgressDisplay,
	cfg Config,
	pollCount int,
) {
	// Stop any active progress display at start of each poll
	progress.Stop()
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
		// Start progress display for stabilization
		progress.Start("Stabilizing", now.Add(cfg.StabilizeTime))
		return
	}

	// Step 3: Check if stable long enough
	stableFor := now.Sub(state.StableSince)
	if stableFor < cfg.StabilizeTime {
		// Continue progress display during stabilization
		endTime := state.StableSince.Add(cfg.StabilizeTime)
		progress.Start("Stabilizing", endTime)
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
		// Show progress display for rate limiting
		endTime := state.LastTriggerTime.Add(cfg.MinTriggerGap)
		progress.Start("Rate limited", endTime)
		return
	}

	// Step 6: Content stable - now split by namespace and upload
	fmt.Printf("\n[%s] === Processing Uploads (stable for %s) ===\n", now.Format("15:04:05"), stableFor.Round(time.Second))
	fmt.Printf("[%s] Total: %d VulnerabilityReports, %d vulnerabilities\n\n", now.Format("15:04:05"), len(reports.Items), totalVulns)

	byNamespace := groupByNamespace(reports.Items)
	performNamespaceUploads(ctx, byNamespace, resolver, tracker, cfg)

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
// Only uploads namespaces where the vulnerability hash changed since last upload.
// Always includes namespaces from cfg.AlwaysIncludeNamespaces even if they have no reports.
func performNamespaceUploads(
	ctx context.Context,
	byNamespace map[string][]unstructured.Unstructured,
	resolver *ProjectResolver,
	tracker *NamespaceTracker,
	cfg Config,
) {
	type nsUpload struct {
		namespace string
		project   string
		vulns     []Vulnerability
		hash      string
	}

	var matched []nsUpload
	var unmatchedNames []string
	var unmatchedVulns []Vulnerability

	// Ensure always-include namespaces are in the map (with empty slice if not present)
	for _, ns := range cfg.AlwaysIncludeNamespaces {
		if _, exists := byNamespace[ns]; !exists {
			byNamespace[ns] = []unstructured.Unstructured{}
		}
	}

	for ns, items := range byNamespace {
		vulns := convertItemsToVulnerabilities(items)
		project, isDefault := resolver.Resolve(ctx, ns)

		if isDefault {
			unmatchedNames = append(unmatchedNames, ns)
			unmatchedVulns = append(unmatchedVulns, vulns...)
		} else {
			hash := computeVulnHash(vulns)
			matched = append(matched, nsUpload{
				namespace: ns,
				project:   project,
				vulns:     vulns,
				hash:      hash,
			})
		}
	}

	// Sort for consistent output
	sort.Slice(matched, func(i, j int) bool {
		return matched[i].namespace < matched[j].namespace
	})
	sort.Strings(unmatchedNames)

	// Upload matched namespaces (only if hash changed)
	uploadCount := 0
	skippedCount := 0
	for _, m := range matched {
		// Check if hash changed since last upload
		state := tracker.GetState(m.namespace)
		if state.LastTriggerHash == m.hash {
			fmt.Printf("  ○ %s: %d vulnerabilities (unchanged, skipped)\n", m.namespace, len(m.vulns))
			skippedCount++
			continue
		}

		// Upload even with 0 vulnerabilities - this clears the security dashboard
		report := buildSecurityReport(m.vulns)
		fmt.Printf("  → %s: %d vulnerabilities → %s\n", m.namespace, len(m.vulns), m.project)
		if err := uploadAndTrigger(cfg, m.project, report); err != nil {
			fmt.Fprintf(os.Stderr, "    ERROR: %v\n", err)
		} else {
			tracker.MarkTriggered(m.namespace, m.hash)
			uploadCount++
		}
	}

	// Upload consolidated unmatched (only if hash changed)
	// Also upload if there are unmatched namespaces with 0 vulns (to clear dashboards)
	if len(unmatchedNames) > 0 {
		consolidatedHash := computeVulnHash(unmatchedVulns)
		consolidatedKey := "__consolidated__"
		state := tracker.GetState(consolidatedKey)

		if state.LastTriggerHash != consolidatedHash {
			report := buildSecurityReport(unmatchedVulns)
			fmt.Printf("  → consolidated (%d namespaces): %d vulnerabilities → %s\n",
				len(unmatchedNames), len(unmatchedVulns), cfg.GitLabDefaultProject)
			fmt.Printf("    Namespaces: %v\n", unmatchedNames)
			if err := uploadAndTrigger(cfg, cfg.GitLabDefaultProject, report); err != nil {
				fmt.Fprintf(os.Stderr, "    ERROR: %v\n", err)
			} else {
				tracker.MarkTriggered(consolidatedKey, consolidatedHash)
				uploadCount++
			}
		} else {
			fmt.Printf("  ○ consolidated (%d namespaces): %d vulnerabilities (unchanged, skipped)\n",
				len(unmatchedNames), len(unmatchedVulns))
			skippedCount++
		}
	}

	if skippedCount > 0 {
		fmt.Printf("\nUploads complete: %d updated, %d unchanged (skipped)\n", uploadCount, skippedCount)
	} else {
		fmt.Printf("\nUploads complete: %d projects updated\n", uploadCount)
	}
}
