package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// Tracker keys for non-namespace state entries.
const (
	globalKey       = "__global__"
	consolidatedKey = "__consolidated__"
)

// runWatcher starts the main vulnerability monitoring loop.
func runWatcher(ctx context.Context, client dynamic.Interface, cfg Config, health *Health) {
	// DeployToken only has write_package_registry, can't read projects
	cacheToken := cfg.GitLabAccessToken
	if cacheToken == "" {
		cacheToken = cfg.DeployToken // Fallback, but project checks will fail
	}
	cache := NewProjectCache(cfg.CacheTTL, cfg.GitLabAPIURL, cacheToken)
	resolver := NewProjectResolver(cfg.GitLabGroupPath, cfg.GitLabDefaultProject, cache, client, cfg.CacheTTL)
	tracker := NewNamespaceTracker()

	vulnGVR := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "vulnerabilityreports",
	}

	slog.Info("starting vulnerability monitoring",
		"poll_interval", cfg.PollInterval,
		"stabilize_time", cfg.StabilizeTime,
		"min_trigger_gap", cfg.MinTriggerGap,
	)

	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()

	var pollCount int
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pollCount++
			if processVulnerabilityReports(ctx, client, vulnGVR, resolver, tracker, cfg, pollCount) {
				if health != nil {
					health.MarkPoll()
				}
			}
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
) bool {
	reports, err := client.Resource(vulnGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		slog.Error("failed to fetch vulnerability reports", "error", err)
		return false
	}

	if len(reports.Items) == 0 {
		// Heartbeat every 6 polls (~1 min at 10s interval)
		if pollCount%6 == 0 {
			slog.Info("no vulnerability reports found in cluster")
		}
		return true
	}

	totalVulns := countTotalVulnerabilities(reports.Items)

	// Step 1: Compute hash of ALL reports (simple: count + resource versions)
	globalHash := computeGlobalHash(reports.Items)
	now := time.Now()

	// Step 2: Check if content changed
	state := tracker.GetState(globalKey)

	changed, oldHash := tracker.UpdateHash(globalKey, globalHash)
	if changed {
		if oldHash == "" {
			slog.Info("initial scan",
				"reports", len(reports.Items),
				"vulnerabilities", totalVulns,
				"hash", globalHash,
			)
		} else {
			slog.Info("content changed",
				"reports", len(reports.Items),
				"vulnerabilities", totalVulns,
				"old_hash", oldHash,
				"new_hash", globalHash,
			)
		}
		// After every content change we restart the stability window. Log it
		// explicitly so operators can see "we noticed, now we're waiting X
		// before doing anything" instead of staring at silence.
		slog.Info("stability timer (re)started",
			"wait_for", cfg.StabilizeTime,
		)
		return true
	}

	// Step 3: Check if stable long enough
	stableFor := now.Sub(state.StableSince)
	if stableFor < cfg.StabilizeTime {
		return true
	}

	// Step 4: Check if already triggered for this hash
	if state.LastTriggerHash == globalHash {
		// Heartbeat every 6 polls when idle
		if pollCount%6 == 0 {
			slog.Info("watching cluster",
				"reports", len(reports.Items),
				"vulnerabilities", totalVulns,
			)
		}
		return true
	}

	// Step 5: Check min gap between triggers
	if !state.LastTriggerTime.IsZero() && now.Sub(state.LastTriggerTime) < cfg.MinTriggerGap {
		return true
	}

	// Step 6: Content stable - now split by namespace and upload
	slog.Info("processing uploads",
		"stable_for", stableFor.Round(time.Second),
		"reports", len(reports.Items),
		"vulnerabilities", totalVulns,
	)

	byNamespace := groupByNamespace(reports.Items)
	scanner := extractScannerInfo(reports.Items)
	allOK := performNamespaceUploads(ctx, byNamespace, resolver, tracker, cfg, scanner)

	// Only mark the global hash as triggered if every namespace succeeded.
	// Otherwise we'd skip the entire next poll cycle and never retry the
	// failed namespaces until cluster content changes again. MarkAttempted
	// still updates LastTriggerTime so MinTriggerGap rate-limits retries.
	if allOK {
		tracker.MarkTriggered(globalKey, globalHash)
	} else {
		tracker.MarkAttempted(globalKey)
	}
	return true
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
// Only uploads namespaces where the vulnerability hash changed since last
// upload. Returns true if every attempted upload succeeded.
func performNamespaceUploads(
	ctx context.Context,
	byNamespace map[string][]unstructured.Unstructured,
	resolver *ProjectResolver,
	tracker *NamespaceTracker,
	cfg Config,
	scanner scannerInfo,
) bool {
	type nsUpload struct {
		namespace string
		project   string
		vulns     []Vulnerability
		hash      string
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
			hash := computeVulnHash(vulns)
			matched = append(matched, nsUpload{
				namespace: ns,
				project:   project,
				vulns:     vulns,
				hash:      hash,
			})
		}
	}

	// Sort for deterministic processing order
	sort.Slice(matched, func(i, j int) bool {
		return matched[i].namespace < matched[j].namespace
	})
	sort.Strings(unmatchedNames)

	uploadCount := 0
	skippedCount := 0
	failedCount := 0
	for _, m := range matched {
		if len(m.vulns) == 0 {
			slog.Info("skipped namespace (no vulnerabilities)", "namespace", m.namespace)
			continue
		}

		// Check if hash changed since last upload
		state := tracker.GetState(m.namespace)
		if state.LastTriggerHash == m.hash {
			slog.Info("skipped namespace (unchanged)",
				"namespace", m.namespace,
				"vulnerabilities", len(m.vulns),
			)
			skippedCount++
			continue
		}

		report := buildSecurityReport(m.vulns, scanner)
		slog.Info("uploading namespace report",
			"namespace", m.namespace,
			"vulnerabilities", len(m.vulns),
			"unique_cves", countUniqueCVEs(m.vulns),
			"project", m.project,
		)
		if err := uploadAndTrigger(cfg, m.project, report); err != nil {
			slog.Error("upload failed",
				"namespace", m.namespace,
				"project", m.project,
				"error", err,
			)
			failedCount++
		} else {
			tracker.MarkTriggered(m.namespace, m.hash)
			uploadCount++

			// Best-effort auto-resolve. Failures don't affect the upload
			// success state — the upload is the authoritative operation.
			if cfg.AutoResolveEnabled {
				currentKeys := buildCurrentKeySet(m.vulns)
				if _, err := resolveStaleFindings(cfg, m.project, m.namespace, currentKeys); err != nil {
					slog.Warn("auto-resolve encountered error",
						"namespace", m.namespace,
						"project", m.project,
						"error", err,
					)
				}
			}
		}
	}

	// Upload consolidated unmatched (only if hash changed)
	if len(unmatchedVulns) > 0 {
		consolidatedHash := computeVulnHash(unmatchedVulns)
		state := tracker.GetState(consolidatedKey)

		if state.LastTriggerHash != consolidatedHash {
			report := buildSecurityReport(unmatchedVulns, scanner)
			slog.Info("uploading consolidated report",
				"namespaces", unmatchedNames,
				"vulnerabilities", len(unmatchedVulns),
				"unique_cves", countUniqueCVEs(unmatchedVulns),
				"project", cfg.GitLabDefaultProject,
			)
			if err := uploadAndTrigger(cfg, cfg.GitLabDefaultProject, report); err != nil {
				slog.Error("consolidated upload failed",
					"project", cfg.GitLabDefaultProject,
					"error", err,
				)
				failedCount++
			} else {
				tracker.MarkTriggered(consolidatedKey, consolidatedHash)
				uploadCount++
			}
		} else {
			slog.Info("skipped consolidated (unchanged)",
				"namespaces", len(unmatchedNames),
				"vulnerabilities", len(unmatchedVulns),
			)
			skippedCount++
		}
	}

	slog.Info("uploads complete",
		"updated", uploadCount,
		"skipped", skippedCount,
		"failed", failedCount,
	)
	return failedCount == 0
}
