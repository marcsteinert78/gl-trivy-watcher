package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// gitlabVulnerability mirrors the subset of fields we need from GitLab's
// /projects/:id/vulnerabilities API response. We only parse fields relevant
// for (a) identifying the CVE, (b) locating the workload, and (c) calling
// the resolve endpoint.
//
// NOTE: In the list response, location and identifiers live UNDER a "finding"
// sub-object, not at the top level. The top-level "location" field exists but
// is always empty in the list view.
type gitlabVulnerability struct {
	ID         int             `json:"id"`
	Severity   string          `json:"severity"`
	State      string          `json:"state"`
	ReportType string          `json:"report_type"`
	Finding    gitlabFinding   `json:"finding"`
}

// gitlabFinding is the nested "finding" object containing the actual
// location and identifier data we match against.
type gitlabFinding struct {
	Location gitlabLocation `json:"location"`
	// Some findings expose identifiers inside a nested "primary_identifier"
	// plus an array. To keep things simple we also parse identifiers from
	// the raw_metadata as a fallback when the typed fields are empty.
	RawMetadata string `json:"raw_metadata"`
	Name        string `json:"name"`
}

type gitlabLocation struct {
	Image      string             `json:"image"`
	Dependency gitlabDependency   `json:"dependency"`
	Kubernetes gitlabKubeResource `json:"kubernetes_resource"`
}

type gitlabDependency struct {
	Package gitlabPackage `json:"package"`
}

type gitlabPackage struct {
	Name string `json:"name"`
}

type gitlabKubeResource struct {
	Namespace     string `json:"namespace"`
	ContainerName string `json:"container_name"`
}

// stalenessKey is the logical identity we use to compare current scan findings
// with detected findings in GitLab. Deliberately excludes the image tag so
// image bumps don't leave the old tag's findings stale forever.
type stalenessKey struct {
	CVE       string
	Namespace string
	Container string
	Package   string
	// ImageRepo is the image WITHOUT the tag (repo only). Keeping this lets us
	// distinguish "same container, different image entirely" — rare but avoids
	// accidentally resolving an unrelated finding.
	ImageRepo string
}

// buildCurrentKeySet builds the set of stalenessKeys present in the current
// cluster scan for a single namespace upload. Anything in GitLab's detected
// list that is NOT in this set is stale.
func buildCurrentKeySet(vulns []Vulnerability) map[stalenessKey]struct{} {
	set := make(map[stalenessKey]struct{}, len(vulns))
	for _, v := range vulns {
		cve := firstCVE(v.Identifiers)
		if cve == "" {
			continue
		}
		set[stalenessKey{
			CVE:       cve,
			Namespace: v.Location.KubernetesResource.Namespace,
			Container: v.Location.KubernetesResource.ContainerName,
			Package:   v.Location.Dependency.Package.Name,
			ImageRepo: imageRepoWithoutTag(v.Location.Image),
		}] = struct{}{}
	}
	return set
}

// firstCVE returns the first CVE identifier from the list, or empty if none.
func firstCVE(ids []Ident) string {
	for _, id := range ids {
		if strings.EqualFold(id.Type, "cve") {
			return id.Name
		}
	}
	return ""
}

// imageRepoWithoutTag strips the :tag suffix from an image reference.
// "paperless-ngx/paperless-ngx:2.20.7" -> "paperless-ngx/paperless-ngx"
func imageRepoWithoutTag(image string) string {
	if i := strings.LastIndex(image, ":"); i > 0 {
		// Avoid splitting on :port of a registry host (e.g. "localhost:5000/x")
		// Only strip if there's no '/' after the last ':'
		if !strings.Contains(image[i+1:], "/") {
			return image[:i]
		}
	}
	return image
}

// cveFromGitLabVuln extracts the CVE name. GitLab returns the CVE either in
// the top-level "title" or inside finding.raw_metadata; we prefer the title
// since it's already plain text (e.g. "CVE-2026-0968"). If the title isn't a
// CVE-id, we parse raw_metadata for the first "cve" identifier.
func cveFromGitLabVuln(v gitlabVulnerability) string {
	// The title field is the most reliable — GitLab sets it to the CVE ID
	// for cluster_image_scanning findings.
	if strings.HasPrefix(v.Finding.Name, "CVE-") {
		return v.Finding.Name
	}
	// Fallback: parse the raw_metadata JSON blob for the first CVE
	// identifier. raw_metadata is always set for cluster_image_scanning.
	if v.Finding.RawMetadata != "" {
		var rm struct {
			Identifiers []struct {
				Type  string `json:"type"`
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"identifiers"`
		}
		if err := json.Unmarshal([]byte(v.Finding.RawMetadata), &rm); err == nil {
			for _, id := range rm.Identifiers {
				if strings.EqualFold(id.Type, "cve") {
					if id.Value != "" {
						return id.Value
					}
					return id.Name
				}
			}
		}
	}
	return ""
}

// stalenessKeyFromGitLab builds the comparison key for a GitLab vulnerability.
// Returns ok=false if essential fields are missing (CVE, container, package).
func stalenessKeyFromGitLab(v gitlabVulnerability) (stalenessKey, bool) {
	cve := cveFromGitLabVuln(v)
	if cve == "" {
		return stalenessKey{}, false
	}
	k := stalenessKey{
		CVE:       cve,
		Namespace: v.Finding.Location.Kubernetes.Namespace,
		Container: v.Finding.Location.Kubernetes.ContainerName,
		Package:   v.Finding.Location.Dependency.Package.Name,
		ImageRepo: imageRepoWithoutTag(v.Finding.Location.Image),
	}
	if k.Container == "" || k.Package == "" {
		return stalenessKey{}, false
	}
	return k, true
}

// resolveStaleFindings queries GitLab for all detected cluster_image_scanning
// vulnerabilities in the project, finds those not present in the current scan,
// and marks them as resolved. Designed to be called after a successful upload
// for the same namespace so GitLab has the latest report.
//
// Returns the number of findings resolved (or that would have been resolved
// in dry-run mode). Non-fatal errors are logged and counted as failures; the
// caller should treat this as best-effort cleanup, not a critical path.
func resolveStaleFindings(cfg Config, project string, namespace string, currentKeys map[stalenessKey]struct{}) (int, error) {
	if !cfg.AutoResolveEnabled {
		return 0, nil
	}

	detected, err := listDetectedVulnerabilities(cfg, project)
	if err != nil {
		return 0, fmt.Errorf("list detected: %w", err)
	}

	var stale []gitlabVulnerability
	skippedUnparseable := 0
	skippedOtherNS := 0

	for _, v := range detected {
		// Only touch cluster_image_scanning findings. Other report_types
		// (e.g. container_scanning from non-OCS CI) have different
		// resolution semantics.
		if v.ReportType != "cluster_image_scanning" {
			continue
		}
		// Only touch findings belonging to the namespace we just scanned.
		// Each namespace upload should not affect another namespace's
		// findings, even if they happen to share the same project.
		if v.Finding.Location.Kubernetes.Namespace != namespace {
			skippedOtherNS++
			continue
		}

		k, ok := stalenessKeyFromGitLab(v)
		if !ok {
			skippedUnparseable++
			continue
		}
		if _, found := currentKeys[k]; !found {
			stale = append(stale, v)
		}
	}

	if len(stale) == 0 {
		slog.Info("auto-resolve: no stale findings",
			"project", project,
			"namespace", namespace,
			"detected_total", len(detected),
			"skipped_unparseable", skippedUnparseable,
			"skipped_other_ns", skippedOtherNS,
		)
		return 0, nil
	}

	// Safety cap — abort if a bug would resolve an implausible number.
	if cfg.AutoResolveMaxPerRun > 0 && len(stale) > cfg.AutoResolveMaxPerRun {
		slog.Warn("auto-resolve: stale count exceeds cap, aborting to prevent accidental mass-resolution",
			"project", project,
			"namespace", namespace,
			"stale_count", len(stale),
			"cap", cfg.AutoResolveMaxPerRun,
		)
		return 0, fmt.Errorf("stale count %d exceeds cap %d", len(stale), cfg.AutoResolveMaxPerRun)
	}

	slog.Info("auto-resolve: stale findings identified",
		"project", project,
		"namespace", namespace,
		"stale_count", len(stale),
		"dry_run", cfg.AutoResolveDryRun,
	)

	if cfg.AutoResolveDryRun {
		for _, v := range stale {
			slog.Info("auto-resolve: would resolve (dry-run)",
				"project", project,
				"vulnerability_id", v.ID,
				"cve", cveFromGitLabVuln(v),
				"image", v.Finding.Location.Image,
				"container", v.Finding.Location.Kubernetes.ContainerName,
				"package", v.Finding.Location.Dependency.Package.Name,
			)
		}
		return len(stale), nil
	}

	resolved := 0
	failed := 0
	for _, v := range stale {
		if err := resolveVulnerability(cfg, project, v.ID); err != nil {
			slog.Error("auto-resolve: resolve failed",
				"project", project,
				"vulnerability_id", v.ID,
				"error", err,
			)
			failed++
			continue
		}
		resolved++
	}

	slog.Info("auto-resolve: complete",
		"project", project,
		"namespace", namespace,
		"resolved", resolved,
		"failed", failed,
	)
	return resolved, nil
}

// listDetectedVulnerabilities pages through GitLab's vulnerabilities API for
// the project. Filtered to state=detected to avoid touching manually resolved
// or dismissed findings.
func listDetectedVulnerabilities(cfg Config, project string) ([]gitlabVulnerability, error) {
	const perPage = 100
	var all []gitlabVulnerability

	for page := 1; ; page++ {
		u := fmt.Sprintf("%s/projects/%s/vulnerabilities?state=detected&per_page=%d&page=%d",
			cfg.GitLabAPIURL, url.PathEscape(project), perPage, page)

		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			return nil, fmt.Errorf("new request: %w", err)
		}
		req.Header.Set("PRIVATE-TOKEN", cfg.GitLabAccessToken)
		req.Header.Set("Accept", "application/json")

		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("http: %w", err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read body: %w", err)
		}
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
		}

		var pageItems []gitlabVulnerability
		if err := json.Unmarshal(body, &pageItems); err != nil {
			return nil, fmt.Errorf("decode: %w", err)
		}
		all = append(all, pageItems...)
		if len(pageItems) < perPage {
			break
		}

		// Hard cap to avoid an infinite loop if the API misbehaves.
		if page >= 100 {
			slog.Warn("auto-resolve: listDetectedVulnerabilities hit page cap",
				"project", project,
				"pages_read", page,
			)
			break
		}
	}

	return all, nil
}

// resolveVulnerability calls the GitLab vulnerability resolution endpoint.
// The resolve action lives at the TOP-LEVEL /vulnerabilities/:id/resolve —
// NOT nested under /projects/:id. Vulnerability IDs are globally unique in
// GitLab, so the project-scoped path returns 404.
// This is idempotent — calling it on an already-resolved vuln returns 200.
func resolveVulnerability(cfg Config, project string, vulnerabilityID int) error {
	_ = project // kept in signature for logging/audit parity; path is global
	u := fmt.Sprintf("%s/vulnerabilities/%d/resolve",
		cfg.GitLabAPIURL, vulnerabilityID)

	req, err := http.NewRequest("POST", u, bytes.NewReader(nil))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("PRIVATE-TOKEN", cfg.GitLabAccessToken)

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 && resp.StatusCode != 201 && resp.StatusCode != 304 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}
