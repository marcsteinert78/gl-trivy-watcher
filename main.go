package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

// ============================================================================
// GitLab Security Report Types
// ============================================================================

type SecurityReport struct {
	Version         string          `json:"version"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Scan            ScanInfo        `json:"scan"`
}

type Vulnerability struct {
	ID          string   `json:"id"`
	Category    string   `json:"category"`
	Name        string   `json:"name"`
	Message     string   `json:"message"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Location    Location `json:"location"`
	Identifiers []Ident  `json:"identifiers"`
	Links       []Link   `json:"links,omitempty"`
}

type Location struct {
	Image              string             `json:"image"`
	OperatingSystem    string             `json:"operating_system"`
	Dependency         Dependency         `json:"dependency"`
	KubernetesResource KubernetesResource `json:"kubernetes_resource"`
}

type KubernetesResource struct {
	Namespace     string `json:"namespace"`
	Kind          string `json:"kind"`
	Name          string `json:"name"`
	ContainerName string `json:"container_name"`
}

type Dependency struct {
	Package Package `json:"package"`
	Version string  `json:"version"`
}

type Package struct {
	Name string `json:"name"`
}

type Ident struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	URL   string `json:"url,omitempty"`
}

type Link struct {
	URL string `json:"url"`
}

type ScanInfo struct {
	Analyzer Analyzer `json:"analyzer"`
	Scanner  Scanner  `json:"scanner"`
	Type     string   `json:"type"`
	Status   string   `json:"status"`
	StartAt  string   `json:"start_time"`
	EndAt    string   `json:"end_time"`
}

type Analyzer struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Vendor  Vendor `json:"vendor"`
}

type Scanner struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Vendor  Vendor `json:"vendor"`
}

type Vendor struct {
	Name string `json:"name"`
}

// ============================================================================
// Configuration
// ============================================================================

type Config struct {
	// GitLab settings
	GitLabAPIURL         string
	GitLabGroupPath      string // e.g., "msteinert1/homeserver"
	GitLabDefaultProject string // Fallback project for unmatched namespaces
	GitLabRef            string

	// Authentication
	DeployToken       string // write_package_registry scope (group-level works for all projects)
	DeployTokenUser   string
	GitLabAccessToken string // PAT or Group Token with api scope (for multi-project pipeline triggers)
	TriggerToken      string // Legacy: project-specific pipeline trigger (single-project only)

	// Timing
	PollInterval  time.Duration
	StabilizeTime time.Duration
	MinTriggerGap time.Duration
	CacheTTL      time.Duration
}

// ============================================================================
// Project Cache - Caches project existence checks
// ============================================================================

type ProjectCache struct {
	mu      sync.RWMutex
	exists  map[string]bool
	checked map[string]time.Time
	ttl     time.Duration
	apiURL  string
	token   string
}

func NewProjectCache(ttl time.Duration, apiURL, token string) *ProjectCache {
	return &ProjectCache{
		exists:  make(map[string]bool),
		checked: make(map[string]time.Time),
		ttl:     ttl,
		apiURL:  apiURL,
		token:   token,
	}
}

func (c *ProjectCache) Exists(projectPath string) bool {
	c.mu.RLock()
	if checkedAt, ok := c.checked[projectPath]; ok {
		if time.Since(checkedAt) < c.ttl {
			exists := c.exists[projectPath]
			c.mu.RUnlock()
			return exists
		}
	}
	c.mu.RUnlock()

	// Cache miss or expired - check via API
	exists := c.checkViaAPI(projectPath)

	c.mu.Lock()
	c.exists[projectPath] = exists
	c.checked[projectPath] = time.Now()
	c.mu.Unlock()

	return exists
}

func (c *ProjectCache) checkViaAPI(projectPath string) bool {
	checkURL := fmt.Sprintf("%s/projects/%s", c.apiURL, url.PathEscape(projectPath))

	req, err := http.NewRequest("GET", checkURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("PRIVATE-TOKEN", c.token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	return resp.StatusCode == 200
}

// MarkExists explicitly marks a project as existing (for default project)
func (c *ProjectCache) MarkExists(projectPath string) {
	c.mu.Lock()
	c.exists[projectPath] = true
	c.checked[projectPath] = time.Now()
	c.mu.Unlock()
}

// ============================================================================
// Namespace State Tracking - Per-namespace hash and trigger tracking
// ============================================================================

type NamespaceState struct {
	Hash            string
	StableSince     time.Time
	LastTriggerHash string
	LastTriggerTime time.Time
}

type NamespaceTracker struct {
	mu     sync.RWMutex
	states map[string]*NamespaceState
}

func NewNamespaceTracker() *NamespaceTracker {
	return &NamespaceTracker{
		states: make(map[string]*NamespaceState),
	}
}

func (t *NamespaceTracker) GetState(namespace string) *NamespaceState {
	t.mu.Lock()
	defer t.mu.Unlock()

	state, ok := t.states[namespace]
	if !ok {
		state = &NamespaceState{}
		t.states[namespace] = state
	}
	return state
}

func (t *NamespaceTracker) UpdateHash(namespace, hash string) (changed bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	state, ok := t.states[namespace]
	if !ok {
		state = &NamespaceState{}
		t.states[namespace] = state
	}

	if state.Hash != hash {
		state.Hash = hash
		state.StableSince = time.Now()
		return true
	}
	return false
}

func (t *NamespaceTracker) MarkTriggered(namespace, hash string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if state, ok := t.states[namespace]; ok {
		state.LastTriggerHash = hash
		state.LastTriggerTime = time.Now()
	}
}

// ============================================================================
// Project Resolution - Annotation → Convention → Default
// ============================================================================

const annotationGitLabProject = "trivy-watcher.io/gitlab-project"

type ProjectResolver struct {
	groupPath      string
	defaultProject string
	cache          *ProjectCache
	client         dynamic.Interface
}

func NewProjectResolver(groupPath, defaultProject string, cache *ProjectCache, client dynamic.Interface) *ProjectResolver {
	// Default project always exists
	cache.MarkExists(defaultProject)

	return &ProjectResolver{
		groupPath:      groupPath,
		defaultProject: defaultProject,
		cache:          cache,
		client:         client,
	}
}

// Resolve determines the GitLab project for a namespace.
// Returns (projectPath, isDefault)
func (r *ProjectResolver) Resolve(ctx context.Context, namespace string) (string, bool) {
	// 1. Check for explicit annotation
	if project := r.getNamespaceAnnotation(ctx, namespace); project != "" {
		if r.cache.Exists(project) {
			return project, false
		}
		// Annotation points to non-existent project - fall through to default
	}

	// 2. Try convention-based resolution: {group}/{namespace}
	if r.groupPath != "" {
		conventionProject := fmt.Sprintf("%s/%s", r.groupPath, namespace)
		if r.cache.Exists(conventionProject) {
			return conventionProject, false
		}
	}

	// 3. Fall back to default
	return r.defaultProject, true
}

func (r *ProjectResolver) getNamespaceAnnotation(ctx context.Context, namespace string) string {
	nsGVR := schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "namespaces",
	}

	ns, err := r.client.Resource(nsGVR).Get(ctx, namespace, metav1.GetOptions{})
	if err != nil {
		return ""
	}

	annotations, _, _ := unstructured.NestedStringMap(ns.Object, "metadata", "annotations")
	return annotations[annotationGitLabProject]
}

// ============================================================================
// Main Application
// ============================================================================

func main() {
	cfg := Config{
		GitLabAPIURL:         getEnvOrDefault("GITLAB_API_URL", "https://gitlab.com/api/v4"),
		GitLabGroupPath:      os.Getenv("GITLAB_GROUP_PATH"),
		GitLabDefaultProject: os.Getenv("GITLAB_DEFAULT_PROJECT"),
		GitLabRef:            getEnvOrDefault("GITLAB_REF", "main"),
		DeployToken:          os.Getenv("DEPLOY_TOKEN"),
		DeployTokenUser:      os.Getenv("DEPLOY_TOKEN_USER"),
		GitLabAccessToken:    os.Getenv("GITLAB_ACCESS_TOKEN"),
		TriggerToken:         os.Getenv("TRIGGER_TOKEN"),
		PollInterval:         getDurationEnv("POLL_INTERVAL", 10*time.Second),
		StabilizeTime:        getDurationEnv("STABILIZE_TIME", 60*time.Second),
		MinTriggerGap:        getDurationEnv("MIN_TRIGGER_GAP", 5*time.Minute),
		CacheTTL:             getDurationEnv("CACHE_TTL", 5*time.Minute),
	}

	if err := validateConfig(cfg); err != nil {
		fmt.Printf("ERROR: %v\n", err)
		os.Exit(1)
	}

	k8sConfig, err := rest.InClusterConfig()
	if err != nil {
		fmt.Printf("ERROR: Failed to get k8s config: %v\n", err)
		os.Exit(1)
	}

	client, err := dynamic.NewForConfig(k8sConfig)
	if err != nil {
		fmt.Printf("ERROR: Failed to create k8s client: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		cancel()
	}()

	printStartupBanner(cfg)
	runWatcher(ctx, client, cfg)
}

func validateConfig(cfg Config) error {
	if cfg.GitLabDefaultProject == "" {
		return fmt.Errorf("GITLAB_DEFAULT_PROJECT required")
	}
	if cfg.DeployToken == "" || cfg.DeployTokenUser == "" {
		return fmt.Errorf("DEPLOY_TOKEN and DEPLOY_TOKEN_USER required")
	}
	if cfg.GitLabAccessToken == "" && cfg.TriggerToken == "" {
		return fmt.Errorf("GITLAB_ACCESS_TOKEN or TRIGGER_TOKEN required")
	}
	return nil
}

func printStartupBanner(cfg Config) {
	fmt.Println("=== Trivy Vulnerability Watcher ===")
	fmt.Println()
	fmt.Println("Configuration:")
	fmt.Printf("  GitLab API:        %s\n", cfg.GitLabAPIURL)
	if cfg.GitLabGroupPath != "" {
		fmt.Printf("  Group Path:        %s\n", cfg.GitLabGroupPath)
		fmt.Println("  Resolution:        namespace annotation → group/namespace → default")
	} else {
		fmt.Println("  Resolution:        namespace annotation → default")
	}
	fmt.Printf("  Default Project:   %s\n", cfg.GitLabDefaultProject)
	fmt.Printf("  Git Ref:           %s\n", cfg.GitLabRef)
	fmt.Println()
	fmt.Println("Authentication:")
	fmt.Printf("  Deploy Token:      %s (upload)\n", cfg.DeployTokenUser)
	if cfg.GitLabAccessToken != "" {
		fmt.Println("  Pipeline Trigger:  Access Token (multi-project)")
	} else {
		fmt.Println("  Pipeline Trigger:  Trigger Token (single-project)")
	}
	fmt.Println()
	fmt.Println("Timing:")
	fmt.Printf("  Poll Interval:     %s\n", cfg.PollInterval)
	fmt.Printf("  Stabilize Time:    %s\n", cfg.StabilizeTime)
	fmt.Printf("  Min Trigger Gap:   %s\n", cfg.MinTriggerGap)
	fmt.Printf("  Cache TTL:         %s\n", cfg.CacheTTL)
	fmt.Println()
}

func runWatcher(ctx context.Context, client dynamic.Interface, cfg Config) {
	cache := NewProjectCache(cfg.CacheTTL, cfg.GitLabAPIURL, cfg.DeployToken)
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

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			processVulnerabilityReports(ctx, client, vulnGVR, resolver, tracker, cfg)
		}
	}
}

// ============================================================================
// Report Processing
// ============================================================================

func processVulnerabilityReports(
	ctx context.Context,
	client dynamic.Interface,
	vulnGVR schema.GroupVersionResource,
	resolver *ProjectResolver,
	tracker *NamespaceTracker,
	cfg Config,
) {
	reports, err := client.Resource(vulnGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching reports: %v\n", err)
		return
	}

	if len(reports.Items) == 0 {
		return
	}

	// Step 1: Compute hash of ALL reports (simple: count + resource versions)
	globalHash := computeGlobalHash(reports.Items)
	now := time.Now()

	// Step 2: Check if content changed
	const globalKey = "__global__"
	state := tracker.GetState(globalKey)

	if tracker.UpdateHash(globalKey, globalHash) {
		fmt.Printf("Content changed (%d reports), waiting to stabilize...\n", len(reports.Items))
		return
	}

	// Step 3: Check if stable long enough
	stableFor := now.Sub(state.StableSince)
	if stableFor < cfg.StabilizeTime {
		return // Still stabilizing, wait silently
	}

	// Step 4: Check if already triggered for this hash
	if state.LastTriggerHash == globalHash {
		return // Already processed this state
	}

	// Step 5: Check min gap between triggers
	if !state.LastTriggerTime.IsZero() && now.Sub(state.LastTriggerTime) < cfg.MinTriggerGap {
		return
	}

	// Step 6: Content stable - now split by namespace and upload
	fmt.Printf("Content stable for %s, processing uploads...\n", stableFor.Round(time.Second))

	byNamespace := groupByNamespace(reports.Items)
	performNamespaceUploads(ctx, byNamespace, resolver, cfg)

	// Mark as triggered
	tracker.MarkTriggered(globalKey, globalHash)
}

func computeGlobalHash(items []unstructured.Unstructured) string {
	// Hash based on resource versions (changes when any report changes)
	var versions []string
	for _, item := range items {
		versions = append(versions, item.GetName()+":"+item.GetResourceVersion())
	}
	sort.Strings(versions)
	data, _ := json.Marshal(versions)
	return fmt.Sprintf("%x", sha256.Sum256(data))[:16]
}

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
	for _, m := range matched {
		report := buildSecurityReport(m.vulns)
		fmt.Printf("  [%s] Uploading %d vulnerabilities → %s\n", m.namespace, len(m.vulns), m.project)
		if err := uploadAndTrigger(cfg, m.project, report); err != nil {
			fmt.Fprintf(os.Stderr, "  [%s] ERROR: %v\n", m.namespace, err)
		}
	}

	// Upload consolidated unmatched
	if len(unmatchedVulns) > 0 {
		report := buildSecurityReport(unmatchedVulns)
		fmt.Printf("  [consolidated] Uploading %d vulnerabilities from %v → %s\n",
			len(unmatchedVulns), unmatchedNames, cfg.GitLabDefaultProject)
		if err := uploadAndTrigger(cfg, cfg.GitLabDefaultProject, report); err != nil {
			fmt.Fprintf(os.Stderr, "  [consolidated] ERROR: %v\n", err)
		}
	}
}

// ============================================================================
// Vulnerability Conversion
// ============================================================================

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
				Category:    "cluster_image_scanning",
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

func buildSecurityReport(vulns []Vulnerability) SecurityReport {
	now := time.Now().UTC().Format("2006-01-02T15:04:05")

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
			Type:    "cluster_image_scanning",
			Status:  "success",
			StartAt: now,
			EndAt:   now,
		},
	}
}

func computeVulnHash(vulns []Vulnerability) string {
	data, _ := json.Marshal(vulns)
	return fmt.Sprintf("%x", sha256.Sum256(data))[:16]
}

// ============================================================================
// GitLab API
// ============================================================================

func uploadAndTrigger(cfg Config, project string, report SecurityReport) error {
	reportJSON, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}

	if err := uploadToPackageRegistry(cfg, project, reportJSON); err != nil {
		return fmt.Errorf("upload: %w", err)
	}

	if err := triggerPipeline(cfg, project); err != nil {
		return fmt.Errorf("trigger: %w", err)
	}

	return nil
}

func uploadToPackageRegistry(cfg Config, project string, report []byte) error {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(report); err != nil {
		return fmt.Errorf("gzip write: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("gzip close: %w", err)
	}

	filename := "trivy-report-latest.json.gz"
	uploadURL := fmt.Sprintf("%s/projects/%s/packages/generic/trivy-reports/1.0.0/%s",
		cfg.GitLabAPIURL, url.PathEscape(project), filename)

	req, err := http.NewRequest("PUT", uploadURL, &buf)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.SetBasicAuth(cfg.DeployTokenUser, cfg.DeployToken)
	req.Header.Set("Content-Type", "application/gzip")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func triggerPipeline(cfg Config, project string) error {
	// Prefer GitLabAccessToken (works across projects) over TriggerToken (project-specific)
	if cfg.GitLabAccessToken != "" {
		return triggerPipelineWithAccessToken(cfg, project)
	}
	return triggerPipelineWithTriggerToken(cfg, project)
}

func triggerPipelineWithAccessToken(cfg Config, project string) error {
	pipelineURL := fmt.Sprintf("%s/projects/%s/pipeline",
		cfg.GitLabAPIURL, url.PathEscape(project))

	body := fmt.Sprintf(`{"ref":"%s"}`, cfg.GitLabRef)
	req, err := http.NewRequest("POST", pipelineURL, strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("PRIVATE-TOKEN", cfg.GitLabAccessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func triggerPipelineWithTriggerToken(cfg Config, project string) error {
	triggerURL := fmt.Sprintf("%s/projects/%s/trigger/pipeline",
		cfg.GitLabAPIURL, url.PathEscape(project))

	data := url.Values{
		"token": {cfg.TriggerToken},
		"ref":   {cfg.GitLabRef},
	}

	resp, err := http.PostForm(triggerURL, data)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// ============================================================================
// Helper Functions
// ============================================================================

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

func getEnvOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getDurationEnv(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

