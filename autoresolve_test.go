package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestImageRepoWithoutTag(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"paperless-ngx/paperless-ngx:2.20.7", "paperless-ngx/paperless-ngx"},
		{"ghcr.io/cloudnative-pg/postgresql:17.9-system-trixie", "ghcr.io/cloudnative-pg/postgresql"},
		{"alpine:3.23", "alpine"},
		{"localhost:5000/myimg:v1", "localhost:5000/myimg"},
		{"no-tag-image", "no-tag-image"},
		{"", ""},
	}
	for _, tc := range tests {
		got := imageRepoWithoutTag(tc.in)
		if got != tc.want {
			t.Errorf("imageRepoWithoutTag(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestFirstCVE(t *testing.T) {
	ids := []Ident{
		{Type: "cwe", Name: "CWE-20"},
		{Type: "cve", Name: "CVE-2026-1234"},
		{Type: "cve", Name: "CVE-2026-5678"}, // first wins
	}
	if got := firstCVE(ids); got != "CVE-2026-1234" {
		t.Errorf("firstCVE = %q, want CVE-2026-1234", got)
	}

	if got := firstCVE(nil); got != "" {
		t.Errorf("firstCVE(nil) = %q, want empty", got)
	}

	if got := firstCVE([]Ident{{Type: "cwe", Name: "CWE-20"}}); got != "" {
		t.Errorf("firstCVE(no cve) = %q, want empty", got)
	}
}

func TestBuildCurrentKeySet(t *testing.T) {
	vulns := []Vulnerability{
		{
			Identifiers: []Ident{{Type: "cve", Name: "CVE-A"}},
			Location: Location{
				Image: "paperless-ngx/paperless-ngx:2.20.14",
				Dependency: Dependency{
					Package: Package{Name: "libssh-4"},
				},
				KubernetesResource: KubernetesResource{
					Namespace: "paperless", ContainerName: "paperless-ngx",
				},
			},
		},
		{
			// No CVE — should be skipped
			Identifiers: []Ident{{Type: "cwe", Name: "CWE-20"}},
			Location: Location{
				Image: "alpine:3.23",
			},
		},
	}

	set := buildCurrentKeySet(vulns)
	if len(set) != 1 {
		t.Errorf("expected 1 key (no-cve entry skipped), got %d", len(set))
	}
	want := stalenessKey{
		CVE:       "CVE-A",
		Namespace: "paperless",
		Container: "paperless-ngx",
		Package:   "libssh-4",
		ImageRepo: "paperless-ngx/paperless-ngx",
	}
	if _, ok := set[want]; !ok {
		t.Errorf("expected key %+v in set %+v", want, set)
	}
}

func TestStalenessKeyFromGitLab(t *testing.T) {
	t.Run("complete vuln", func(t *testing.T) {
		v := gitlabVulnerability{
			Identifiers: []struct {
				ExternalID string `json:"external_id"`
				Name       string `json:"name"`
				Type       string `json:"type"`
			}{
				{ExternalID: "CVE-1", Name: "CVE-1", Type: "cve"},
			},
		}
		v.Location.Image = "paperless-ngx/paperless-ngx:2.20.7"
		v.Location.KubernetesResource.Namespace = "paperless"
		v.Location.KubernetesResource.ContainerName = "ngx"
		v.Location.Dependency.Package.Name = "libssh-4"

		k, ok := stalenessKeyFromGitLab(v)
		if !ok {
			t.Fatal("expected ok=true")
		}
		want := stalenessKey{
			CVE:       "CVE-1",
			Namespace: "paperless",
			Container: "ngx",
			Package:   "libssh-4",
			ImageRepo: "paperless-ngx/paperless-ngx",
		}
		if k != want {
			t.Errorf("got %+v, want %+v", k, want)
		}
	})

	t.Run("missing package - skip", func(t *testing.T) {
		v := gitlabVulnerability{
			Identifiers: []struct {
				ExternalID string `json:"external_id"`
				Name       string `json:"name"`
				Type       string `json:"type"`
			}{
				{ExternalID: "CVE-1", Type: "cve"},
			},
		}
		v.Location.KubernetesResource.ContainerName = "ngx"
		if _, ok := stalenessKeyFromGitLab(v); ok {
			t.Error("expected ok=false for missing package")
		}
	})

	t.Run("missing cve - skip", func(t *testing.T) {
		v := gitlabVulnerability{}
		v.Location.KubernetesResource.ContainerName = "ngx"
		v.Location.Dependency.Package.Name = "libc"
		if _, ok := stalenessKeyFromGitLab(v); ok {
			t.Error("expected ok=false for missing CVE")
		}
	})
}

// TestStalenessIgnoresImageTag is the central behavioral test: a current scan
// on image tag 2.20.14 should resolve a GitLab finding for the same CVE in
// the same (container, package) on the old 2.20.7 tag.
func TestStalenessIgnoresImageTag(t *testing.T) {
	current := []Vulnerability{
		{
			Identifiers: []Ident{{Type: "cve", Name: "CVE-X"}},
			Location: Location{
				Image: "paperless-ngx/paperless-ngx:2.20.14",
				Dependency: Dependency{
					Package: Package{Name: "libc6"},
				},
				KubernetesResource: KubernetesResource{
					Namespace: "paperless", ContainerName: "ngx",
				},
			},
		},
	}
	currentSet := buildCurrentKeySet(current)

	// GitLab still has a finding for the same CVE on the OLD tag.
	oldFinding := gitlabVulnerability{
		Identifiers: []struct {
			ExternalID string `json:"external_id"`
			Name       string `json:"name"`
			Type       string `json:"type"`
		}{{ExternalID: "CVE-X", Type: "cve"}},
	}
	oldFinding.Location.Image = "paperless-ngx/paperless-ngx:2.20.7"
	oldFinding.Location.KubernetesResource.Namespace = "paperless"
	oldFinding.Location.KubernetesResource.ContainerName = "ngx"
	oldFinding.Location.Dependency.Package.Name = "libc6"

	k, _ := stalenessKeyFromGitLab(oldFinding)
	if _, stillPresent := currentSet[k]; !stillPresent {
		t.Error("expected old-tag finding to be considered still present (same CVE+ns+container+package+image-repo); staleness key should ignore image tag")
	}
}

// makeGitLabVuln is a concise helper for constructing test vulnerabilities
// against the awkward inline struct fields on gitlabVulnerability.
func makeGitLabVuln(id int, cve, image, ns, container, pkg string) gitlabVulnerability {
	v := gitlabVulnerability{
		ID:         id,
		State:      "detected",
		ReportType: "cluster_image_scanning",
		Identifiers: []struct {
			ExternalID string `json:"external_id"`
			Name       string `json:"name"`
			Type       string `json:"type"`
		}{{ExternalID: cve, Type: "cve"}},
	}
	v.Location.Image = image
	v.Location.KubernetesResource.Namespace = ns
	v.Location.KubernetesResource.ContainerName = container
	v.Location.Dependency.Package.Name = pkg
	return v
}

func TestListDetectedVulnerabilitiesPagination(t *testing.T) {
	var calls []string
	// First page: 100 items, second page: 3 items (loop terminates).
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.String())
		page := r.URL.Query().Get("page")
		var items []gitlabVulnerability
		switch page {
		case "1":
			for i := 0; i < 100; i++ {
				items = append(items, makeGitLabVuln(i, fmt.Sprintf("CVE-%d", i), "img:v1", "ns", "c", "pkg"))
			}
		case "2":
			for i := 100; i < 103; i++ {
				items = append(items, makeGitLabVuln(i, fmt.Sprintf("CVE-%d", i), "img:v1", "ns", "c", "pkg"))
			}
		default:
			items = nil
		}
		_ = json.NewEncoder(w).Encode(items)
	}))
	defer server.Close()

	cfg := Config{GitLabAPIURL: server.URL, GitLabAccessToken: "t"}
	out, err := listDetectedVulnerabilities(cfg, "group/proj")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 103 {
		t.Errorf("got %d items, want 103", len(out))
	}
	if len(calls) != 2 {
		t.Errorf("got %d paginated calls, want 2", len(calls))
	}
	for _, c := range calls {
		if !strings.Contains(c, "state=detected") {
			t.Errorf("query missing state=detected filter: %s", c)
		}
	}
}

func TestListDetectedVulnerabilitiesError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
	}))
	defer server.Close()

	cfg := Config{GitLabAPIURL: server.URL, GitLabAccessToken: "t"}
	if _, err := listDetectedVulnerabilities(cfg, "group/proj"); err == nil {
		t.Error("expected error on 403, got nil")
	}
}

func TestResolveVulnerability(t *testing.T) {
	var gotMethod, gotPath, gotToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotToken = r.Header.Get("PRIVATE-TOKEN")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := Config{GitLabAPIURL: server.URL, GitLabAccessToken: "secret-token"}
	if err := resolveVulnerability(cfg, "group/proj", 42); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotMethod != "POST" {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if !strings.HasSuffix(gotPath, "/vulnerabilities/42/resolve") {
		t.Errorf("path = %q, want suffix /vulnerabilities/42/resolve", gotPath)
	}
	if gotToken != "secret-token" {
		t.Errorf("PRIVATE-TOKEN = %q, want secret-token", gotToken)
	}
}

func TestResolveVulnerabilityServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer server.Close()

	cfg := Config{GitLabAPIURL: server.URL, GitLabAccessToken: "t"}
	if err := resolveVulnerability(cfg, "group/proj", 7); err == nil {
		t.Error("expected error on 500, got nil")
	}
}

func TestResolveStaleFindingsDisabled(t *testing.T) {
	// Server should never be hit when feature is disabled.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected call when AutoResolveEnabled=false: %s %s", r.Method, r.URL)
	}))
	defer server.Close()

	cfg := Config{GitLabAPIURL: server.URL, GitLabAccessToken: "t", AutoResolveEnabled: false}
	n, err := resolveStaleFindings(cfg, "p", "ns", map[stalenessKey]struct{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("got %d resolves, want 0", n)
	}
}

func TestResolveStaleFindingsDryRun(t *testing.T) {
	// Two detected findings: one stale, one still in current scan.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/resolve") {
			t.Errorf("dry-run must not POST resolve, got %s", r.URL.Path)
		}
		items := []gitlabVulnerability{
			makeGitLabVuln(1, "CVE-STALE", "img:oldtag", "paperless", "ngx", "libc6"),
			makeGitLabVuln(2, "CVE-KEEP", "img:oldtag", "paperless", "ngx", "libssh-4"),
		}
		_ = json.NewEncoder(w).Encode(items)
	}))
	defer server.Close()

	cfg := Config{
		GitLabAPIURL:         server.URL,
		GitLabAccessToken:    "t",
		AutoResolveEnabled:   true,
		AutoResolveDryRun:    true,
		AutoResolveMaxPerRun: 100,
	}
	current := map[stalenessKey]struct{}{
		{CVE: "CVE-KEEP", Namespace: "paperless", Container: "ngx", Package: "libssh-4", ImageRepo: "img"}: {},
	}
	n, err := resolveStaleFindings(cfg, "group/proj", "paperless", current)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 1 {
		t.Errorf("got %d stale, want 1 (CVE-STALE)", n)
	}
}

func TestResolveStaleFindingsLive(t *testing.T) {
	var mu sync.Mutex
	var resolvedIDs []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/resolve") {
			mu.Lock()
			// path ends /vulnerabilities/<id>/resolve
			parts := strings.Split(r.URL.Path, "/")
			if len(parts) >= 2 {
				resolvedIDs = append(resolvedIDs, parts[len(parts)-2])
			}
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		}
		items := []gitlabVulnerability{
			makeGitLabVuln(11, "CVE-STALE", "img:oldtag", "paperless", "ngx", "libc6"),
			makeGitLabVuln(22, "CVE-KEEP", "img:oldtag", "paperless", "ngx", "libssh-4"),
		}
		_ = json.NewEncoder(w).Encode(items)
	}))
	defer server.Close()

	cfg := Config{
		GitLabAPIURL:         server.URL,
		GitLabAccessToken:    "t",
		AutoResolveEnabled:   true,
		AutoResolveDryRun:    false,
		AutoResolveMaxPerRun: 100,
	}
	current := map[stalenessKey]struct{}{
		{CVE: "CVE-KEEP", Namespace: "paperless", Container: "ngx", Package: "libssh-4", ImageRepo: "img"}: {},
	}
	n, err := resolveStaleFindings(cfg, "group/proj", "paperless", current)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 1 {
		t.Errorf("got %d resolves, want 1", n)
	}
	if len(resolvedIDs) != 1 || resolvedIDs[0] != "11" {
		t.Errorf("resolved IDs = %v, want [11]", resolvedIDs)
	}
}

func TestResolveStaleFindingsCrossNamespaceIgnored(t *testing.T) {
	// GitLab returns a finding for a DIFFERENT namespace. It must be ignored
	// entirely — we're scanning "paperless" only.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/resolve") {
			t.Error("must not resolve cross-namespace finding")
		}
		items := []gitlabVulnerability{
			makeGitLabVuln(99, "CVE-X", "img:oldtag", "other-namespace", "ngx", "libc6"),
		}
		_ = json.NewEncoder(w).Encode(items)
	}))
	defer server.Close()

	cfg := Config{
		GitLabAPIURL:         server.URL,
		GitLabAccessToken:    "t",
		AutoResolveEnabled:   true,
		AutoResolveDryRun:    false,
		AutoResolveMaxPerRun: 100,
	}
	n, err := resolveStaleFindings(cfg, "p", "paperless", map[stalenessKey]struct{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("got %d resolves, want 0 (cross-namespace must be skipped)", n)
	}
}

func TestResolveStaleFindingsCapAborts(t *testing.T) {
	// Return way more stale findings than the cap allows.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/resolve") {
			t.Error("cap should abort BEFORE any resolve call")
		}
		var items []gitlabVulnerability
		for i := 0; i < 50; i++ {
			items = append(items, makeGitLabVuln(i, fmt.Sprintf("CVE-%d", i), "img:v1", "paperless", "c", "pkg"))
		}
		_ = json.NewEncoder(w).Encode(items)
	}))
	defer server.Close()

	cfg := Config{
		GitLabAPIURL:         server.URL,
		GitLabAccessToken:    "t",
		AutoResolveEnabled:   true,
		AutoResolveDryRun:    false,
		AutoResolveMaxPerRun: 10, // 50 stale > cap of 10
	}
	n, err := resolveStaleFindings(cfg, "p", "paperless", map[stalenessKey]struct{}{})
	if err == nil {
		t.Error("expected error when stale exceeds cap")
	}
	if n != 0 {
		t.Errorf("resolved %d with cap exceeded, want 0", n)
	}
}

func TestResolveStaleFindingsIgnoresNonCIS(t *testing.T) {
	// Non-cluster_image_scanning findings should be ignored.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/resolve") {
			t.Error("must not resolve non-cluster_image_scanning findings")
		}
		v := makeGitLabVuln(1, "CVE-X", "img:v1", "paperless", "c", "pkg")
		v.ReportType = "container_scanning" // not cluster_image_scanning
		_ = json.NewEncoder(w).Encode([]gitlabVulnerability{v})
	}))
	defer server.Close()

	cfg := Config{
		GitLabAPIURL:         server.URL,
		GitLabAccessToken:    "t",
		AutoResolveEnabled:   true,
		AutoResolveDryRun:    false,
		AutoResolveMaxPerRun: 100,
	}
	n, err := resolveStaleFindings(cfg, "p", "paperless", map[stalenessKey]struct{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("got %d resolves, want 0 (wrong report_type)", n)
	}
}

// TestStalenessNotMatchedWhenContainerDiffers ensures we don't accidentally
// resolve a finding that applies to a different container in the same namespace.
func TestStalenessNotMatchedWhenContainerDiffers(t *testing.T) {
	current := []Vulnerability{
		{
			Identifiers: []Ident{{Type: "cve", Name: "CVE-X"}},
			Location: Location{
				Dependency: Dependency{Package: Package{Name: "libc6"}},
				KubernetesResource: KubernetesResource{
					Namespace: "paperless", ContainerName: "ngx",
				},
			},
		},
	}
	currentSet := buildCurrentKeySet(current)

	// Same CVE but in a different container (gotenberg).
	other := gitlabVulnerability{
		Identifiers: []struct {
			ExternalID string `json:"external_id"`
			Name       string `json:"name"`
			Type       string `json:"type"`
		}{{ExternalID: "CVE-X", Type: "cve"}},
	}
	other.Location.KubernetesResource.Namespace = "paperless"
	other.Location.KubernetesResource.ContainerName = "gotenberg"
	other.Location.Dependency.Package.Name = "libc6"

	k, _ := stalenessKeyFromGitLab(other)
	if _, present := currentSet[k]; present {
		t.Error("different container must not match")
	}
}
