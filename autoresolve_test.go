package main

import (
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
