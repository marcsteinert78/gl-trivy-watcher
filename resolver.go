package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

const annotationGitLabProject = "trivy-watcher.io/gitlab-project"

// annotationCacheTTL controls how long namespace annotation lookups are
// memoized. The same value as the project-existence cache keeps both layers
// in sync without exposing yet another knob.
const annotationCacheTTL = 5 * time.Minute

// annotationEntry is a single cached annotation lookup. value=="" means the
// namespace exists but has no project annotation — we still cache that to
// avoid re-querying the apiserver every poll cycle.
type annotationEntry struct {
	value     string
	cachedAt  time.Time
}

// ProjectResolver resolves namespace to GitLab project using:
// 1. Namespace annotation (explicit)
// 2. Naming convention (group/namespace)
// 3. Default project (fallback)
type ProjectResolver struct {
	groupPath      string
	defaultProject string
	cache          *ProjectCache
	client         dynamic.Interface

	annMu          sync.RWMutex
	annotations    map[string]annotationEntry
	annotationTTL  time.Duration
}

// NewProjectResolver creates a new resolver.
func NewProjectResolver(groupPath, defaultProject string, cache *ProjectCache, client dynamic.Interface) *ProjectResolver {
	// Mark default project as existing (skip API check)
	cache.MarkExists(defaultProject)

	return &ProjectResolver{
		groupPath:      groupPath,
		defaultProject: defaultProject,
		cache:          cache,
		client:         client,
		annotations:    make(map[string]annotationEntry),
		annotationTTL:  annotationCacheTTL,
	}
}

// Resolve finds the GitLab project for a namespace.
// Returns (project, isDefault) where isDefault=true means fallback to default project.
func (r *ProjectResolver) Resolve(ctx context.Context, namespace string) (string, bool) {
	// 1. Check namespace annotation
	if annotated := r.getNamespaceAnnotation(ctx, namespace); annotated != "" {
		return annotated, false // Found via annotation, NOT default
	}

	// 2. Try naming convention: {group}/{namespace}
	if r.groupPath != "" {
		conventionPath := fmt.Sprintf("%s/%s", r.groupPath, namespace)
		if r.cache.Exists(conventionPath) {
			return conventionPath, false // Found via convention, NOT default
		}
	}

	// 3. Fall back to default
	return r.defaultProject, true // IS default
}

// getNamespaceAnnotation reads the GitLab project annotation from a namespace,
// memoizing the result for annotationTTL. Lookups (including the empty
// "namespace exists but has no annotation" result) are cached to avoid hitting
// the apiserver on every poll cycle for every namespace.
func (r *ProjectResolver) getNamespaceAnnotation(ctx context.Context, namespace string) string {
	if r.client == nil {
		return ""
	}

	r.annMu.RLock()
	if entry, ok := r.annotations[namespace]; ok && time.Since(entry.cachedAt) < r.annotationTTL {
		r.annMu.RUnlock()
		return entry.value
	}
	r.annMu.RUnlock()

	nsGVR := schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "namespaces",
	}

	ns, err := r.client.Resource(nsGVR).Get(ctx, namespace, metav1.GetOptions{})
	if err != nil {
		// Don't cache errors — transient apiserver failures should retry
		// next cycle, not get pinned for the full TTL.
		return ""
	}

	value := ""
	if annotations := ns.GetAnnotations(); annotations != nil {
		value = annotations[annotationGitLabProject]
	}

	r.annMu.Lock()
	r.annotations[namespace] = annotationEntry{value: value, cachedAt: time.Now()}
	r.annMu.Unlock()

	return value
}
