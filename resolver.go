package main

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

const annotationGitLabProject = "trivy-watcher.io/gitlab-project"

// ProjectResolver resolves namespace to GitLab project using:
// 1. Namespace annotation (explicit)
// 2. Naming convention (group/namespace)
// 3. Default project (fallback)
type ProjectResolver struct {
	groupPath      string
	defaultProject string
	cache          *ProjectCache
	client         dynamic.Interface
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

// getNamespaceAnnotation reads the GitLab project annotation from a namespace.
func (r *ProjectResolver) getNamespaceAnnotation(ctx context.Context, namespace string) string {
	if r.client == nil {
		return ""
	}

	nsGVR := schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "namespaces",
	}

	ns, err := r.client.Resource(nsGVR).Get(ctx, namespace, metav1.GetOptions{})
	if err != nil {
		return ""
	}

	annotations := ns.GetAnnotations()
	if annotations == nil {
		return ""
	}

	return annotations[annotationGitLabProject]
}
