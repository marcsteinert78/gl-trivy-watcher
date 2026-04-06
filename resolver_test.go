package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"
)

// newFakeDynamicWithNamespace builds a fake dynamic client preloaded with a
// single Namespace carrying the given annotation value (empty value = no
// annotation). It also returns the action accumulator so tests can count
// apiserver calls.
func newFakeDynamicWithNamespace(name, annotationValue string) (*dynamicfake.FakeDynamicClient, *clienttesting.Fake) {
	scheme := runtime.NewScheme()
	nsGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"}
	scheme.AddKnownTypeWithName(nsGVR.GroupVersion().WithKind("NamespaceList"), &unstructured.UnstructuredList{})

	ns := &unstructured.Unstructured{}
	ns.SetGroupVersionKind(schema.GroupVersionKind{Version: "v1", Kind: "Namespace"})
	ns.SetName(name)
	if annotationValue != "" {
		ns.SetAnnotations(map[string]string{annotationGitLabProject: annotationValue})
	}

	client := dynamicfake.NewSimpleDynamicClient(scheme, ns)
	return client, &client.Fake
}

func countNamespaceGets(actions []clienttesting.Action) int {
	n := 0
	for _, a := range actions {
		if a.GetVerb() == "get" && a.GetResource().Resource == "namespaces" {
			n++
		}
	}
	return n
}

// Resolve returns (project, isDefault) where:
// - isDefault=false: project was found (via annotation or convention)
// - isDefault=true: using default project (fallback)

func TestProjectResolverFindsViaConvention(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "mediastack") {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cache := NewProjectCache(5*time.Minute, server.URL, "token")
	resolver := NewProjectResolver("msteinert1/homeserver", "default/project", cache, nil, 5*time.Minute)

	ctx := context.Background()
	project, isDefault := resolver.Resolve(ctx, "mediastack")

	if project != "msteinert1/homeserver/mediastack" {
		t.Errorf("project = %q, want 'msteinert1/homeserver/mediastack'", project)
	}
	if isDefault {
		t.Error("isDefault should be false when project found via convention")
	}
}

func TestProjectResolverFallbackToDefault(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cache := NewProjectCache(5*time.Minute, server.URL, "token")
	resolver := NewProjectResolver("msteinert1/homeserver", "default/fallback", cache, nil, 5*time.Minute)

	ctx := context.Background()
	project, isDefault := resolver.Resolve(ctx, "unknown-namespace")

	if project != "default/fallback" {
		t.Errorf("project = %q, want 'default/fallback'", project)
	}
	if !isDefault {
		t.Error("isDefault should be true when falling back to default")
	}
}

func TestProjectResolverCachesAPIResult(t *testing.T) {
	apiCallCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiCallCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cache := NewProjectCache(5*time.Minute, server.URL, "token")
	resolver := NewProjectResolver("group", "default/project", cache, nil, 5*time.Minute)

	ctx := context.Background()

	resolver.Resolve(ctx, "test-ns")
	firstCount := apiCallCount

	resolver.Resolve(ctx, "test-ns")

	if apiCallCount != firstCount {
		t.Errorf("Second call should use cache, API called %d times", apiCallCount)
	}
}

func TestProjectResolverEmptyGroupPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("API should not be called when groupPath is empty")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cache := NewProjectCache(time.Minute, server.URL, "token")
	resolver := NewProjectResolver("", "default/project", cache, nil, 5*time.Minute)

	ctx := context.Background()
	project, isDefault := resolver.Resolve(ctx, "test-ns")

	if project != "default/project" {
		t.Errorf("project = %q, want 'default/project'", project)
	}
	if !isDefault {
		t.Error("isDefault should be true when groupPath is empty (skip convention)")
	}
}

func TestProjectResolverDefaultProjectMarkedInCache(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("API call: %s", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cache := NewProjectCache(time.Minute, server.URL, "token")
	_ = NewProjectResolver("group", "group/default", cache, nil, 5*time.Minute)

	if !cache.Exists(context.Background(), "group/default") {
		t.Error("Default project should be pre-marked as existing")
	}
}

func TestProjectResolverNilClientSkipsAnnotation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cache := NewProjectCache(time.Minute, server.URL, "token")
	resolver := NewProjectResolver("group", "group/default", cache, nil, 5*time.Minute)

	ctx := context.Background()
	project, isDefault := resolver.Resolve(ctx, "test")

	if project != "group/test" {
		t.Errorf("project = %q, want 'group/test'", project)
	}
	if isDefault {
		t.Error("isDefault should be false when found via convention")
	}
}

func TestNewProjectResolver(t *testing.T) {
	cache := NewProjectCache(time.Minute, "https://gitlab.com", "token")
	resolver := NewProjectResolver("group/subgroup", "group/default", cache, nil, 5*time.Minute)

	if resolver == nil {
		t.Fatal("NewProjectResolver returned nil")
	}
	if resolver.groupPath != "group/subgroup" {
		t.Errorf("groupPath = %q, want 'group/subgroup'", resolver.groupPath)
	}
	if resolver.defaultProject != "group/default" {
		t.Errorf("defaultProject = %q, want 'group/default'", resolver.defaultProject)
	}
}

func TestProjectCacheCheckViaAPI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PRIVATE-TOKEN") != "test-token" {
			t.Error("Missing PRIVATE-TOKEN header")
		}
		if strings.Contains(r.URL.Path, "existing") {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cache := NewProjectCache(time.Minute, server.URL, "test-token")

	if !cache.Exists(context.Background(), "existing") {
		t.Error("Existing project should return true")
	}
	if cache.Exists(context.Background(), "nonexistent") {
		t.Error("Nonexistent project should return false")
	}
}

func TestProjectCacheExpiration(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cache := NewProjectCache(10*time.Millisecond, server.URL, "token")

	cache.Exists(context.Background(), "project")
	if callCount != 1 {
		t.Errorf("First call: expected 1 API call, got %d", callCount)
	}

	cache.Exists(context.Background(), "project")
	if callCount != 1 {
		t.Errorf("Second call: expected cache hit, got %d API calls", callCount)
	}

	time.Sleep(15 * time.Millisecond)

	cache.Exists(context.Background(), "project")
	if callCount != 2 {
		t.Errorf("After TTL: expected 2 API calls, got %d", callCount)
	}
}

func TestProjectCacheMarkExists(t *testing.T) {
	cache := NewProjectCache(time.Minute, "http://unused", "token")
	cache.MarkExists("my/project")

	if !cache.Exists(context.Background(), "my/project") {
		t.Error("MarkExists should make Exists return true")
	}
}

func TestProjectResolverAnnotationCacheHit(t *testing.T) {
	client, fakeAccumulator := newFakeDynamicWithNamespace("annotated-ns", "explicit/project")

	cache := NewProjectCache(time.Minute, "http://unused", "token")
	resolver := NewProjectResolver("group", "default/project", cache, client, 5*time.Minute)

	ctx := context.Background()

	for i := 0; i < 5; i++ {
		project, isDefault := resolver.Resolve(ctx, "annotated-ns")
		if project != "explicit/project" {
			t.Fatalf("call %d: project = %q, want 'explicit/project'", i, project)
		}
		if isDefault {
			t.Fatalf("call %d: isDefault should be false for annotated namespace", i)
		}
	}

	if got := countNamespaceGets(fakeAccumulator.Actions()); got != 1 {
		t.Errorf("expected 1 namespace GET (cached), got %d", got)
	}
}

func TestProjectResolverAnnotationCacheNegativeHit(t *testing.T) {
	// Namespace exists but has no annotation — cache the empty result so
	// we don't re-query the apiserver every poll.
	client, fakeAccumulator := newFakeDynamicWithNamespace("plain-ns", "")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cache := NewProjectCache(time.Minute, server.URL, "token")
	resolver := NewProjectResolver("group", "default/project", cache, client, 5*time.Minute)

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		project, isDefault := resolver.Resolve(ctx, "plain-ns")
		if project != "default/project" || !isDefault {
			t.Fatalf("call %d: got (%q, %v), want fallback", i, project, isDefault)
		}
	}

	if got := countNamespaceGets(fakeAccumulator.Actions()); got != 1 {
		t.Errorf("expected 1 namespace GET (negative result cached), got %d", got)
	}
}

func TestProjectResolverAnnotationCacheExpiry(t *testing.T) {
	client, fakeAccumulator := newFakeDynamicWithNamespace("annotated-ns", "explicit/project")

	cache := NewProjectCache(time.Minute, "http://unused", "token")
	resolver := NewProjectResolver("group", "default/project", cache, client, 5*time.Minute)
	resolver.annotationTTL = 10 * time.Millisecond

	ctx := context.Background()
	resolver.Resolve(ctx, "annotated-ns")
	resolver.Resolve(ctx, "annotated-ns")
	if got := countNamespaceGets(fakeAccumulator.Actions()); got != 1 {
		t.Errorf("before TTL: expected 1 GET, got %d", got)
	}

	time.Sleep(20 * time.Millisecond)

	resolver.Resolve(ctx, "annotated-ns")
	if got := countNamespaceGets(fakeAccumulator.Actions()); got != 2 {
		t.Errorf("after TTL: expected 2 GETs, got %d", got)
	}
}

func TestProjectCacheConcurrent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cache := NewProjectCache(time.Minute, server.URL, "token")

	done := make(chan bool, 100)
	for i := 0; i < 100; i++ {
		go func() {
			cache.Exists(context.Background(), "project")
			cache.MarkExists("another")
			done <- true
		}()
	}

	for i := 0; i < 100; i++ {
		<-done
	}
}
