package main

import (
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// ProjectCache caches GitLab project existence checks to reduce API calls.
type ProjectCache struct {
	mu      sync.RWMutex
	exists  map[string]bool
	checked map[string]time.Time
	ttl     time.Duration
	apiURL  string
	token   string
}

// NewProjectCache creates a new cache with the given TTL.
func NewProjectCache(ttl time.Duration, apiURL, token string) *ProjectCache {
	return &ProjectCache{
		exists:  make(map[string]bool),
		checked: make(map[string]time.Time),
		ttl:     ttl,
		apiURL:  apiURL,
		token:   token,
	}
}

// Exists checks if a GitLab project exists (cached).
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

// checkViaAPI queries GitLab to check if project exists.
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

// MarkExists explicitly marks a project as existing (for default project).
func (c *ProjectCache) MarkExists(projectPath string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.exists[projectPath] = true
	c.checked[projectPath] = time.Now()
}
