package main

import (
	"net/http"
	"time"
)

// httpClient is shared by all outbound HTTP calls (GitLab uploads, pipeline
// triggers, project-existence checks). The default http.Client has no timeout,
// which would block the watcher loop indefinitely on a hung connection.
var httpClient = &http.Client{Timeout: 30 * time.Second}
