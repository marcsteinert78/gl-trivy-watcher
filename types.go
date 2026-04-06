package main

// SecurityReport represents a GitLab Security Report (v15.0.0 schema).
// See: https://gitlab.com/gitlab-org/security-products/security-report-schemas
type SecurityReport struct {
	Version         string          `json:"version"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Scan            ScanInfo        `json:"scan"`
}

// Vulnerability represents a single vulnerability finding.
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

// Location describes where the vulnerability was found.
type Location struct {
	Image              string             `json:"image"`
	OperatingSystem    string             `json:"operating_system"`
	Dependency         Dependency         `json:"dependency"`
	KubernetesResource KubernetesResource `json:"kubernetes_resource"`
}

// KubernetesResource identifies the K8s workload containing the vulnerability.
type KubernetesResource struct {
	Namespace     string `json:"namespace"`
	Kind          string `json:"kind"`
	Name          string `json:"name"`
	ContainerName string `json:"container_name"`
}

// Dependency describes the vulnerable package.
type Dependency struct {
	Package Package `json:"package"`
	Version string  `json:"version"`
}

// Package contains the package name.
type Package struct {
	Name string `json:"name"`
}

// Ident represents a vulnerability identifier (CVE, CWE, etc).
type Ident struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	URL   string `json:"url,omitempty"`
}

// Link contains a reference URL for the vulnerability.
type Link struct {
	URL string `json:"url"`
}

// ScanInfo contains metadata about the scan.
type ScanInfo struct {
	Analyzer Analyzer `json:"analyzer"`
	Scanner  Scanner  `json:"scanner"`
	Type     string   `json:"type"`
	Status   string   `json:"status"`
	StartTime  string   `json:"start_time"`
	EndTime    string   `json:"end_time"`
}

// Analyzer identifies the tool that performed the analysis.
type Analyzer struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Vendor  Vendor `json:"vendor"`
}

// Scanner identifies the scanning engine.
type Scanner struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Vendor  Vendor `json:"vendor"`
}

// Vendor contains vendor information.
type Vendor struct {
	Name string `json:"name"`
}
