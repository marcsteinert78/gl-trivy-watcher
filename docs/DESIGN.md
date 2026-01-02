# Trivy-Watcher Architecture

## Overview

Trivy-Watcher monitors Kubernetes VulnerabilityReports created by Trivy Operator and uploads them to GitLab's Security Dashboard. This enables vulnerability tracking in GitLab's Operational Vulnerabilities view.

## Per-Namespace Upload Feature

### Problem Statement

In multi-team environments, different namespaces are owned by different teams. A single consolidated vulnerability report makes it difficult for teams to:
- See only their relevant vulnerabilities
- Track remediation progress for their services
- Integrate security scanning into their team's CI/CD pipeline

### Solution

Trivy-Watcher supports per-namespace vulnerability uploads. Each namespace can have its own GitLab project, receiving only the vulnerabilities from that namespace.

```
┌─────────────────────────────────────────────────────────────────┐
│                      Trivy-Watcher                              │
│                                                                 │
│  1. Fetch all VulnerabilityReports from cluster                 │
│  2. Group reports by namespace                                  │
│  3. For each namespace:                                         │
│     a. Resolve GitLab project (annotation → convention → skip)  │
│     b. If project exists: upload namespace-specific report      │
│     c. If not: collect for consolidated upload                  │
│  4. Upload all unmatched namespaces to default project          │
└─────────────────────────────────────────────────────────────────┘
```

### Project Resolution Strategy

The watcher resolves the GitLab project for each namespace using a three-tier strategy:

```
┌─────────────────┐
│ 1. Annotation   │  Namespace has trivy-watcher.io/gitlab-project annotation?
└────────┬────────┘  → Use specified project path
         │ No
         ▼
┌─────────────────┐
│ 2. Convention   │  Project {GROUP_PATH}/{NAMESPACE} exists?
└────────┬────────┘  → Use convention-based project
         │ No
         ▼
┌─────────────────┐
│ 3. Default      │  Collect vulnerabilities for consolidated upload
└─────────────────┘  → Upload to GITLAB_DEFAULT_PROJECT
```

#### 1. Explicit Annotation (Highest Priority)

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: legacy-app
  annotations:
    trivy-watcher.io/gitlab-project: "other-group/legacy-project"
```

Use case: Namespace name doesn't match project name, or project is in a different group.

#### 2. Naming Convention

If no annotation is present, the watcher constructs a project path:

```
{GITLAB_GROUP_PATH}/{NAMESPACE_NAME}
```

Example:
- Group path: `msteinert1/homeserver`
- Namespace: `mediastack`
- Resolved project: `msteinert1/homeserver/mediastack`

The watcher checks if this project exists via GitLab API (cached).

#### 3. Default Project (Fallback)

Namespaces without a matching project are consolidated and uploaded to `GITLAB_DEFAULT_PROJECT`. This ensures no vulnerabilities are lost.

### Consolidated Upload for Unmatched Namespaces

**Critical Design Decision**: Unmatched namespaces are collected and uploaded as a single consolidated report to the default project. This prevents:

- Overwriting the default project's report with partial data
- Losing vulnerabilities from namespaces without dedicated projects

```
Matched namespaces:     mediastack → mediastack project (isolated)
                        gitlab     → gitlab project (isolated)

Unmatched namespaces:   kube-system    ─┐
                        cert-manager   ─┼─► Consolidated → default project
                        monitoring     ─┘
```

### Configuration

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `GITLAB_GROUP_PATH` | GitLab group for convention-based resolution | - |
| `GITLAB_DEFAULT_PROJECT` | Fallback project for unmatched namespaces | - |
| `GITLAB_API_URL` | GitLab API base URL | `https://gitlab.com/api/v4` |
| `DEPLOY_TOKEN` | Token with `write_package_registry` scope | - |
| `DEPLOY_TOKEN_USER` | Deploy token username | - |
| `GITLAB_ACCESS_TOKEN` | Access Token with `api` scope (multi-project) | - |
| `TRIGGER_TOKEN` | Pipeline trigger token (single-project, legacy) | - |

**Note**: Either `GITLAB_ACCESS_TOKEN` or `TRIGGER_TOKEN` is required. For multi-project setups, use `GITLAB_ACCESS_TOKEN`.

### Authentication Strategy

#### Single-Project Mode (Legacy)
- `TRIGGER_TOKEN`: Project-specific pipeline trigger token
- Only works for the configured project
- Minimal permissions (can only trigger pipelines)

#### Multi-Project Mode (Recommended for per-namespace)
- `GITLAB_ACCESS_TOKEN`: Group Access Token or PAT with `api` scope
- Works across all projects in the group
- Required for per-namespace uploads to different projects

**Security Trade-off**:

| Mode | Token Scope | Risk | Use When |
|------|-------------|------|----------|
| Single-Project | `trigger` only | Minimal | All vulns → one project |
| Multi-Project | `api` (broad) | Higher | Per-namespace projects |

**Mitigation for Multi-Project Mode**:
1. Use **Group Access Token** (not personal) - can be revoked without affecting user
2. Set **expiration date** on token (max 1 year recommended)
3. Limit token to **specific group** (not instance-wide)
4. Store in **Kubernetes Secret** with restricted RBAC
5. Consider **IP allowlist** if GitLab supports it

### Project Existence Caching

To avoid repeated API calls, project existence is cached:

```go
type ProjectCache struct {
    mu      sync.RWMutex
    exists  map[string]bool
    checked map[string]time.Time
    ttl     time.Duration
}
```

- Cache TTL: 5 minutes (configurable)
- Thread-safe for concurrent access
- Reduces GitLab API load significantly

### Per-Namespace Hash Tracking

Each namespace maintains its own content hash to avoid unnecessary uploads:

```go
type NamespaceState struct {
    Hash        string
    StableSince time.Time
    LastTrigger time.Time
}
```

A namespace's pipeline is only triggered when:
1. Content hash changed AND stabilized (configurable delay)
2. Minimum time since last trigger has passed
3. Hash differs from last triggered hash

### Log Output

The watcher provides clear, actionable log messages:

```
=== Processing 5 namespaces ===
  ✓ mediastack: 42 vulnerabilities → msteinert1/homeserver/mediastack
  ✓ gitlab: 18 vulnerabilities → msteinert1/homeserver/gitlab
  ○ kube-system: 12 vulnerabilities → (no project, collecting)
  ○ cert-manager: 3 vulnerabilities → (no project, collecting)
  ○ monitoring: 7 vulnerabilities → (no project, collecting)

Consolidated upload: 22 vulnerabilities from [kube-system, cert-manager, monitoring]
  → msteinert1/homeserver/kubernetes (default)
```

## GitLab Integration

### Report Upload Flow

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐     ┌──────────────────┐
│  Trivy-Watcher  │────▶│ Package Registry │────▶│   CI Pipeline   │────▶│ Security Dashboard│
│  (in-cluster)   │     │ (artifact store) │     │ (trivy:* job)   │     │ (Operational tab) │
└─────────────────┘     └──────────────────┘     └─────────────────┘     └──────────────────┘
        │                       │                        │                        │
        │  1. Upload gzipped    │  2. Trigger pipeline   │  3. Download &         │
        │     JSON report       │     via trigger token  │     publish artifact   │
        └───────────────────────┴────────────────────────┴────────────────────────┘
```

### Step 1: Report Upload to Package Registry

The watcher uploads the security report as a gzipped JSON file to GitLab's Generic Package Registry:

```
PUT /projects/{project}/packages/generic/trivy-reports/1.0.0/trivy-report-latest.json.gz
```

- **Package Name**: `trivy-reports`
- **Version**: `1.0.0` (fixed, always overwrites)
- **Filename**: `trivy-report-latest.json.gz`
- **Authentication**: Deploy Token with `write_package_registry` scope

### Step 2: Pipeline Trigger

After upload, the watcher triggers a pipeline in the target project:

```
POST /projects/{project}/trigger/pipeline
  token={TRIGGER_TOKEN}
  ref=main
```

The triggered pipeline runs the `trivy:cluster-scan` job.

### Step 3: CI Job Configuration

Each project needs a `.gitlab-ci.yml` with the trivy job:

```yaml
stages:
  - trivy

trivy:cluster-scan:
  stage: trivy
  image: alpine:latest
  variables:
    TRIVY_REPORT_URL: "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/trivy-reports/1.0.0/trivy-report-latest.json.gz"
  script:
    - apk add --no-cache curl gzip jq
    - 'curl -f -H "JOB-TOKEN: $CI_JOB_TOKEN" "$TRIVY_REPORT_URL" | gunzip > gl-container-scanning-report.json'
    - |
      echo "=== Security Scan Summary ==="
      jq -r '"Total: " + (.vulnerabilities | length | tostring)' gl-container-scanning-report.json
  artifacts:
    reports:
      cluster_image_scanning: gl-container-scanning-report.json
    paths:
      - gl-container-scanning-report.json
    expire_in: 30 days
  rules:
    - if: $CI_PIPELINE_SOURCE == "trigger"
```

### Key Configuration Points

| Setting | Value | Why |
|---------|-------|-----|
| `artifacts.reports.cluster_image_scanning` | `gl-container-scanning-report.json` | **Critical**: This artifact type routes to Operational tab |
| `$CI_JOB_TOKEN` | Auto-provided | Allows downloading from same project's Package Registry |
| `rules: trigger` | Only on trigger | Prevents running on normal pushes |

### Why Operational (not Development)?

GitLab distinguishes vulnerability sources:

| Artifact Type | Dashboard Location | Use Case |
|---------------|-------------------|----------|
| `container_scanning` | Development | Image scans during CI build |
| `cluster_image_scanning` | **Operational** | Runtime cluster scans |

The report JSON must also include:
- `"category": "cluster_image_scanning"` per vulnerability
- `"type": "cluster_image_scanning"` in scan info
- `kubernetes_resource` in location (namespace, pod, container)

### Report Schema (GitLab Security Report v15.0.0)

```json
{
  "version": "15.0.0",
  "vulnerabilities": [
    {
      "id": "CVE-2021-12345-nginx-libssl",
      "category": "cluster_image_scanning",
      "name": "CVE-2021-12345",
      "message": "CVE-2021-12345 in libssl [mediastack/sonarr-abc123/sonarr]",
      "severity": "High",
      "location": {
        "image": "nginx:1.21",
        "kubernetes_resource": {
          "namespace": "mediastack",
          "kind": "Pod",
          "name": "sonarr-abc123",
          "container_name": "sonarr"
        }
      }
    }
  ],
  "scan": {
    "type": "cluster_image_scanning",
    "status": "success"
  }
}
```

### Security Considerations

#### Token Types and Scopes

| Token | Scope | Purpose | Risk Level |
|-------|-------|---------|------------|
| Deploy Token | `write_package_registry` | Upload reports to Package Registry | Low |
| Trigger Token | Pipeline trigger only | Trigger CI pipelines | Low |
| Group Access Token | `api` | Multi-project pipeline triggers | Medium |
| Personal Access Token | `api` | Multi-project (not recommended) | High |

#### Recommended Setup

**For Single-Project (all vulns → one project)**:
```
DEPLOY_TOKEN=gldt-xxx          # Group deploy token
DEPLOY_TOKEN_USER=gitlab+deploy-token-N
TRIGGER_TOKEN=glptt-xxx        # Project trigger token
```

**For Multi-Project (per-namespace)**:
```
DEPLOY_TOKEN=gldt-xxx          # Group deploy token (same for all)
DEPLOY_TOKEN_USER=gitlab+deploy-token-N
GITLAB_ACCESS_TOKEN=glpat-xxx  # Group Access Token with api scope
```

#### Security Best Practices

1. **Prefer Group Access Tokens over PATs**
   - Can be revoked without affecting user accounts
   - Scoped to specific group only
   - Clear ownership and audit trail

2. **Token Expiration**
   - Set maximum 1 year expiration
   - Rotate tokens regularly
   - Monitor token usage in GitLab audit logs

3. **Kubernetes Secret Storage**
   - Store tokens in Kubernetes Secrets (not ConfigMaps)
   - Use `stringData` for clarity, GitLab encodes automatically
   - Restrict access via RBAC to trivy-watcher ServiceAccount only

4. **Network Isolation**
   - Trivy-watcher only needs egress to GitLab API
   - Consider NetworkPolicy to restrict other egress
   - If self-hosted GitLab: internal network only

5. **Namespace Isolation**
   - Each namespace's vulns only visible in their project
   - Teams cannot see other teams' vulnerabilities
   - Consolidated report (default project) may contain cross-team data

### Future Enhancements

1. **Namespace Labels**: Filter which namespaces to process via label selector
2. **Severity Thresholds**: Only upload vulnerabilities above certain severity
3. **Webhook Mode**: React to VulnerabilityReport changes instead of polling
4. **Metrics Endpoint**: Expose Prometheus metrics for monitoring
