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

After upload, the watcher triggers a pipeline in the target project via the GitLab API:

```
POST /projects/{project}/pipeline
  Header: PRIVATE-TOKEN: {GITLAB_ACCESS_TOKEN}
  Body: {"ref":"main","variables":[{"key":"TRIVY_TRIGGERED","value":"true"}]}
```

**Key Design Decision**: We use the `/pipeline` API with a custom variable `TRIVY_TRIGGERED=true` instead of the `/trigger/pipeline` endpoint. This is because:

1. `/trigger/pipeline` requires project-specific trigger tokens (won't work for multi-project)
2. `/pipeline` API sets `CI_PIPELINE_SOURCE=api` (not `trigger`)
3. Using a custom variable is more explicit and self-documenting

The triggered pipeline runs the `trivy:cluster-scan` job only when `TRIVY_TRIGGERED=true`.

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
    # Only run when triggered by trivy-watcher (passes TRIVY_TRIGGERED=true)
    - if: $TRIVY_TRIGGERED == "true"
```

**Important**: The workflow rules must also allow pipelines with `TRIVY_TRIGGERED`:

```yaml
workflow:
  rules:
    # ... other rules ...
    - if: $TRIVY_TRIGGERED == "true"
```

### Key Configuration Points

| Setting | Value | Why |
|---------|-------|-----|
| `artifacts.reports.cluster_image_scanning` | `gl-container-scanning-report.json` | **Critical**: This artifact type routes to Operational tab |
| `$CI_JOB_TOKEN` | Auto-provided | Allows downloading from same project's Package Registry |
| `$TRIVY_TRIGGERED == "true"` | Only on trivy-watcher triggers | More explicit than checking `CI_PIPELINE_SOURCE` |

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

5. **Namespace Isolation (Limited)**
   - Each namespace's vulns uploaded to their project
   - **Note**: Group-level dashboards aggregate vulnerabilities from ALL projects
   - For true isolation, use separate GitLab groups per team
   - Consolidated report (default project) contains all unmatched namespaces

## Auto-Resolve Stale Vulnerabilities

### Problem Statement

GitLab's cluster_image_scanning dashboard treats each `(CVE, image-tag, location)` tuple as a distinct finding and never removes entries on its own. Upgrading an image from `app:2.20.7` to `app:2.20.14` does not close the 2.20.7 findings — they remain `state=detected` forever, while the new tag adds its own. After a few months of routine patching the Ultimate dashboard's Critical count is several multiples of the cluster's actual state, which defeats the point of having a dashboard.

There is no server-side setting to fix this. The only supported approach is to explicitly resolve each stale finding via the API.

### Design

After a successful namespace upload, the watcher:

1. Fetches all `state=detected` vulnerabilities for the target project from `GET /projects/:id/vulnerabilities?state=detected` (paginated).
2. Filters to `report_type=cluster_image_scanning` in the namespace that was just uploaded. Findings from other namespaces or other scan types are ignored, even when they share the same project.
3. Builds a comparison key for every remaining finding and checks whether that key is present in the current cluster scan.
4. For findings not present in the current scan, calls `POST /vulnerabilities/:id/resolve` — a **top-level** endpoint, not nested under `/projects/:id`. Vulnerability IDs are globally unique in GitLab, so the project-scoped path returns 404.

```
┌──────────────────────────────────────────────────────────────────┐
│  After namespace upload for "paperless":                         │
│                                                                  │
│  1. List detected vulns in project                               │
│     └─▶ 537 findings (accumulated from months of image bumps)    │
│                                                                  │
│  2. Filter: report_type=cluster_image_scanning                   │
│             namespace=paperless (skip other namespaces)          │
│     └─▶ 270 candidates                                           │
│                                                                  │
│  3. For each: build key, check against current scan set          │
│     └─▶ 270 not found in current scan → stale                    │
│                                                                  │
│  4. Safety cap? (270 < 500)                                      │
│     └─▶ proceed                                                  │
│                                                                  │
│  5. For each stale: POST /vulnerabilities/:id/resolve            │
│     └─▶ resolved=270, failed=0                                   │
└──────────────────────────────────────────────────────────────────┘
```

### Matching Key

```go
type stalenessKey struct {
    CVE       string
    Namespace string
    Container string
    Package   string
    ImageRepo string  // image reference WITHOUT :tag
}
```

**Why the tag is excluded**: image bumps are the primary driver of staleness. If `app:2.20.7` had a CVE in `libssl` and we redeploy `app:2.20.14` without that CVE, we want the 2.20.7 finding to resolve even though the new scan's image string is different. Including the tag in the key would make auto-resolve useless for its main use case.

**Why `ImageRepo` is still included**: protects against resolving an unrelated finding that coincidentally shares (CVE, namespace, container, package) with the current scan. It's a rare edge case — containers usually keep the same image repo across upgrades — but keeping it costs nothing.

**Why the namespace is part of the key**: the same container name can exist in different namespaces (e.g. `prometheus` in `monitoring` and in a tenant namespace). We only want to reconcile findings the current upload is authoritative for.

### GitLab API Quirk: Nested Location

The GitLab `/projects/:id/vulnerabilities` list response has a top-level `location` field, but it is always empty. The real location and identifier data live under `finding.location` and `finding.raw_metadata` in the same object. The watcher parses the nested path; matching against the top-level field silently matches nothing (skipped_unparseable would be 0 but skipped_other_ns would include every finding).

### Safety Guards

1. **Dry-run default** (`AUTO_RESOLVE_DRY_RUN=true`) — logs every candidate with CVE, container, package, and image, without calling the resolve endpoint. First deployment should always run in dry-run until the logs look right.
2. **Per-namespace cap** (`AUTO_RESOLVE_MAX_PER_RUN=500`) — aborts the run for that namespace if the stale count exceeds the cap. A bug that computed keys wrongly, or a Trivy outage that produced an empty scan, could otherwise wipe the entire dashboard. The cap is per namespace, so one misbehaving upload can't poison other namespaces' reconciliation.
3. **Scoped to cluster_image_scanning** — other scan types (e.g. `container_scanning` from a CI build) have different resolution semantics and are explicitly skipped.
4. **Scoped to the just-uploaded namespace** — a project receiving uploads from multiple namespaces (unusual but possible via the default-project fallback) only reconciles the namespace that was just uploaded; others remain untouched until their own upload cycle runs.
5. **Idempotent** — `POST /vulnerabilities/:id/resolve` on an already-resolved vulnerability returns 200. No special handling needed for races or retries.

### Rollout Sequence

The feature is designed for a two-phase rollout:

| Phase | Settings | Purpose |
|-------|----------|---------|
| 1 (observe) | `AUTO_RESOLVE_ENABLED=true`, `AUTO_RESOLVE_DRY_RUN=true` | Log candidates; verify matching logic against real data |
| 2 (act)     | `AUTO_RESOLVE_ENABLED=true`, `AUTO_RESOLVE_DRY_RUN=false` | Actually resolve stale findings |

Re-detection is automatic: if the cluster scan surfaces the CVE again later, GitLab re-opens it. Resolving isn't destructive.

### Token Requirements

The resolve endpoint uses the same `GITLAB_ACCESS_TOKEN` (PAT or Group Access Token with `api` scope) that's already needed for pipeline triggers. No additional scopes required.

## Future Enhancements

1. **Namespace Labels**: Filter which namespaces to process via label selector
2. **Severity Thresholds**: Only upload vulnerabilities above certain severity
3. **Webhook Mode**: React to VulnerabilityReport changes instead of polling
4. **Metrics Endpoint**: Expose Prometheus metrics for monitoring, including auto-resolve counters (resolved/failed per namespace)
