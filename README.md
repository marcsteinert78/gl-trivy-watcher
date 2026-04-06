# Trivy Watcher

Bridges [Trivy Operator](https://github.com/aquasecurity/trivy-operator) and the GitLab Security Dashboard. GitLab can ingest container scanning reports as CI artifacts but has no native way to pull continuous results from a Trivy Operator running in a Kubernetes cluster — this watcher closes that gap.

It runs as a small in-cluster controller that polls `VulnerabilityReport` CRs, groups findings by namespace, converts them to GitLab's [Container Scanning report format](https://docs.gitlab.com/ee/user/application_security/container_scanning/), and triggers a CI pipeline in the matching GitLab project. The pipeline picks the report up as an artifact, which makes it appear on the project's Security Dashboard.

> **Note:** This project is AI-assisted (Claude) under human review. See [LICENSE](LICENSE) (Apache-2.0).

## Why you might want this

- You run Trivy Operator and want its findings to show up in GitLab's Security Dashboard alongside the rest of your security telemetry.
- You operate many GitLab projects and want each namespace's vulnerabilities routed to the matching project automatically.
- You want a single small Go binary instead of a Helm chart of glue scripts.

## Prerequisites

- A Kubernetes cluster with [Trivy Operator](https://aquasecurity.github.io/trivy-operator/) installed and producing `VulnerabilityReport` CRs.
- A GitLab instance (self-hosted or gitlab.com). Note that the **Security Dashboard view** requires a paid GitLab tier (Ultimate). Reports are still uploaded and stored on lower tiers — they just won't appear on the dashboard UI.
- For each target project: a CI job that downloads the report and exposes it as a `container_scanning` artifact (see [Pipeline integration](#pipeline-integration) below).
- A container image. This repo ships a `Dockerfile`; build and push it to a registry your cluster can pull from.

## How it works

```
Trivy Operator ──▶ VulnerabilityReport CRs
                          │
                          ▼
                    Trivy Watcher  ─────▶  GitLab Package Registry  (one report per project)
                          │
                          └─────▶ GitLab Pipeline Trigger
                                          │
                                          ▼
                              CI job downloads the report
                                          │
                                          ▼
                              GitLab Security Dashboard
```

The watcher waits for the cluster's set of reports to become **stable** (no changes for `STABILIZE_TIME`, default 60s), then uploads. A hash-based change detector skips uploads when nothing actually changed, and `MIN_TRIGGER_GAP` rate-limits how often any given project gets a fresh pipeline.

## Namespace routing

For every namespace, the watcher resolves which GitLab project should receive its vulnerability report using three strategies, in order:

1. **Namespace annotation** (most explicit):
   ```bash
   kubectl annotate namespace my-app trivy-watcher.io/gitlab-project=my-group/my-app
   ```
2. **Naming convention** — if `GITLAB_GROUP_PATH=my-group` is set, the watcher tries `my-group/<namespace>` and uses it if the project exists.
3. **Default project** (`GITLAB_DEFAULT_PROJECT`) — fallback for everything that wasn't matched. All unmatched namespaces are merged into a single **consolidated** report uploaded to the default project, so you don't lose visibility on findings from infrastructure namespaces like `kube-system`.

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `GITLAB_DEFAULT_PROJECT` | **required** | Fallback project (path) for namespaces without an explicit mapping |
| `GITLAB_GROUP_PATH` | optional | Group prefix for `group/<namespace>` resolution |
| `DEPLOY_TOKEN` | **required** | Deploy Token for the upload (scope: `write_package_registry`) |
| `DEPLOY_TOKEN_USER` | **required** | Deploy Token username (e.g., `gitlab+deploy-token-123`) |
| `GITLAB_ACCESS_TOKEN` | **required** | PAT or Group Access Token with `api` scope (used to trigger pipelines and check whether projects exist) |
| `GITLAB_REF` | `main` | Branch to trigger pipeline on |
| `GITLAB_API_URL` | `https://gitlab.com/api/v4` | GitLab API URL |
| `POLL_INTERVAL` | `10s` | How often to check for changes |
| `STABILIZE_TIME` | `60s` | Wait time after the last change before uploading |
| `MIN_TRIGGER_GAP` | `5m` | Minimum time between triggers for the same project |
| `CACHE_TTL` | `5m` | Project-existence and namespace-annotation cache TTL |
| `HEALTH_ADDR` | `:8080` | Listen address for `/healthz` liveness probe |

## Token setup

1. **Deploy Token** (Group → Settings → Repository → Deploy tokens) — used for the package upload
   - Name: `trivy-watcher`
   - Scopes: `write_package_registry` only
   - Note the username (e.g., `gitlab+deploy-token-12345`)
2. **Group or Project Access Token** (Settings → Access Tokens) — used to trigger pipelines and check project existence
   - Scope: `api`

Group-level tokens work across all child projects, which is what you usually want.

## Required RBAC

```yaml
rules:
  - apiGroups: ["aquasecurity.github.io"]
    resources: ["vulnerabilityreports"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["namespaces"]
    verbs: ["get"]  # for the trivy-watcher.io/gitlab-project annotation lookup
```

## Pipeline integration

Each target project needs a CI job that downloads the latest report and exposes it as a `container_scanning` artifact. This is the job the watcher triggers via `TRIVY_TRIGGERED=true`:

```yaml
trivy:cluster-scan:
  stage: trivy
  image: alpine:latest
  script:
    - apk add --no-cache curl gzip
    - 'curl -H "JOB-TOKEN: $CI_JOB_TOKEN"
       "$CI_API_V4_URL/projects/$CI_PROJECT_ID/packages/generic/trivy-reports/1.0.0/trivy-report-latest.json.gz"
       | gunzip > gl-container-scanning-report.json'
  artifacts:
    reports:
      container_scanning: gl-container-scanning-report.json
  rules:
    - if: $TRIVY_TRIGGERED == "true"
```

## Health endpoint

The watcher exposes `/healthz` on `HEALTH_ADDR` (default `:8080`). It returns `200 OK` while the watcher loop is running and has completed a successful poll within the last `3 × POLL_INTERVAL` (minimum 30s); otherwise `503 Service Unavailable`. Wire it up as a Kubernetes `livenessProbe` so kubelet recycles a hung pod:

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 8080
  initialDelaySeconds: 15
  periodSeconds: 30
```

There is intentionally no readiness probe — nothing routes traffic to this pod.

## Building

A `Dockerfile` is included in the repo. Build and push to a registry your cluster can reach:

```bash
docker build -t your-registry.example.com/trivy-watcher:latest .
docker push your-registry.example.com/trivy-watcher:latest
```

Or build locally for development:

```bash
go build -o trivy-watcher .
go test ./...
```

## License

Apache-2.0 — see [LICENSE](LICENSE).
