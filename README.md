# Trivy Watcher

Go-based Kubernetes controller that watches Trivy Operator VulnerabilityReports and uploads them to GitLab Security Dashboard.

## How it works

1. Watches `VulnerabilityReport` CRs in the cluster
2. Converts to GitLab Security Report format
3. Uploads compressed report to GitLab Package Registry
4. Triggers pipeline in target project with report URL
5. Pipeline downloads and attaches report as artifact

## Architecture

```
Trivy Operator -> VulnerabilityReport CRs -> Trivy Watcher -> GitLab Package Registry
                                                          -> GitLab Pipeline Trigger
                                                                      |
                                                                      v
                                                          Pipeline downloads report
                                                                      |
                                                                      v
                                                          GitLab Security Dashboard
```

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `GITLAB_DEFAULT_PROJECT` | required | Fallback project (path) for namespaces without an explicit mapping |
| `GITLAB_GROUP_PATH` | optional | Group prefix for `group/<namespace>` resolution |
| `DEPLOY_TOKEN` | required | Deploy Token (scope: `write_package_registry`) |
| `DEPLOY_TOKEN_USER` | required | Deploy Token username (e.g., `gitlab+deploy-token-123`) |
| `GITLAB_ACCESS_TOKEN` | required | PAT or Group Token with `api` scope (multi-project pipeline triggers) |
| `GITLAB_REF` | `main` | Branch to trigger pipeline on |
| `GITLAB_API_URL` | `https://gitlab.com/api/v4` | GitLab API URL |
| `POLL_INTERVAL` | `10s` | How often to check for changes |
| `STABILIZE_TIME` | `60s` | Wait time after last change |
| `MIN_TRIGGER_GAP` | `5m` | Minimum time between triggers |
| `CACHE_TTL` | `5m` | Project-existence cache TTL |

## Token Setup (Minimal Permissions)

1. **Deploy Token** (Group → Settings → Repository → Deploy tokens)
   - Name: `trivy-watcher`
   - Scopes: `write_package_registry` only
   - Note the username (e.g., `gitlab+deploy-token-12345`)

2. **Group / Project Access Token** (Settings → Access Tokens)
   - Scope: `api` (needed to trigger pipelines across multiple projects)

## Deployment

See `kubernetes/trivy-watcher/` in the kubernetes repo for deployment manifests.

## Required RBAC

```yaml
rules:
  - apiGroups: ["aquasecurity.github.io"]
    resources: ["vulnerabilityreports"]
    verbs: ["get", "list", "watch"]
```

## Pipeline Integration

Target project needs this job:

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

## Building locally

```bash
go build -o trivy-watcher .
```

## Container image

Built automatically on main branch:
`registry.gitlab.com/msteinert1/homeserver/tools/trivy-watcher:latest`

## Development

This project was built with the assistance of Claude Code (Anthropic).
All code is human-reviewed, tested, and integrated; commits use the
`Co-Authored-By` trailer to attribute AI involvement.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
