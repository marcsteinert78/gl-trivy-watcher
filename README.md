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
| `GITLAB_PROJECT_ID` | required | Target project ID (numeric or path) |
| `GITLAB_TOKEN` | required | Token with `api` scope |
| `GITLAB_REF` | `main` | Branch to trigger pipeline on |
| `GITLAB_API_URL` | `https://gitlab.com/api/v4` | GitLab API URL |
| `POLL_INTERVAL` | `10s` | How often to check for changes |
| `STABILIZE_TIME` | `60s` | Wait time after last change |
| `MIN_TRIGGER_GAP` | `5m` | Minimum time between triggers |

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
    - apk add --no-cache curl gzip jq
    - 'curl -H "JOB-TOKEN: $CI_JOB_TOKEN" "$TRIVY_REPORT_URL" | gunzip > gl-container-scanning-report.json'
  artifacts:
    reports:
      container_scanning: gl-container-scanning-report.json
  rules:
    - if: $TRIVY_REPORT_URL
```

## Building locally

```bash
go build -o trivy-watcher .
```

## Container image

Built automatically on main branch:
`registry.gitlab.com/msteinert1/homeserver/tools/trivy-watcher:latest`
