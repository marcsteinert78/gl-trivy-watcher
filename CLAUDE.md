# Claude Code Context

## GitLab Project
- **Project ID**: 77402174
- **Path**: msteinert1/homeserver/tools/trivy-watcher
- **URL**: https://gitlab.com/msteinert1/homeserver/tools/trivy-watcher

## Related Projects
| Repo | Project ID | Description |
|------|------------|-------------|
| kubernetes | 77345162 | K8s manifests (deployment target) |
| gitops | 77345161 | ArgoCD config |
| infrastructure | 77353235 | Terraform IaC |

## Container Image
`registry.gitlab.com/msteinert1/homeserver/tools/trivy-watcher:latest`

## Technology
- **Language**: Go 1.23
- **Base Image**: scratch (minimal)
- **Size**: ~15MB
- **Dependencies**: k8s.io/client-go, k8s.io/apimachinery

## Build
Pipeline uses Kaniko for rootless container builds.
