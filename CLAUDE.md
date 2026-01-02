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

## GitLab Tokens
- **Validity**: 11 months (expire in December at earliest)
- **Location**: `~/.config/gitlab/gitlab.local` (self-hosted), `~/.config/gitlab/gitlab.com` (SaaS)
- **IMPORTANT**: ALWAYS read the token from config file with `tr -d '\n'` BEFORE making API calls
- **Usage**: `curl -s --header "PRIVATE-TOKEN: $(tr -d '\n' < ~/.config/gitlab/gitlab.local)" ...`
