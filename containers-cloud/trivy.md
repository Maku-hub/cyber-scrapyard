# Trivy

> A fast, all-in-one scanner for container images, filesystems, git repos, and
> IaC — finds known CVEs, misconfigurations, exposed secrets, and license issues.

- **Link:** https://github.com/aquasecurity/trivy
- **Type:** open source
- **Platform:** cross-platform

## Description

Trivy (from Aqua Security) is the de facto open-source vulnerability scanner for
the container/cloud-native world. Point it at an image and it enumerates OS
packages and application dependencies, matching them against vulnerability
databases; but it also scans plain filesystems, git repositories, Kubernetes
clusters, and infrastructure-as-code (Terraform, Dockerfiles, Kubernetes
manifests) for misconfigurations and hard-coded secrets. Zero-config to start,
easy to wire into CI, and it exits non-zero on findings so it can gate a build.

## Installation

```bash
# Debian/Ubuntu via the Aqua apt repo, or use the install script / docker image
sudo apt install trivy
```

```bash
# Run without installing
docker run --rm aquasec/trivy:latest image nginx:latest
```

## Usage examples

```bash
# Scan a container image for OS + dependency CVEs
trivy image nginx:latest

# Only show HIGH/CRITICAL and ignore unfixed vulns (typical CI gate)
trivy image --severity HIGH,CRITICAL --ignore-unfixed myapp:1.0

# Fail the build (exit code 1) when qualifying issues are found
trivy image --exit-code 1 --severity CRITICAL myapp:1.0

# Scan a local project directory for vulns, misconfigs, and secrets
trivy fs .

# Scan IaC / config files (Terraform, Dockerfile, k8s manifests)
trivy config ./deploy

# Scan the active Kubernetes cluster (uses your current kube-context)
trivy k8s --report summary
```

## Notes & references

- Output formats via `--format` (`table`, `json`, `sarif`, `cyclonedx`,
  `spdx`); SARIF uploads straight into GitHub code scanning.
- Use `.trivyignore` to suppress accepted-risk CVE IDs.
- Docs: https://trivy.dev/
- Compares with [Clair](clair.md) (registry-integrated image scanning) and
  complements the host/CIS audits in [docker-bench-security](docker-bench-security.md).
