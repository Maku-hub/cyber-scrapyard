# IaC Scanning (Checkov & tfsec)

> Static analysis for infrastructure-as-code: catch insecure Terraform,
> CloudFormation, Kubernetes, and Dockerfile configuration *before* it is
> deployed, straight from the pull request.

- **Type:** open source
- **Platform:** cross-platform (CLI, pre-commit, CI)

## Description

This page is a themed reference on infrastructure-as-code (IaC) static analysis:
scanning declarative config for misconfigurations that would become real risk
once applied. The idea is to shift security left — an unencrypted S3 bucket or a
security group open to `0.0.0.0/0` is far cheaper to fix in a diff than in
production. Two tools dominate the space and are covered here: **Checkov**, the
broad multi-framework scanner, and **tfsec**, the fast Terraform-focused one
(now maintained alongside Trivy).

## Checkov

Bridgecrew's policy-as-code scanner covering Terraform, CloudFormation, Helm,
Kubernetes, ARM, Serverless, and Dockerfiles, with 1000+ built-in policies.

- **Link:** https://github.com/bridgecrewio/checkov

```bash
# Install via pip/pipx
pipx install checkov
```

```bash
# Scan a directory of IaC (auto-detects the frameworks present)
checkov -d .

# Scan a single Terraform plan/file
checkov -f main.tf

# Restrict to one framework and emit SARIF for GitHub code scanning
checkov -d . --framework terraform -o sarif

# Skip a specific check that's an accepted risk
checkov -d . --skip-check CKV_AWS_20

# Scan a Dockerfile for insecure instructions
checkov -f Dockerfile --framework dockerfile
```

## tfsec

A fast, Terraform-native scanner (part of the Aqua Security family, converging
with Trivy) that flags cloud-provider misconfigurations with clear remediation.

- **Link:** https://github.com/aquasecurity/tfsec

```bash
# Install via the official script, brew, or go install
brew install tfsec
```

```bash
# Scan the Terraform in the current directory
tfsec .

# Emit SARIF and fail CI on findings
tfsec . --format sarif --out results.sarif

# Only fail on HIGH/CRITICAL severity
tfsec . --minimum-severity HIGH
```

## Notes & references

- Both tools return a non-zero exit code on findings, so they gate a pipeline out
  of the box; both support **pre-commit** hooks to catch issues before push.
- Inline suppressions: Checkov uses `#checkov:skip=CKV_ID:reason`; tfsec uses
  `#tfsec:ignore:rule-id`.
- [Trivy](trivy.md) also performs `trivy config` IaC scanning — tfsec's rules now
  feed into it — so a Trivy-centric shop may consolidate on that.
- Checkov docs: https://www.checkov.io/ ; tfsec docs: https://aquasecurity.github.io/tfsec/
- For runtime and posture checks after deployment, see [Falco](falco.md),
  [Kubescape](kubescape.md), and [Prowler](prowler.md).
