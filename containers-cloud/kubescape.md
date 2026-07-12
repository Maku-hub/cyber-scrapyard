# Kubescape

> An open-source Kubernetes security platform that scans clusters, manifests, and
> Helm charts against recognised frameworks — NSA/CISA hardening guidance, MITRE
> ATT&CK for Kubernetes, and CIS benchmarks.

- **Link:** https://github.com/kubescape/kubescape
- **Type:** open source
- **Platform:** cross-platform (CLI, in-cluster operator, CI)

## Description

Kubescape (a CNCF project) measures the *posture* of a Kubernetes environment
against well-known control frameworks and hands back a risk score plus concrete
remediation. Its differentiator is the framework mapping: rather than a flat list
of checks, findings are grouped by the NSA/CISA Kubernetes Hardening Guidance,
the MITRE ATT&CK matrix for Kubernetes, and CIS benchmarks — so you can report
"how do we score against NSA/CISA?" directly. It scans live clusters, raw YAML
manifests, and Helm charts, which makes it useful both in CI (shift-left) and
against a running cluster.

## Installation

```bash
# Official install script (drops the binary in your PATH)
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
```

## Usage examples

```bash
# Scan the current cluster against all built-in frameworks
kubescape scan

# Scan specifically against the NSA/CISA hardening framework
kubescape scan framework nsa

# Scan against MITRE ATT&CK for Kubernetes
kubescape scan framework mitre

# Scan local manifests before they ever reach the cluster (shift-left / CI)
kubescape scan *.yaml

# Fail CI when the risk score exceeds a threshold (percent)
kubescape scan --fail-threshold 40

# Machine-readable output for pipelines / dashboards
kubescape scan --format json --output results.json
```

## Notes & references

- List available frameworks with `kubescape list frameworks`; common ones are
  `nsa`, `mitre`, `cis-v1.23-t1.0.1`, and `allcontrols`.
- Output formats include `pretty-printer`, `json`, `junit`, `sarif`, and `html`
  — SARIF uploads into GitHub code scanning.
- For continuous in-cluster monitoring, deploy the **Kubescape operator** via its
  Helm chart rather than running one-off CLI scans.
- Complements [kube-bench](kube-bench.md) (CIS configuration checks) and
  [Trivy](trivy.md)'s `k8s` scanning; pairs with runtime detection from
  [Falco](falco.md).
- Docs: https://kubescape.io/
