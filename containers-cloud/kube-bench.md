# kube-bench

> Checks whether a Kubernetes cluster is deployed according to the CIS Kubernetes
> Benchmark — the configuration-hardening counterpart to Kubescape's posture scan.

- **Link:** https://github.com/aquasecurity/kube-bench
- **Type:** open source
- **Platform:** Linux (runs on cluster nodes; Go binary or container)

## Description

kube-bench (from Aqua Security) audits a cluster's components against the CIS
Kubernetes Benchmark. It inspects the API server, controller manager, scheduler,
etcd, and kubelet configuration files and flags, plus RBAC and pod security
settings, then reports PASS/FAIL/WARN with the exact remediation text from the
benchmark. It auto-detects the platform/version and picks the right check set,
and understands managed distributions (EKS, GKE, AKS, OpenShift) where you only
control part of the control plane.

## Installation

```bash
# Run as a Job/Pod in the cluster (recommended)
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl logs job/kube-bench
```

```bash
# Or run the binary directly on a node
kube-bench
```

## Usage examples

```bash
# Run all applicable checks for the auto-detected version
kube-bench

# Run only the control-plane master checks
kube-bench run --targets master

# Run only the worker-node (kubelet) checks
kube-bench run --targets node

# Managed EKS profile, JSON output for pipelines
kube-bench run --benchmark eks-1.2.0 --json
```

## Notes & references

- Every FAIL comes with a remediation snippet — work through the master and node
  targets, then re-run to confirm.
- Output as JSON/JUnit for CI dashboards and compliance evidence.
- The natural partner to [Kubescape](kubescape.md): CIS configuration audit vs
  framework-based posture and attack-path analysis.
- The Docker-host analogue is [docker-bench-security](docker-bench-security.md).
