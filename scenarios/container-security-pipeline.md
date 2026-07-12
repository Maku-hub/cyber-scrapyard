# Container & Image Security

> You have a container image and/or a Kubernetes cluster in scope. Scan the
> supply chain (image, dependencies, IaC) and the runtime (host, cluster,
> behaviour) for weaknesses.

## Scope & assumptions

- **Authorized use only.** Confirm you may pull the images, read the IaC repos,
  and run benchmarks/scanners against the cluster and its nodes. Active
  cluster-attack probing must be explicitly sanctioned.
- You have the image reference (registry/repo:tag) and, for cluster phases,
  kubeconfig access plus permission to run in-cluster jobs.
- The flow follows the pipeline left-to-right: build-time artefacts first
  (image, deps, IaC), then the deployed cluster/host, then live runtime
  detection.

## Phase 1 — Scan the image for CVEs

Start where the risk is densest: OS packages and language libraries baked into
the image. This surfaces known-vulnerable components before deployment.

- Scan the image with [Trivy](../containers-cloud/trivy.md), and optionally
  corroborate with [Grype](../vulnerability-scanners/grype.md) — a second engine
  often catches or de-dupes differently.

```bash
trivy image --severity HIGH,CRITICAL myapp:1.4.2   # OS + library CVEs
grype myapp:1.4.2                                   # second-opinion scan
```

## Phase 2 — Scan dependencies & generate an SBOM

Go deeper into the application's own dependency tree and produce a Software Bill
of Materials for tracking. This catches vulnerable direct/transitive packages
tied to specific ecosystems.

- Run [OSV-Scanner](../vulnerability-scanners/osv-scanner.md) against lockfiles
  and the SBOM; [Trivy](../containers-cloud/trivy.md) can also emit an SBOM
  (CycloneDX/SPDX) for your inventory.

```bash
trivy image --format cyclonedx -o sbom.json myapp:1.4.2   # generate SBOM
osv-scanner --sbom sbom.json                              # match SBOM against OSV
```

## Phase 3 — Scan IaC & configuration

Misconfigured manifests and Terraform are a top cause of container/cloud
incidents. Check the definitions that build and deploy the workload.

- Use the [IaC scanning](../containers-cloud/iac-scanning.md) page (Trivy config,
  Checkov, etc.) to flag insecure Dockerfiles, Kubernetes manifests, and
  Terraform (privileged pods, missing limits, host mounts).
- Cross-reference against the hardening guidance on the
  [Docker security](../containers-cloud/docker-security.md) page.

```bash
trivy config ./deploy    # scan Dockerfiles + k8s manifests + terraform
```

## Phase 4 — CIS benchmark the host & cluster

Now assess the deployed platform against recognised baselines — this covers the
Docker daemon/host and the Kubernetes control plane and nodes.

- Run [docker-bench-security](../containers-cloud/docker-bench-security.md) on
  container hosts and [kube-bench](../containers-cloud/kube-bench.md) for the
  CIS Kubernetes benchmark.
- Add [Kubescape](../containers-cloud/kubescape.md) for NSA/MITRE-framework
  posture scoring and attack-surface visibility.

```bash
kube-bench run --targets master,node    # CIS Kubernetes benchmark
kubescape scan framework nsa             # posture against NSA hardening guidance
```

## Phase 5 — Runtime detection

Static scanning can't see what a container does once running. Deploy runtime
detection to catch anomalous behaviour (shells in containers, unexpected network,
privilege changes).

- Deploy [Falco](../containers-cloud/falco.md) and validate that its rules fire
  on suspect activity, giving you runtime visibility to pair with the build-time
  findings.

```bash
falco -r /etc/falco/falco_rules.yaml     # stream runtime security events
```

## Reporting / next steps

Report findings per pipeline stage: image/dependency CVEs (with fixed versions),
IaC misconfigurations, benchmark deviations (mapped to CIS/NSA controls), and
runtime gaps. Prioritise fixes that shift left — pin/patch base images, fail the
build on critical CVEs, correct manifests, and enforce Falco rules in CI/CD and
admission control. Re-run the relevant scans to confirm closure and wire them
into the pipeline so the checks stay continuous.
