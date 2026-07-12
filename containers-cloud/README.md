# Containers & Cloud Security

Tools and concepts for securing containerised and cloud-native infrastructure:
hardening Docker hosts and images, scanning for vulnerabilities and
misconfigurations, benchmarking Kubernetes against CIS, auditing cloud accounts
for risky configuration, and practising on deliberately-vulnerable labs. The
emphasis throughout is defensive — find and fix the misconfigurations before an
attacker does.

## Tools & topics

| Tool / Topic | Summary |
| --- | --- |
| [Docker Security](docker-security.md) | Container detection, `--privileged` risks, and hardening best practices |
| [Trivy](trivy.md) | Fast all-in-one scanner: images, filesystems, IaC, secrets, and CVEs |
| [Clair](clair.md) | Registry-integrated static vulnerability scanning of image layers |
| [docker-bench-security](docker-bench-security.md) | Audits a Docker host/containers against the CIS Docker Benchmark |
| [kube-bench](kube-bench.md) | Checks a cluster against the CIS Kubernetes Benchmark |
| [Kubescape](kubescape.md) | K8s posture scanning against NSA/CISA, MITRE ATT&CK, and CIS frameworks |
| [Falco](falco.md) | Runtime threat detection for containers/K8s via kernel syscall monitoring |
| [IaC Scanning](iac-scanning.md) | Static analysis of Terraform/K8s/Dockerfiles with Checkov and tfsec |
| [Scout Suite](scoutsuite.md) | Multi-cloud configuration auditing with a shareable HTML report |
| [Prowler](prowler.md) | AWS/Azure/GCP/K8s assessment mapped to CIS, PCI, NIST, and more |
| [CloudGoat](cloudgoat.md) | Vulnerable-by-design AWS lab for practising cloud attack & defence |
| [Cloud Attack](cloud-attack.md) | Offensive cloud enum & exploitation with CloudFox and Pacu (authorized use) |

## How these fit together

- **Docker layer** — [Docker Security](docker-security.md) explains the risks;
  [docker-bench-security](docker-bench-security.md) audits the host;
  [Trivy](trivy.md) and [Clair](clair.md) scan the images.
- **Kubernetes layer** — [kube-bench](kube-bench.md) checks *configuration*
  against CIS; [Kubescape](kubescape.md) scores posture against NSA/MITRE/CIS
  frameworks and surfaces attack paths.
- **Cloud layer** — [Scout Suite](scoutsuite.md) and [Prowler](prowler.md) audit
  account posture; [CloudGoat](cloudgoat.md) is the safe playground to learn on.

> Most container and cloud breaches come from misconfiguration, not exotic
> exploits. Scan images, audit configs against a benchmark, and grant least
> privilege — that closes the majority of the attack surface.

For these tools chained into a single build-to-runtime workflow, see the
[Container & Image Security](../scenarios/container-security-pipeline.md)
scenario.

See also: [Defensive Security & Blue Team](../defense-blueteam/) for monitoring
and detection (e.g. [Wazuh](../defense-blueteam/wazuh.md) can ingest container
and host telemetry), and [Digital Forensics & Incident Response](../forensics-ir/)
for investigating a compromised workload.
