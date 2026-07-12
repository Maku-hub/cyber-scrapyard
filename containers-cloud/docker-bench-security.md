# Docker Bench for Security

> A script that audits your Docker host and containers against the CIS Docker
> Benchmark — dozens of automated best-practice checks in one run.

- **Link:** https://github.com/docker/docker-bench-security
- **Type:** open source
- **Platform:** Linux

## Description

Docker Bench is the official Docker implementation of the CIS Docker Benchmark.
It's a shell script that inspects the host configuration, the Docker daemon
setup and its config files, container runtime options, and image/build practices,
then prints PASS/WARN/INFO/NOTE results for each check. It's the fastest way to
find low-hanging misconfigurations — daemon exposed on TCP, containers running as
root or `--privileged`, missing `no-new-privileges`, permissive socket
permissions — and to track hardening progress over time.

## Installation

```bash
# Clone the repo (no install needed — it's a shell script)
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
```

## Usage examples

```bash
# Run the full benchmark (needs root / docker access to inspect the host)
sudo ./docker-bench-security.sh

# Run only specific check groups (e.g. host config + daemon config)
sudo ./docker-bench-security.sh -c host_configuration,docker_daemon_configuration

# Run via the prebuilt image, mounting the host paths it inspects
docker run --rm --net host --pid host --userns host --cap-add audit_control \
  -v /var/lib:/var/lib:ro -v /var/run/docker.sock:/var/run/docker.sock:ro \
  docker/docker-bench-security
```

## Notes & references

- Output legend: `[PASS]` good, `[WARN]` fix this, `[INFO]`/`[NOTE]` review.
  Focus on WARN items first.
- Use `-l logfile.log` to save results and diff runs after remediation.
- Complements the hardening guidance in [Docker Security](docker-security.md)
  and image scanning by [Trivy](trivy.md)/[Clair](clair.md).
- Kubernetes has its own equivalent — [kube-bench](kube-bench.md).
