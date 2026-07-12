# Clair

> An open-source engine for static analysis of vulnerabilities in container
> images, designed to integrate with a registry and scan layers as they're
> pushed.

- **Link:** https://github.com/quay/clair
- **Type:** open source
- **Platform:** Linux (runs as a service, typically in containers)

## Description

Clair (from the Quay/Red Hat project) is a vulnerability scanner built to sit
behind a container registry. It indexes each image layer, extracts the installed
package manifest, and cross-references it against upstream vulnerability data,
exposing results over an API. Unlike a one-shot CLI, Clair is a service you run
continuously — it re-evaluates existing images as new CVEs are published, so an
image that was clean yesterday can be flagged today without re-scanning. It's the
scanner embedded in Quay, and can be driven standalone via `clair-scanner` or
`clairctl`.

## Installation

```bash
# Run the Clair service with a mounted config (exposes API on 6060/6061)
docker run --rm -v /root/clair_config/:/config -p 6060-6061:6060-6061 -d \
  clair -config="/config/config.yaml"
```

## Usage examples

```bash
# Scan a local image against a running Clair instance
clair-scanner -c http://172.17.0.3:6060 --ip 172.17.0.1 ubuntu-image

# Fail on findings at or above a threshold (whitelist known-accepted CVEs)
clair-scanner -c http://172.17.0.3:6060 --ip 172.17.0.1 \
  -w whitelist.yaml --threshold High myapp:1.0
```

## Notes & references

- `--ip` must be an address the Clair container can reach back on to pull the
  image layers being scanned.
- Best deployed as part of a registry pipeline (native in Quay) rather than
  ad hoc; for quick local/CI scans, [Trivy](trivy.md) is usually simpler.
- Docs: https://quay.github.io/clair/
- Pair with build-time [Trivy](trivy.md) scanning and host hardening from
  [docker-bench-security](docker-bench-security.md).
