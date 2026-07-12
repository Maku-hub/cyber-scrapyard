# Docker Security

> How to tell you're inside a container, why flags like `--privileged` are
> dangerous, and — most importantly — how to harden containers so those risks
> don't apply to you.

- **Link:** https://docs.docker.com/engine/security/
- **Type:** concept reference (Docker is open source / freemium)
- **Platform:** Linux (containers), cross-platform tooling

## Description

This page is a themed, defence-focused reference on container security. It covers
recognising a container environment, the misconfigurations that let an attacker
break out to the host (shown at *reference level* so you understand the risk),
and — the part that matters most for defenders — concrete hardening practices.
The takeaway: most container escapes are enabled by insecure run-time options, so
running containers with least privilege closes the door.

## Detecting a container environment

```bash
# cgroup entries mentioning docker/containerd are a strong hint
cat /proc/1/cgroup | grep -E 'docker|containerd'
# The Docker runtime drops this marker file
ls -la /.dockerenv
# Randomised hostname, container-style os-release, and mounts
hostname; cat /etc/os-release; mount | grep docker
```

## Escape-enabling misconfigurations (reference level)

These are the conditions defenders must avoid. They matter because each one
represents a control you should verify is *not* present in production.

- **Docker socket / daemon exposed** — membership of the `docker` group, or a
  daemon listening on TCP `2375` with no TLS, is effectively root on the host.
  Check with `id`, `docker ps`, and `nmap <host> -p 2375`.
- **`--privileged`** — grants near-total host access (all devices, capabilities).
  With it, host disks (`/dev/sda`) can be mounted and read from inside the
  container.
- **`--pid=host`** — shares the host PID namespace, exposing all host processes.
- **Bind-mounting the host root** (`-v /:/host`) — hands the container the whole
  filesystem.

The escape primitives that follow from the above (e.g. `nsenter --target 1`,
mounting a host disk, `chroot` into a bind-mounted host root) all depend on one
of these misconfigurations existing in the first place — remove the
misconfiguration and the primitive has nothing to stand on.

## Hardening best practices

```bash
# Don't use --privileged. Need one device? Pass just that device:
docker run --device=/dev/sda:/dev/xvdc --rm -it ubuntu fdisk /dev/xvdc

# Drop ALL capabilities, add back only what's required (e.g. bind port <1024)
docker run -it --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE php:apache

# Don't run as root inside the container
docker run -u 1001 -it ubuntu:latest /bin/bash

# Prevent privilege escalation entirely
docker run --rm -it --user 1001:1001 --security-opt no-new-privileges ubuntu:latest /bin/bash

# Read-only root filesystem with an explicit writable tmpfs
docker run --rm -it --read-only --tmpfs /tmp ubuntu:latest /bin/bash

# Confine syscalls/behaviour with a seccomp and/or AppArmor profile (keep the default seccomp on)
docker run --rm -it --security-opt seccomp=default.json --security-opt apparmor=docker-default ubuntu:latest /bin/bash
```

Additional guidance:

- Never expose the Docker daemon on an unauthenticated TCP port; if remote
  access is needed, use TLS client certificates.
- Never bind-mount the Docker socket (`/var/run/docker.sock`) into a container
  you don't fully trust.
- Prefer **rootless mode**: https://docs.docker.com/engine/security/rootless/
- Keep images minimal and patched; scan them (see [Trivy](trivy.md),
  [Clair](clair.md)) and audit the host (see
  [docker-bench-security](docker-bench-security.md)).

## Notes & references

- Audit an installation against the CIS Docker Benchmark with
  [docker-bench-security](docker-bench-security.md) (`./docker-bench-security.sh`).
- Monitor the daemon and containers at the host level with auditd/OSSEC/[Wazuh](../defense-blueteam/wazuh.md).
- Official security docs: https://docs.docker.com/engine/security/
- For Kubernetes, the equivalent checks live in [kube-bench](kube-bench.md) and
  [Kubescape](kubescape.md).
