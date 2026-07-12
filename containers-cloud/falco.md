# Falco

> The CNCF runtime security engine for containers and Kubernetes: watches kernel
> syscalls (and other event sources) in real time and alerts on suspicious
> behaviour as it happens.

- **Link:** https://github.com/falcosecurity/falco
- **Type:** open source
- **Platform:** Linux (containers/Kubernetes), cross-platform tooling

## Description

Where image scanners tell you about *known* problems before deployment, Falco
watches what a workload actually *does* at run time. It taps kernel syscalls via
an eBPF probe (or kernel module) and evaluates a stream of events against a
customizable rule set — flagging things like a shell spawned inside a container,
a write to a sensitive path, an unexpected outbound connection, or a package
manager running in production. It's the CNCF-graduated standard for runtime
threat detection, and it pairs naturally with the pre-deploy scanning tools in
this section.

## Installation

```bash
# Debian/Ubuntu via the official falcosecurity apt repo
sudo apt install falco
```

```bash
# Or run it as a DaemonSet on Kubernetes via the official Helm chart
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco --namespace falco --create-namespace
```

## Usage examples

```bash
# Run Falco in the foreground with the default rule set
sudo falco

# Load a custom rules file in addition to the defaults
sudo falco -r /etc/falco/my_rules.yaml

# Validate a rules file without starting the engine
sudo falco -V /etc/falco/my_rules.yaml

# List the event sources compiled into this build (syscall, k8s_audit, ...)
falco --list-events

# Output alerts as JSON (easy to ship to a SIEM)
sudo falco -o json_output=true

# Dry-run against a captured scap trace instead of the live system
sudo falco -e /path/to/capture.scap
```

## Notes & references

- Rules, macros, and lists are defined in YAML; the defaults live in
  `/etc/falco/falco_rules.yaml`, and your overrides go in
  `falco_rules.local.yaml` so upgrades don't clobber them.
- **Falcosidekick** fans alerts out to Slack, Elasticsearch, webhooks, and more:
  https://github.com/falcosecurity/falcosidekick
- Modern deployments prefer the **eBPF** driver (`--modern-bpf`) — no kernel
  module to build or load.
- Complements pre-deploy scanning ([Trivy](trivy.md), [Kubescape](kubescape.md))
  and feeds detections into [Defensive Security & Blue Team](../defense-blueteam/)
  tooling such as [Wazuh](../defense-blueteam/wazuh.md).
- Docs: https://falco.org/docs/
