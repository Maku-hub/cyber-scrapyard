# Sigma

> A vendor-neutral, YAML-based format for writing SIEM detection rules once and
> converting them to whatever query language your backend speaks — "the YARA of
> log files."

- **Link:** https://github.com/SigmaHQ/sigma
- **Type:** open source
- **Platform:** cross-platform (rules are YAML; tooling is Python)

## Description

Sigma solves a portability problem: every SIEM (Elastic, Splunk, Microsoft
Sentinel, QRadar, ...) has its own query syntax, so a detection written for one
doesn't run on another. A Sigma rule describes the *logic* of a detection — which
log source, which fields, which conditions — in a simple YAML structure, and a
converter (`sigma-cli` with the pySigma library) translates it into the target
backend's query. The SigmaHQ repo also ships thousands of community rules for
Windows, Linux, cloud, and network telemetry, so you get a ready-made detection
library that isn't locked to a vendor. It's the log-analysis counterpart to
[YARA](../reverse-engineering-malware/yara.md) (files) and Snort/Suricata
signatures (packets).

## Installation

```bash
# The modern CLI + conversion library (pySigma) via pipx
pipx install sigma-cli

# Add the backend/pipeline plugins you need (Splunk, Elasticsearch, Sentinel, ...)
sigma plugin list
sigma plugin install splunk

# Grab the community rule repository
git clone https://github.com/SigmaHQ/sigma.git
```

## Usage examples

```bash
# Convert a single rule to a Splunk search
sigma convert -t splunk rules/windows/process_creation/proc_creation_win_susp_whoami.yml

# Convert to Elasticsearch (Lucene) query syntax
sigma convert -t elasticsearch -f lucene rules/windows/process_creation/

# Convert to Microsoft Sentinel (KQL), applying a field-mapping pipeline
sigma convert -t sentinel -p sysmon rules/windows/

# List available conversion targets and pipelines
sigma list targets
sigma list pipelines
```

### Anatomy of a rule

```yaml
# A minimal Sigma rule: title, log source, detection logic, condition
title: Whoami Execution
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\whoami.exe'
  condition: selection
level: low
```

## Notes & references

- **Pipelines matter**: the same rule targets different field names on different
  products (e.g. raw Windows Event Log vs [Sysmon](sysmon.md) vs ECS), so pick the
  matching `-p` pipeline or your query will reference fields that don't exist.
- Rules carry MITRE ATT&CK tags, making Sigma a natural way to map detection
  coverage to techniques.
- Feed conversions into your SIEM: [Wazuh](wazuh.md), Elastic (as used by
  [Security Onion](security-onion.md)), Splunk, or Sentinel.
- Zeek logs and Sysmon events make excellent Sigma inputs — see
  [Zeek](../network-analysis/zeek.md) for the network side.
- Docs & rule-writing guide: https://sigmahq.io and https://github.com/SigmaHQ/sigma-specification
