# Wazuh

> Open-source SIEM/XDR built on a host agent: log analysis, file-integrity
> monitoring, rootkit detection, vulnerability detection, and alerting from one
> platform.

- **Link:** https://github.com/wazuh/wazuh
- **Type:** open source
- **Platform:** cross-platform (agents: Linux/Windows/macOS; server: Linux)

## Description

Wazuh is a full security-monitoring platform that started life as a fork of
OSSEC. Lightweight agents run on your endpoints and ship logs, file-integrity
events, process/inventory data, and system-call telemetry to a central manager,
which correlates them against a large rule set and MITRE ATT&CK mappings. The
Wazuh dashboard (an OpenSearch/Kibana derivative) gives you search, alerting, and
compliance views (PCI DSS, GDPR, CIS). It's the go-to free option when you want
HIDS + SIEM + light XDR without per-endpoint licensing.

## Installation

```bash
# All-in-one server install (manager + indexer + dashboard) on a fresh Linux host
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

```bash
# Install an agent on Debian/Ubuntu and point it at the manager
WAZUH_MANAGER="10.0.0.10" apt install wazuh-agent
```

## Usage examples

```bash
# Register/enrol a new agent against the manager
/var/ossec/bin/agent-auth -m 10.0.0.10

# Start / check the agent service
systemctl start wazuh-agent
/var/ossec/bin/wazuh-control status

# List connected agents from the manager
/var/ossec/bin/agent_control -l

# Test how a raw log line is decoded and which rule it triggers
/var/ossec/bin/wazuh-logtest
```

### File-integrity monitoring (agent `ossec.conf`)

```xml
<!-- Watch a directory and alert on any change, checking every 12h -->
<syscheck>
  <directories check_all="yes" realtime="yes">/etc,/usr/bin</directories>
  <frequency>43200</frequency>
</syscheck>
```

## Notes & references

- Ingests [Sysmon](sysmon.md), [Suricata](suricata.md) EVE, and [osquery](osquery.md)
  data, making it a natural hub for endpoint + network telemetry.
- Rules and decoders live under `/var/ossec/{ruleset,etc/rules}`; write custom
  rules in `local_rules.xml`.
- Docs: https://documentation.wazuh.com/
- Complements packet-level detection from [Snort](snort.md)/[Suricata](suricata.md)
  with host-level visibility for [incident response](../forensics-ir/).
