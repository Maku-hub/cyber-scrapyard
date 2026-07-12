# Security Onion

> A free Linux distro that bundles a full network security monitoring and SIEM
> stack — Suricata, Zeek, the Elastic stack, and a hunting UI — into one
> deployable platform.

- **Link:** https://github.com/Security-Onion-Solutions/securityonion
- **Type:** open source
- **Platform:** Linux (dedicated ISO / appliance)

## Description

Security Onion saves you from wiring together a dozen tools by hand. Install the
ISO and you get NSM sensors ([Suricata](suricata.md) for alerts, Zeek for
protocol metadata, packet capture), the Elastic stack for storage and search,
plus purpose-built analyst apps: **SOC** (the web console), **Hunt** for
pivoting through data, **Alerts/Dashboards**, **CyberChef**, and case management
via TheHive. It scales from a single evaluation VM to distributed sensor +
search-node deployments, making it a common choice for SOC labs and real
monitoring alike.

## Installation

```bash
# Boot the Security Onion ISO, then run the guided setup
sudo so-setup
```

## Usage examples

```bash
# Check the status of all Security Onion services/containers
sudo so-status

# Import a PCAP so its alerts and logs appear in the analyst tools
sudo so-import-pcap /path/to/capture.pcap

# Restart the Suricata sensor after a rule change
sudo so-suricata-restart
```

- Browse to the **SOC** web UI, then use **Alerts** → **Hunt** → **PCAP** to
  pivot from a Suricata alert down to the raw packets that caused it.

## Notes & references

- Two analysis modes: **live** (sensor on a SPAN/TAP port) or **import** (feed
  it PCAPs) — the import workflow is great for CTFs and case review.
- Docs: https://docs.securityonion.net/
- Bundles the same detection engines documented separately here —
  [Suricata](suricata.md) and Zeek — with storage and a UI on top.
- A natural companion to hands-on [DFIR](../forensics-ir/) and
  [network analysis](../network-analysis/) work.
