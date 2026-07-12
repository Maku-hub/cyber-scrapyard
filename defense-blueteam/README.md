# Defensive Security & Blue Team

Tools and concepts for the other side of the keyboard: detecting, monitoring,
and responding to attacks rather than launching them. This category spans
network intrusion detection, host and endpoint telemetry, log aggregation
(SIEM/XDR), web application firewalling, and the theory behind how endpoint
protection and denial-of-service attacks actually work.

## Tools & topics

| Tool / Topic | Summary |
| --- | --- |
| [Snort](snort.md) | Classic open-source IDS/IPS — signature rules, alerting/dropping, PCAP analysis |
| [Suricata](suricata.md) | Modern multi-threaded IDS/IPS/NSM with rich protocol logging and JSON (EVE) output |
| [Wazuh](wazuh.md) | Open-source SIEM/XDR/HIDS — log analysis, file integrity, and alerting via host agents |
| [Sysmon](sysmon.md) | Windows system monitoring — detailed process/network/registry events to the Event Log |
| [ModSecurity](modsecurity.md) | Web application firewall (WAF) engine, powered by the OWASP Core Rule Set |
| [osquery](osquery.md) | Query endpoint state as SQL tables — telemetry for hunting and compliance |
| [Sigma](sigma.md) | Vendor-neutral YAML detection rules — convert once to any SIEM query via sigma-cli |
| [Zeek](../network-analysis/zeek.md) | Network security monitor — protocol logs that make ideal detection input (see Network Analysis) |
| [YARA](../reverse-engineering-malware/yara.md) | Pattern-matching rules for files/memory — detection engine for malware hunting (see RE & Malware) |
| [Security Onion](security-onion.md) | All-in-one NSM/SIEM Linux distro (Suricata + Zeek + Elastic + analyst UI) |
| [AV & EDR concepts](av-edr-concepts.md) | Static vs dynamic vs behavioural analysis, sandboxes, and evasion |
| [DoS / DDoS defence](dos-defense.md) | L4 vs L7 attack classes, mitigation, and slowhttptest for authorised testing |
| [Elastic Stack (ELK)](elastic-elk.md) | Open-source SIEM/log backend — Elasticsearch + Kibana + Beats (free Basic tier) |

## How these fit together

- **Network layer** — [Snort](snort.md) / [Suricata](suricata.md) watch the
  wire; [Security Onion](security-onion.md) packages them with storage and a UI.
- **Host layer** — [Sysmon](sysmon.md) and [osquery](osquery.md) generate rich
  endpoint telemetry.
- **Aggregation & response** — [Wazuh](wazuh.md) correlates host + network
  events into a SIEM/XDR with alerting.
- **Perimeter** — [ModSecurity](modsecurity.md) filters web traffic;
  [DoS defence](dos-defense.md) keeps services available.
- **Theory** — [AV & EDR concepts](av-edr-concepts.md) explains how detection
  decisions are made.

> Detection is layered: signatures catch the known, behaviour catches the novel.
> Assume any single layer will be bypassed and instrument accordingly.

See also: [Network Traffic Analysis](../network-analysis/) for inspecting the
packets your sensors flag, and [Digital Forensics & Incident Response](../forensics-ir/)
for what happens after an alert fires. The
[Malware Triage](../scenarios/malware-triage.md) scenario shows the upstream side —
analysis output (YARA rules, IOCs) becoming the detections you deploy here.
