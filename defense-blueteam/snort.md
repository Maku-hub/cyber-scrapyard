# Snort

> The classic open-source IDS/IPS: sniffs traffic, matches it against a rule
> set, and alerts (or drops) when something looks malicious. Also replays and
> analyses saved PCAPs.

- **Link:** https://www.snort.org
- **Type:** open source
- **Platform:** cross-platform (Linux primarily; also BSD/Windows)

## Description

Snort is a long-lived, heavily maintained intrusion detection system. It can run
purely as an IDS (alert only) or as an inline IPS, where on detecting an attack
it can drop the packet or ask the firewall to block the attacker. It's widely
embedded in appliances and is a great way to learn signature-based detection,
because the rule language is compact and readable. Rules come from the community
set (shipped with many distros), the official Talos/VRT rules, and commercial
feeds such as Proofpoint.

## Installation

```bash
# Debian/Kali/Ubuntu
sudo apt install snort
```

Key configuration files:

```bash
# Main config: variables, preprocessors, rule includes
/etc/snort/snort.conf
# Debian-specific settings (interface, HOME_NET)
/etc/snort/snort.debian.conf
# Your own local rules live here
/etc/snort/rules/local.rules
```

In `snort.conf` you typically: disable dynamic detection (dynamic rule
libraries) if unused, set `RULE_PATH`, and enable the rule files you want.

## Usage examples

```bash
# Sniffer mode — print packet headers to the console
snort -v -i eth0

# Verbose with application-layer payload
snort -vd -i eth0

# Run in IDS mode against a config, alert to console, quiet startup banner
snort -K none -A console -q -c /etc/snort/snort.conf -i ens4

# Read and analyse a saved capture, logging to a directory
snort -r capture.pcap -l /root/snort_logs -c /etc/snort/snort.conf
```

### Rule syntax

The general form is:

```
action proto srcIP srcPort -> dstIP dstPort (options)
```

Available protocols: `tcp`, `udp`, `icmp`, `ip`.

```bash
# Minimal rule — alert on any IP traffic, just to test the pipeline
alert ip any any -> any any (msg:"test rule"; sid:1000001;)

# Match a case-insensitive string anywhere in the payload
alert ip any any -> any any (msg:"suspicious string"; content:"evil_payload"; nocase; sid:1000002;)

# Alert on ICMP echo requests (type 8, code 0)
alert icmp any any -> any any (msg:"ICMP echo request"; itype:8; icode:0; sid:6666666;)

# ICMP echo carrying a specific string in the payload
alert icmp any any -> any any (msg:"keyword in ping"; itype:8; content:"SECRET"; sid:6666667;)

# Threshold — only alert after 5 echo requests from the same source within 60s
alert icmp any any -> any any (msg:"repeated pings"; itype:8; icode:0; sid:6666668; threshold: type threshold, track by_src, count 5, seconds 60;)
```

Rule option quick reference:

- `msg` — text shown in the alert.
- `sid` — unique rule ID (use `>1000000` for local rules).
- `content` / `nocase` — payload match, optionally case-insensitive.
- `itype` / `icode` — ICMP type and code.
- `threshold` / `detection_filter` — rate-limit or require N hits before alerting.

## Notes & references

- Output plugins control logging: plain text, or the binary **unified** format
  (feed to Barnyard2) to minimise Snort's own load on busy links.
- Manual / docs: https://docs.snort.org/
- Rule-writing walkthrough: https://litux.nl/mirror/snortids/0596006616/snortids-CHP-5-SECT-2.html
- For a more modern, multi-threaded alternative see [Suricata](suricata.md).
- Pair with [Wireshark](../network-analysis/wireshark.md) to inspect the packets
  that triggered a rule.
