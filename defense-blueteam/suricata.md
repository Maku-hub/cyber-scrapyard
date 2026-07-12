# Suricata

> A modern, multi-threaded IDS/IPS and network security monitor: signature
> detection plus rich protocol logging, file extraction, and JSON (EVE) output.

- **Link:** https://github.com/OISF/suricata
- **Type:** open source
- **Platform:** cross-platform (Linux primarily; also BSD/Windows/macOS)

## Description

Suricata is the OISF's high-performance engine that plays in the same space as
Snort but scales across CPU cores and does far more than raw signature matching.
It understands application protocols (HTTP, TLS, DNS, SMB, and more), can extract
transferred files, computes JA3/JA4 TLS fingerprints, and emits structured
`eve.json` logs that drop straight into Elasticsearch/Kibana or a SIEM. It reads
most Snort-format rules, so migrating rule sets is straightforward.

## Installation

```bash
# Debian/Kali/Ubuntu
sudo apt install suricata
```

```bash
# Fetch/update rule sets with the bundled rule manager
sudo suricata-update
```

## Usage examples

```bash
# Run as IDS on an interface using the default config
sudo suricata -c /etc/suricata/suricata.yaml -i eth0

# Analyse a saved capture (offline mode)
suricata -r capture.pcap -l ./logs

# Validate configuration and rules without starting capture
suricata -T -c /etc/suricata/suricata.yaml

# Inline IPS mode via NFQUEUE (packets must be sent to the queue by iptables)
sudo suricata -c /etc/suricata/suricata.yaml -q 0
```

### Reading the output

```bash
# Tail the unified JSON event log (alerts, flows, protocol records)
tail -f /var/log/suricata/eve.json | jq .

# Human-readable fast log of alerts only
tail -f /var/log/suricata/fast.log
```

### Example rule

```bash
# Alert on outbound DNS query for a known-bad domain
alert dns any any -> any any (msg:"DNS lookup to suspicious domain"; dns.query; content:"evil.example"; nocase; sid:2000001;)
```

## Notes & references

- `eve.json` is the killer feature — one structured record per event, ideal for
  feeding [Wazuh](wazuh.md), the ELK stack, or [Security Onion](security-onion.md).
- Rule/config docs: https://docs.suricata.io/
- Largely rule-compatible with [Snort](snort.md); ET Open is a popular free
  rule set installed via `suricata-update`.
