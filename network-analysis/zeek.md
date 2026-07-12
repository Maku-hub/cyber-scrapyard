# Zeek

> A network security monitor that turns raw traffic into rich, structured
> protocol logs and event-driven scripts — less "did a signature fire?" and more
> "here is everything that happened on the wire."

- **Link:** https://github.com/zeek/zeek
- **Type:** open source
- **Platform:** Linux / macOS (cross-platform from source)

## Description

Zeek (formerly Bro) sits passively on a tap or SPAN port and interprets traffic
at the application layer, writing one log per protocol: `conn.log` for every
connection, plus `dns.log`, `http.log`, `ssl.log`, `files.log`, `x509.log`, and
many more. Rather than matching packet signatures like [Snort](../defense-blueteam/snort.md)
or [Suricata](../defense-blueteam/suricata.md), it produces a high-fidelity
record of network behaviour that is ideal for threat hunting, incident response,
and building detections after the fact. Its scripting language lets you react to
events (a new connection, a downloaded file, a suspicious certificate) and raise
notices. Zeek is the network-metadata engine inside
[Security Onion](../defense-blueteam/security-onion.md).

## Installation

```bash
# Debian/Ubuntu via the official OpenSUSE Build Service repo (see docs for the current line)
echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_12/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
sudo apt update && sudo apt install zeek

# Zeek installs under /opt/zeek — add its bin to PATH
export PATH=/opt/zeek/bin:$PATH
```

## Usage examples

```bash
# Process a pcap offline — generates *.log files in the current directory
zeek -r capture.pcap

# Read a pcap and also load a policy script (e.g. hash all downloaded files)
zeek -r capture.pcap policy/frameworks/files/hash-all-files.zeek

# Live capture on an interface (root/pcap privileges required)
sudo zeek -i eth0

# Run a one-off inline script against a capture
zeek -r capture.pcap -e 'event zeek_init(){ print "starting"; }'
```

### Reading the logs

```bash
# Zeek logs are tab-separated with a header; zeek-cut extracts named columns
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto service

# Pull every DNS query seen in the capture
cat dns.log | zeek-cut query

# List files carved/observed and their MIME types
cat files.log | zeek-cut tx_hosts mime_type filename md5
```

## Notes & references

- For production sensors, `zeekctl` manages a clustered, multi-worker deployment
  across CPU cores; a single `zeek -i` process is fine for a lab.
- Output can be switched to JSON (`LogAscii::use_json=T`) for easy ingestion into
  a SIEM such as [Wazuh](../defense-blueteam/wazuh.md) or Elastic.
- The Zeek Package Manager (`zkg`) installs community scripts; docs at
  https://docs.zeek.org.
- Great pairing: capture with [tcpdump](tcpdump.md), enrich with Zeek, then write
  behavioural detections in [Sigma](../defense-blueteam/sigma.md).
