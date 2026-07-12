# Arkime

> Large-scale, open-source full-packet capture with a fast indexed session
> database and a web UI — the "record everything and search it later" piece of
> network security monitoring, sitting alongside Zeek and tcpdump.

- **Link:** https://github.com/arkime/arkime
- **Type:** open source
- **Platform:** Linux (server); web UI is cross-platform

## Description

Arkime (formerly Moloch) captures raw traffic to disk as standard PCAP while
indexing per-session metadata into OpenSearch/Elasticsearch, giving you a
searchable history of everything that crossed the wire. Where [tcpdump](tcpdump.md)
captures ad-hoc and [Zeek](zeek.md) turns traffic into protocol logs, Arkime
keeps the *full packets* and makes months of them queryable through a browser:
pivot on an IP, port, or hostname, drill into a session, and export the exact
PCAP for deeper analysis in [Wireshark](wireshark.md). That makes it the
retrospective NSM layer — when an alert fires today about activity from last
week, Arkime is where you go to see what actually happened.

## Installation

```bash
# Install the prebuilt package for your distro (RPM/DEB from the releases page)
sudo dpkg -i arkime_*.deb        # Debian/Ubuntu

# Run the guided configuration (sets interface, OpenSearch URL, password)
sudo /opt/arkime/bin/Configure
```

## Usage examples

```bash
# Initialise the OpenSearch/Elasticsearch indices (first run only — wipes data)
sudo /opt/arkime/db/db.pl http://localhost:9200 init

# Start live capture on the configured interface(s)
sudo systemctl start arkimecapture

# Start the web/viewer service, then browse to https://<host>:8005
sudo systemctl start arkimeviewer

# Add an admin user for the web UI
sudo /opt/arkime/bin/arkime_add_user.sh admin "Admin User" <password> --admin
```

### Importing existing PCAPs

```bash
# Index an offline capture so its sessions appear in the UI
/opt/arkime/bin/capture -r /path/to/capture.pcap

# Recursively import a directory of PCAPs
/opt/arkime/bin/capture -R /path/to/pcaps/
```

## Notes & references

- Arkime's own **query language** (e.g. `ip.dst == 10.0.0.5 && port.dst == 443`)
  drives the UI; sessions link straight to the raw PCAP for export.
- It needs an **OpenSearch or Elasticsearch** backend and fast disk — full-packet
  retention is storage-hungry, so size disks for your desired capture window.
- Three roles can run on one box or scale out: **capture** (writes PCAP + index),
  **viewer** (per-node PCAP access), and the OpenSearch cluster.
- Pairs well with [Zeek](zeek.md) and [Suricata](../defense-blueteam/suricata.md):
  let the sensors alert, then use Arkime to pull the full packets behind the alert.
- Docs: https://arkime.com/
