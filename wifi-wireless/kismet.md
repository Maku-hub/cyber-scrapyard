# Kismet

> A passive wireless detector, sniffer, and IDS — it listens across channels and
> maps every device and network in range without transmitting anything.

- **Link:** https://github.com/kismetwireless/kismet
- **Type:** open source
- **Platform:** cross-platform (Linux, macOS, Windows via WSL)

## Description

Kismet is a passive tool: it hops channels and logs every access point and
client it hears, including hidden (non-beaconing) networks and clients that are
merely probing for known SSIDs. Because it never injects or associates, it's
ideal for reconnaissance, wardriving, and rogue-AP detection where you want to
map the RF environment without touching it. Modern Kismet runs a server with a
web UI, supports Wi-Fi, Bluetooth, and SDR sources, and logs to a rich SQLite
database you can replay and analyse later.

## Installation

```bash
sudo apt install kismet        # Debian/Kali/Ubuntu

# Add your user to the kismet group so you can run it without root
sudo usermod -aG kismet $USER
```

## Usage examples

```bash
# Start Kismet on a specific capture interface (monitor mode set automatically)
sudo kismet -c wlan0

# Then open the web UI in a browser
#   http://localhost:2501
# (set an admin login on first launch)

# Capture from several sources at once
sudo kismet -c wlan0 -c wlan1

# Replay/analyse a previously recorded capture (pcap/pcapng auto-detected)
kismet -c /path/to/capture.pcapng
# ...or state the datasource explicitly:
kismet -c pcapfile:file=/path/to/capture.pcapng
```

## Notes & references

- Kismet is **passive** — it detects hidden SSIDs and probing clients without
  ever sending frames, which makes it stealthy and safe for monitoring.
- The `.kismet` log is a SQLite DB; the `kismetdb_*` helper tools export it to
  pcap, JSON, or CSV for further analysis.
- Great for spotting rogue/evil-twin APs — pair it with
  [evil twin attacks](evil-twin-attacks.md) when validating defences.
- Probe-request data feeds "known beacons"/Karma-style attacks; see
  [evil twin attacks](evil-twin-attacks.md).
- Documentation: https://www.kismetwireless.net/docs/
