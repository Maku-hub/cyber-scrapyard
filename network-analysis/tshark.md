# tshark

> The command-line version of Wireshark: capture, filter, and dissect packets
> from a terminal — ideal for remote boxes, scripting, and pcap post-processing.

- **Link:** https://www.wireshark.org/docs/man-pages/tshark.html
- **Type:** open source
- **Platform:** cross-platform (ships with [Wireshark](wireshark.md))

## Description

tshark gives you Wireshark's protocol dissectors without the GUI. It's perfect
when you're on an SSH session, need to extract specific fields into a pipeline,
or want to generate quick statistics from a capture file. It understands the
same display filters (`-Y`) as Wireshark and can emit selected fields (`-e`) in
a tab-separated form that's trivial to feed into `awk`, `grep`, or a script.

## Installation

```bash
sudo apt install tshark      # Debian/Kali/Ubuntu (part of the wireshark package)
```

## Usage examples

```bash
# Capture and fully dissect a single packet on eth0 (-V = verbose, -c = count)
tshark -V -c 1 -i eth0

# Live-filter HTTP GET requests on eth0 (display filter with -Y)
tshark -Y 'http.request.method == "GET"' -i eth0

# Summarize IP endpoints from a pcap (communication patterns, exfil, scans)
tshark -r capture.pcap -qz endpoints,ip

# Follow the first TCP conversation in a pcap as ASCII text
tshark -r capture.pcap -q -z follow,tcp,ascii,0

# Extract specific fields (src IP, dst IP, protocol) in tab-separated form
tshark -e ip.src -e ip.dst -e frame.protocols -T fields -r capture.pcap
```

## Notes & references

- `-Y` applies a **display** filter; `-f` applies a **BPF capture** filter (same
  syntax as [tcpdump](tcpdump.md)) — capture filters are cheaper on high traffic.
- `-T fields -e <field>` is the workhorse for scripting; add `-E header=y` and
  `-E separator=,` to produce clean CSV.
- `-z` statistics are powerful: try `-qz conv,tcp`, `-qz http,tree`,
  `-qz io,phs` (protocol hierarchy).
- Full man page: https://www.wireshark.org/docs/man-pages/tshark.html
