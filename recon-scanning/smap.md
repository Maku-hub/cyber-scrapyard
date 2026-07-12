# Smap

> A passive, Nmap-compatible port scanner that pulls its results from Shodan's
> internet-wide dataset instead of sending packets to the target.

- **Link:** https://github.com/s0md3v/Smap
- **Type:** open source
- **Platform:** cross-platform (single Go binary)

## Description

Smap takes the same arguments and produces the same output formats as Nmap, but
it never touches the target: results come from Shodan's precomputed scan data.
That makes it stealthy (no traffic to the host, nothing in their logs) and fast
(thousands of hosts in seconds), and it doesn't even need a Shodan API key. The
trade-off is freshness — you see what Shodan last observed, not the live state —
so treat it as reconnaissance to prioritise, not ground truth. It's a great
first pass before deciding what deserves an active [Nmap](nmap.md) scan.

## Installation

```bash
# Install with Go (drops the binary in $GOPATH/bin)
go install -v github.com/s0md3v/smap/cmd/smap@latest
```

## Usage examples

```bash
# Scan a single host — same syntax as nmap
smap 192.168.1.1

# Scan multiple hosts / a domain
smap example.com 1.1.1.1

# Read targets from a file, one per line
smap -iL targets.txt

# Shodan already returns service/version data; -sV is accepted but a no-op
smap -sV example.com

# Save output in all Nmap formats (normal, XML, greppable)
smap -oA results example.com

# Optionally verify a host with a real local Nmap pass
smap --active example.com
```

## Notes & references

- Smap ignores most Nmap flags (only `-p`, `-h`, `-o*`, `-iL`, `--concurrency`,
  `--append-output`, `--active` are honored) — it does **not** run NSE scripts.
- Because it queries Shodan, only publicly reachable, previously-scanned hosts
  return data — internal/RFC1918 addresses will come back empty.
- Output is Nmap-compatible, so XML from `-oX` imports cleanly into tools that
  already parse Nmap results.
- Pair with [Nmap](nmap.md): use Smap to triage a large scope passively, then
  confirm interesting hosts with an active scan.
- See also [Shodan](../osint/shodan.md) for interactive querying of the same
  underlying dataset.
