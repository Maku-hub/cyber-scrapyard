# mitmproxy

> An interactive, scriptable HTTPS proxy: intercept, inspect, modify, and replay
> web traffic from a terminal UI, web UI, or Python addons.

- **Link:** https://github.com/mitmproxy/mitmproxy
- **Type:** open source
- **Platform:** cross-platform (Python)

## Description

mitmproxy sits between a client and a server and lets you see and tamper with
HTTP/HTTPS traffic in real time. It ships three fronts: `mitmproxy` (interactive
console TUI), `mitmweb` (browser UI), and `mitmdump` (a scriptable, tcpdump-like
CLI). It's excellent for testing mobile apps and APIs, debugging TLS traffic, and
writing Python addons that rewrite requests on the fly. Where
[Wireshark](wireshark.md) shows you packets, mitmproxy speaks HTTP and can
actively change it. Use only against clients/traffic you control or are
authorized to test.

## Installation

```bash
sudo apt install mitmproxy   # or: pipx install mitmproxy
```

## Usage examples

```bash
# Interactive TUI proxy on the default port 8080
mitmproxy

# Browser-based UI instead of the terminal
mitmweb

# Headless capture, printing flows and saving them to a file (-w)
mitmdump -w traffic.flows

# Replay saved flows / read them back
mitmdump -r traffic.flows

# Transparent mode (client has no proxy set; redirect traffic with iptables/pf)
mitmproxy --mode transparent

# Run a Python addon that rewrites requests or responses
mitmdump -s rewrite_addon.py
```

## Notes & references

- To intercept HTTPS the client must trust mitmproxy's CA — install it from
  http://mitm.it while the proxy is running. Without it, TLS clients will (and
  should) refuse the connection.
- Console keys: `f` set a view filter, `i` set interception, `e` edit a flow,
  `r` replay — flows can be paused, edited, and forwarded.
- `mitmdump` is the automation-friendly front; addons hook events like
  `request` / `response` for on-the-fly modification.
- Docs: https://docs.mitmproxy.org/ — see also web-layer tooling in
  [../web-app-security/](../web-app-security/) (Burp Suite, ZAP).
