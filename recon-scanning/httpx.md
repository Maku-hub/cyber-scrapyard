# httpx

> Fast and multi-purpose HTTP toolkit that probes hosts, confirms live web
> servers, and pulls titles, status codes, tech stacks and more across large
> lists of targets.

- **Link:** https://github.com/projectdiscovery/httpx
- **Type:** open source
- **Platform:** cross-platform (Go)

## Description

httpx (from ProjectDiscovery) is the tool you run right after subdomain
enumeration or port scanning to answer "which of these hosts actually serve
HTTP/HTTPS, and what are they?". It takes a list of hosts, ports or URLs on
stdin and, using a fast retryable HTTP client, reports which are alive along
with rich metadata — status code, page title, content length, response time,
detected technologies, TLS data, CDN, and more. It's the standard glue between
discovery tools (subfinder, naabu, amass) and content/vuln scanners (nuclei,
ffuf).

## Installation

```bash
# Install with Go (requires Go 1.21+)
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

## Usage examples

```bash
# Probe a single host for a live web server
echo example.com | httpx

# Probe a list of hosts and show status code, title and detected tech
httpx -l hosts.txt -status-code -title -tech-detect

# Pipe subdomains straight from subfinder into httpx
subfinder -d example.com -silent | httpx -silent

# Probe specific ports and only keep hosts that respond 200
httpx -l hosts.txt -ports 80,443,8080,8443 -mc 200

# Follow redirects and capture the final resolved URL
httpx -l hosts.txt -follow-redirects -location

# Grab response headers, TLS details and web server banner
httpx -l hosts.txt -include-response -tls-grab -web-server

# Save structured results as JSON for later parsing
httpx -l hosts.txt -json -o results.json
```

## Notes & references

- Not to be confused with the Python `httpx` library — ProjectDiscovery's tool
  is a separate CLI; install it via the Go path above to avoid the name clash.
- Use `-silent` to emit only clean URLs, ideal for piping into the next tool.
- Rate-limit with `-rate-limit` / `-threads` when probing production targets so
  you don't hammer the server.
- Pairs naturally with [naabu](naabu.md) for ports and
  [nuclei](../web-app-security/nuclei.md) for templated scanning.
- Docs: https://docs.projectdiscovery.io/tools/httpx
