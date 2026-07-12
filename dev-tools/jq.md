# jq

> A command-line JSON processor: slice, filter, map, and reshape JSON from the
> shell — the `sed`/`awk` for structured data that APIs and modern tools spit
> out.

- **Link:** https://github.com/jqlang/jq
- **Type:** open source
- **Platform:** cross-platform

## Description

So much of security tooling now speaks JSON — API responses, `nmap`/`nuclei`
output, cloud CLIs, container manifests, threat-intel feeds. jq lets you query
and transform that JSON in a pipeline instead of eyeballing walls of braces:
pull out a single field, filter arrays by condition, flatten nested structures,
and reformat into CSV or compact lines. It pretty-prints by default, so even
`curl ... | jq` is an instant readability win.

## Installation

```bash
sudo apt install jq           # Debian/Kali/Ubuntu
```

## Usage examples

```bash
# Pretty-print any JSON (identity filter)
cat data.json | jq '.'

# Extract a single field
jq '.status' response.json

# Pull one field from every object in an array
jq '.hosts[].ip' scan.json

# Filter an array by a condition
jq '.findings[] | select(.severity == "high")' report.json

# Reshape: build new objects from selected fields
jq '.results[] | {host: .ip, port: .port}' scan.json

# Turn JSON rows into CSV
jq -r '.users[] | [.name, .email] | @csv' users.json

# Query an API response inline
curl -s https://api.example.com/v1/hosts | jq '.data[].hostname'
```

## Notes & references

- Official manual with the full filter language: https://jqlang.github.io/jq/manual/
- Try filters live in the browser: https://jqplay.org
- `-r` gives **raw** (unquoted) output — essential when piping values into other
  commands.
- `-c` prints compact one-line JSON, handy for feeding logs or `while read`
  loops.
- For interactive exploration and richer output, complements the browser-based
  [CyberChef](cyberchef.md).
