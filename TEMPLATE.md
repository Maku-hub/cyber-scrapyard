# Tool Name

> One-line summary of what the tool does and when you'd reach for it.

- **Link:** https://example.com
- **Type:** open source / freemium / commercial
- **Platform:** Linux / Windows / macOS / cross-platform

## Description

A short paragraph: what problem it solves, where it fits in a workflow, and
what makes it worth knowing. Keep it practical — a reader should understand
*why* they'd use it, not just *that* it exists.

## Installation

```bash
# The quickest way to get it running (package manager, pipx, docker, etc.)
sudo apt install toolname
```

## Usage examples

```bash
# Each example gets a one-line comment explaining what it does.
toolname --scan target.example.com

# Show a second, more advanced example when it adds real value.
toolname --deep --output report.txt target.example.com
```

## Notes & references

- Gotchas, tips, or common flags worth remembering.
- Links to good tutorials, docs, or write-ups.

---

## Sanctioned variants

Two deviations from the layout above are intentional and consistent across the repo:

- **GUI tools** (e.g. Ghidra, Autopsy, Burp) may replace `## Usage examples` with
  a `## Typical workflow` section of numbered steps, since there's no simple CLI
  invocation to show.
- **Collection pages** grouping several related tools under one topic (e.g.
  `subdomain-enumeration.md`, `hex-editors-and-misc.md`) may drop the single
  `**Link:**` bullet and instead give each tool its own short subsection with its
  own link.

Concept/overview pages (e.g. Cyber Kill Chain) should still carry a `**Link:**`
bullet to their canonical reference where one exists.
