# Recon-ng

> A full-featured reconnaissance framework with a Metasploit-style console:
> modular, database-backed OSINT collection you can automate end to end.

- **Link:** https://github.com/lanmaster53/recon-ng
- **Type:** open source
- **Platform:** cross-platform (Python)

## Description

Recon-ng brings structure to OSINT. Instead of running one-off tools, you work
inside an interactive console that feels like Metasploit: load modules, set
options, run them, and let results accumulate in a workspace database where each
new host, contact, or credential becomes a pivot for the next module. That
persistence and the marketplace of modules make it ideal for methodical,
repeatable engagements — and everything can be scripted for automation.

## Installation

```bash
# Debian/Kali
sudo apt install recon-ng

# Or from source
git clone https://github.com/lanmaster53/recon-ng.git
cd recon-ng && pip install -r REQUIREMENTS
./recon-ng
```

## Usage examples

```text
# Inside the recon-ng console:

# Create/switch to a workspace (isolates a target's data)
workspaces create acme

# Browse and install modules from the marketplace
marketplace search
marketplace install hackertarget

# Load a module, view and set its options, then run it
modules load recon/domains-hosts/hackertarget
options set SOURCE example.com
run

# Add API keys for modules that need them
keys add shodan_api <YOUR_KEY>
keys list

# Review collected data and export a report
show hosts
show contacts
modules load reporting/html
run
```

## Notes & references

- Data persists per workspace in a SQLite DB, so results chain: harvested hosts
  become input for the next module automatically.
- Many modules require API keys (`keys add ...`) — Shodan, Hunter, Bing,
  BuiltWith, etc.
- Can be driven non-interactively with resource scripts (`-r commands.rc`) for
  repeatable automation.
- Complements [theHarvester](theharvester.md) (quick collection) and
  [SpiderFoot](spiderfoot.md) (broad automation); this one rewards a structured,
  methodology-driven workflow.
- Author's course & wiki: https://github.com/lanmaster53/recon-ng/wiki
