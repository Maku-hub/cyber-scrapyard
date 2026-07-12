# Log & Triage at Scale: Velociraptor & Chainsaw

> Go beyond one host: **Velociraptor** hunts and collects artifacts across many
> endpoints on demand, and **Chainsaw** rips through Windows event logs (with
> Sigma rules) to surface attacker activity fast.

- **Link:** Velociraptor https://github.com/Velocidex/velociraptor · Chainsaw https://github.com/WithSecureLabs/chainsaw
- **Type:** open source
- **Platform:** cross-platform (Velociraptor: server + Win/Linux/macOS agents; Chainsaw: cross-platform CLI)

## Description

Single-host tools don't scale to an enterprise incident. These two cover the
"across the fleet" and "through the logs" problems:

- **Velociraptor** — an endpoint visibility and DFIR platform. A central server
  pushes queries written in **VQL** (Velociraptor Query Language) to deployed
  agents, letting you hunt for IOCs, collect artifacts (it embeds KAPE-style
  targets), and monitor endpoints across an environment in near real time.
- **Chainsaw** — a fast Rust CLI for searching and detecting threats in Windows
  `.evtx` event logs. It applies **Sigma** rules and built-in detection logic to
  flag suspicious logons, service installs, PowerShell abuse, and more, and can
  search/extract by Event ID or string.

## Installation

```bash
# Velociraptor — download the single self-contained binary:
#   https://github.com/Velocidex/velociraptor/releases
./velociraptor gui            # quick standalone GUI for local collection/hunting

# Chainsaw — download a release binary, or build from source with cargo:
#   https://github.com/WithSecureLabs/chainsaw/releases
git clone https://github.com/WithSecureLabs/chainsaw && cd chainsaw && cargo build --release
```

## Usage examples

```bash
# --- Chainsaw: hunt Windows event logs with Sigma rules + mappings ---
chainsaw hunt C:\evtx_logs\ -s sigma/rules/ --mapping mappings/sigma-event-logs-all.yml

# Search event logs for a specific Event ID (e.g. 4625 = failed logons) or string
chainsaw search -t 'Event.System.EventID: =4625' C:\evtx_logs\   # failed logons
chainsaw search -e "mimikatz" C:\evtx_logs\

# --- Velociraptor: local triage collection without a full deployment ---
velociraptor artifacts collect Windows.KapeFiles.Targets --args Device=C:

# Run a VQL query directly
velociraptor query "SELECT Name, Pid FROM pslist()"
```

## Notes & references

- **Velociraptor** shines for scoping an incident: run one hunt and every agent
  reports back which hosts match — then collect artifacts from just those.
- **Chainsaw** is the quick win on a pile of exported `.evtx` files; pair its
  Sigma output with [EvtxECmd](eric-zimmerman-tools.md) for normalized CSVs.
- Related: **Hayabusa** (similar Sigma-based evtx timeliner), **DeepBlueCLI**
  (PowerShell log analysis), and full SIEM pipelines.
- This is where DFIR meets detection engineering — see
  [Defensive Security & Blue Team](../defense-blueteam/) for Sysmon logging and
  Sigma rule authoring that feed these tools.
- Velociraptor docs: https://docs.velociraptor.app
