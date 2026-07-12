# Hayabusa

> A fast, Sigma-based Windows event-log analyzer: point it at EVTX files and it
> produces a ranked, timelined list of suspicious activity — a rapid way to triage
> what an attacker did from the logs alone.

- **Link:** https://github.com/Yamato-Security/hayabusa
- **Type:** open source
- **Platform:** cross-platform (Rust; Windows/Linux/macOS binaries)

## Description

Windows event logs record the who/when of authentication, process creation,
service installs, and PowerShell activity — but there are thousands of events and
few analysts know every relevant Event ID. Hayabusa, by Yamato Security, applies
a large built-in set of detection rules (its own plus native
[Sigma](../defense-blueteam/) support) across `.evtx` files and outputs a single
CSV timeline of hits, each tagged with a severity, the MITRE ATT&CK technique, and
the rule that fired. It's written in Rust for speed and is a go-to for fast
log-based triage in incident response and DFIR.

## Installation

```bash
# Download the prebuilt binary for your OS
# from https://github.com/Yamato-Security/hayabusa/releases and unzip it

# First run: fetch/update the bundled detection + Sigma rule set
./hayabusa update-rules
```

## Usage examples

```bash
# Analyze a directory of EVTX files into a CSV timeline
hayabusa csv-timeline -d ./evtx_logs -o timeline.csv

# Analyze a single event-log file
hayabusa csv-timeline -f Security.evtx -o security.csv

# Live triage: scan the local machine's event logs (run as admin on Windows)
hayabusa csv-timeline -l -o live.csv

# Print a quick summary of detections by severity/technique
hayabusa metrics -d ./evtx_logs

# Produce a super-timeline-friendly output for import elsewhere
hayabusa csv-timeline -d ./evtx_logs --profile super-verbose -o super.csv
```

## Notes & references

- Severity is colour-coded (critical/high/medium/…); sort the CSV by level to work
  the most serious detections first.
- Output includes the **MITRE ATT&CK** tactic/technique and the rule title, so
  each hit is immediately explainable in a report.
- Enable channels like **Security**, **System**, **PowerShell/Operational**, and
  **Sysmon** for the richest results — collect them with [KAPE](kape.md).
- Same idea as [Chainsaw](log-and-triage.md); both consume Sigma rules — analysts
  often run whichever they prefer, or both, for coverage.
- Import the timeline into [Timesketch](timesketch.md) for collaborative review.
- Docs and rule repo: https://github.com/Yamato-Security/hayabusa and
  https://github.com/Yamato-Security/hayabusa-rules
