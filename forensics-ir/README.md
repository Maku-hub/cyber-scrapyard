# Digital Forensics & Incident Response

Tools for acquiring evidence, reconstructing what happened on a system, and
responding to incidents at scale. This category covers disk and memory imaging,
memory forensics, filesystem and artifact parsing, rapid triage collection, and
log analysis — the toolkit for answering *what did the attacker do, when, and
what did they touch?*

> ⚠️ **Handle evidence carefully.** Work on **copies/images**, preserve the
> chain of custody, and note hashes at every step. Acquiring or analyzing systems
> you don't own requires authorization.

## Tools

| Tool | Summary |
| --- | --- |
| [Autopsy & The Sleuth Kit](autopsy-sleuthkit.md) | Open-source disk forensics — GUI (Autopsy) over the TSK filesystem-analysis engine |
| [Volatility](volatility.md) | The standard memory-forensics framework (Volatility 3) — parse RAM for processes, network, injection |
| [FTK Imager](ftk-imager.md) | Free, trusted disk/memory imaging and evidence preview |
| [Eric Zimmerman's tools](eric-zimmerman-tools.md) | Fast Windows artifact parsers — Amcache, ShellBags, MFT, prefetch, jump lists, and more |
| [KAPE](kape.md) | Kroll Artifact Parser/Extractor — targeted triage collection + parsing modules |
| [Log & triage at scale](log-and-triage.md) | Velociraptor for endpoint hunting/collection; Chainsaw for Windows event-log analysis |
| [Plaso (log2timeline/psort)](plaso-timeline.md) | Build super-timelines by parsing timestamps from hundreds of artifact types into one view |
| [RegRipper](regripper.md) | Plugin-driven registry hive parser — persistence, USB history, execution, and user activity |
| [MemProcFS](memprocfs.md) | Mount a memory image as a browsable filesystem of processes, handles, and hives |
| [bulk_extractor](bulk-extractor.md) | High-speed artifact carving (emails, URLs, PANs, PCAP) straight from raw bytes |
| [Hayabusa](hayabusa.md) | Fast, Sigma-based Windows EVTX analyzer producing a ranked, ATT&CK-tagged timeline |
| [Timesketch](timesketch.md) | Web-based collaborative timeline analysis — search, tag, and correlate super-timelines |

## The DFIR process (at a glance)

1. **Acquire** — image disks and capture RAM **before** touching the system more
   than necessary ([FTK Imager](ftk-imager.md)); hash every image.
2. **Triage** — for speed at scale, collect just the key artifacts with
   [KAPE](kape.md) or [Velociraptor](log-and-triage.md) instead of full images.
3. **Memory analysis** — run [Volatility](volatility.md) against the RAM capture
   for running processes, injected code, network connections, and credentials.
4. **Disk & artifact analysis** — carve and timeline the filesystem in
   [Autopsy](autopsy-sleuthkit.md); parse Windows artifacts with
   [Eric Zimmerman's tools](eric-zimmerman-tools.md) to reconstruct execution and
   file-access history.
5. **Log analysis** — hunt Windows event logs with
   [Chainsaw](log-and-triage.md) (Sigma rules) to spot logons, service installs,
   and lateral movement.
6. **Timeline & report** — merge artifacts into a super-timeline (e.g. Plaso),
   correlate, and document findings with IOCs.

## Key evidence sources

- **Memory (RAM)** — volatile; capture first. Reveals live processes, injected
  code, decrypted strings, and network state.
- **Disk / filesystem** — deleted files, `$MFT`, journals, and slack space.
- **Windows artifacts** — Prefetch, Amcache, ShellBags, LNK/JumpLists, registry
  hives, and browser history reconstruct user and program activity.
- **Event logs** — Security/System/PowerShell/Sysmon logs for the who/when.

For a worked example that puts memory forensics to use, see the
[Malware Triage](../scenarios/malware-triage.md) scenario, whose Phase 6 analyses
a detonation's memory capture with [Volatility](volatility.md).

See also: [Reverse Engineering & Malware Analysis](../reverse-engineering-malware/)
for analyzing any malware you recover, and
[Defensive Security & Blue Team](../defense-blueteam/) for the logging (Sysmon)
and detection (Sigma, EDR) that make these investigations possible.
