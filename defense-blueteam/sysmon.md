# Sysmon

> A Windows system service (Sysinternals) that logs high-value security events —
> process creation, network connections, file/registry changes — to the Event
> Log for detection and forensics.

- **Link:** https://learn.microsoft.com/sysinternals/downloads/sysmon
- **Type:** free (closed source, Microsoft/Sysinternals)
- **Platform:** Windows (a Linux port exists via Sysmon for Linux)

## Description

Sysmon (System Monitor) fills the gaps in default Windows auditing. Once
installed it runs as a driver + service and writes detailed, structured events
to `Microsoft-Windows-Sysmon/Operational`: full command lines and hashes for
every process, parent/child relationships, network connections with the owning
process, DNS queries, image loads, and registry/file changes. It's the backbone
of most Windows detection pipelines — you point a log shipper at its channel and
feed a SIEM. The behaviour is entirely driven by an XML configuration, so a good
config is what makes it useful.

## Installation

```powershell
# Download Sysmon from Sysinternals, then install with a config file
sysmon64.exe -accepteula -i sysmonconfig.xml
```

## Usage examples

```powershell
# Install/upgrade the running config from a file
sysmon64.exe -c sysmonconfig.xml

# Print the current effective configuration
sysmon64.exe -c

# Uninstall the driver and service
sysmon64.exe -u

# Read Sysmon events with PowerShell (e.g. process-creation, Event ID 1)
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 20 |
  Where-Object { $_.Id -eq 1 }
```

### Key event IDs

- **1** — process creation (command line, hashes, parent process).
- **3** — network connection (with the initiating process).
- **7** — image/DLL loaded.
- **11** — file created.
- **13** — registry value set.
- **22** — DNS query.

## Notes & references

- Don't write your own config from scratch — start from the widely used
  **SwiftOnSecurity** template and tune it:
  https://github.com/SwiftOnSecurity/sysmon-config
- Another popular, ATT&CK-mapped modular config: Olaf Hartong's `sysmon-modular`.
- Ship the Operational channel to [Wazuh](wazuh.md) or an ELK/SIEM for
  correlation and alerting.
- Great source of timeline data for [DFIR](../forensics-ir/).
