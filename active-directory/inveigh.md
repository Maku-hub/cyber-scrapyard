# Inveigh

> The Windows-side LLMNR/NBT-NS/mDNS spoofer and NTLM capture/relay tool —
> what you reach for when your foothold is a Windows box rather than a Linux
> attack host. The counterpart to [Responder](responder.md).

- **Link:** https://github.com/Kevin-Robertson/Inveigh
- **Type:** open source
- **Platform:** Windows (original PowerShell module + a cross-platform .NET/C# port)

## Description

[Responder](responder.md) is the go-to name-resolution poisoner, but it runs on
Linux. When your point of presence is a compromised Windows host — and you can't
or don't want to drop a Linux VM on the segment — Inveigh does the same job from
Windows. It poisons LLMNR, NBT-NS and mDNS broadcasts so victims authenticate to
you, captures the resulting NetNTLMv1/v2 challenge-responses for offline cracking
(Hashcat), and can relay them to other hosts. The original `Inveigh.ps1`
PowerShell module is handy for living-off-the-land; the newer C#/.NET build
(sometimes shipped as `InveighZero`) is a single executable with an interactive
console.

## Installation

```powershell
# PowerShell module — import directly from the cloned repo
git clone https://github.com/Kevin-Robertson/Inveigh
Import-Module .\Inveigh.psd1

# ...or download a prebuilt C#/.NET binary (Inveigh.exe) from Releases:
#   https://github.com/Kevin-Robertson/Inveigh/releases
```

## Usage examples

```powershell
# PowerShell: start LLMNR/NBT-NS/mDNS spoofing and capture NetNTLM hashes
Invoke-Inveigh -ConsoleOutput Y -NBNS Y -mDNS Y -LLMNR Y

# Show what has been captured so far in the current session
Get-Inveigh
Get-InveighCleartext        # any cleartext creds grabbed via HTTP basic auth

# Stop the running spoofer
Stop-Inveigh
```

```powershell
# C#/.NET build: run the standalone executable (interactive console)
.\Inveigh.exe

# Capture only (no poisoning) to observe the segment first — recon before noise
.\Inveigh.exe -LLMNR N -NBNS N -Inspect Y
```

## Notes & references

- Same hash types and workflow as [Responder](responder.md): crack NetNTLMv2
  offline with `hashcat -m 5600` (see [Password Cracking](../password-cracking/))
  or relay it with [ntlmrelayx](impacket.md) when SMB signing is not enforced.
- Running on Windows means AV/EDR may flag both the PowerShell module and the
  binary — expect detection on a monitored host.
- Defence is identical to Responder: disable LLMNR/NBT-NS via GPO, enforce SMB
  signing, and monitor for rogue name-resolution responders.
- Full parameter reference and wiki:
  https://github.com/Kevin-Robertson/Inveigh/wiki
