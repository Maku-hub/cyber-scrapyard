# Windows

> A reference of useful Windows administration, diagnostic, and reconnaissance
> commands, plus notes on a few security-relevant internals. Handy for system
> administration, incident response, and understanding where Windows keeps its
> secrets.
>
> ⚠️ **For authorized and educational use only.** Run these on machines you own
> or administer. Several items (credential locations, BitLocker internals) are
> included so defenders understand the attack surface.

## Elevated command prompt

Many administrative commands require an elevated shell.

```bash
# Run cmd as another user / as Administrator
runas /user:Administrator cmd

# Launch an elevated cmd from PowerShell
powershell -Command "Start-Process cmd -Verb RunAs"
```

## System & configuration info

```bash
# Detailed system and configuration information (OS, patches, hardware)
systeminfo

# MAC addresses of all network adapters
getmac -v

# Command history for the current session
doskey /history

# Recursively search for a file by name (quietly skip access errors)
Get-ChildItem -Path C:\ -Recurse -Filter "NTDS.DIT" -ErrorAction SilentlyContinue
```

## Networking

```bash
# Active connections, listening ports, and owning PIDs
netstat -ano

# Routing table — networks this host knows about
route print

# Add a route (destination network, mask, gateway/our IP)
route add 192.168.10.0 MASK 255.255.255.0 192.168.0.15

# Delete a route
route DELETE xxx.xxx.xxx.xxx

# Release the current DHCP-assigned address, then request a new one
ipconfig /release
ipconfig /renew

# Show, then clear, the local DNS resolver cache
ipconfig /displaydns
ipconfig /flushdns
```

The hosts file lives at `C:\Windows\System32\drivers\etc\hosts`.

## Wi-Fi profiles

```bash
# List saved wireless profiles
netsh wlan show profile

# Reveal the stored key for a specific network
netsh wlan show profile "wifinetwork" key=clear | findstr "Key Content"

# Loop over every saved profile and print SSID + key
for /f "skip=9 tokens=1,2 delims=:" %i in ('netsh wlan show profiles') do @if "%j" NEQ "" (echo SSID: %j & netsh wlan show profiles %j key=clear | findstr "Key Content") & echo.
```

## Files, folders & encryption

```bash
# Encrypt files in the current folder (EFS)
cipher /E

# Hide / un-hide a folder (hidden + system + read-only attributes)
attrib +h +s +r foldername
attrib -h -s -r foldername

# Hide a zip/rar inside an image (concatenation trick)
copy /b image.ext+folder.zip image.ext

# Map a normal folder as a mounted drive letter, and remove it
subst q: c:\filelocation
subst /d q:

# Free space by clearing temp files
del /q /f /s %temp%\*
del /s /q C:\Windows\temp\*
```

## Credentials & disk encryption (defensive awareness)

```bash
# Open the stored usernames/passwords manager
rundll32.exe keymgr.dll,KRShowKeyMgr
```

- Local account password hashes live in the SAM database at
  `%SystemRoot%\System32\config\SAM` (protected while Windows is running).
- **BitLocker** protects a volume with a key hierarchy (`FVEK` ← `VMK` ← key
  protector). Check status and know that maintenance/update flows can temporarily
  suspend protection:

```bash
# Check whether a volume is BitLocker-encrypted
manage-bde -status

# During an update, BitLocker may be suspended for a set number of reboots,
# which can expose the volume key in the clear until protection resumes:
Suspend-BitLocker -MountPoint "C:" -RebootCount 1   # 0 = suspend indefinitely
```

## Windows internals note — NTDLL

Windows routes key operations through `ntdll.dll`, which exposes the native
API / syscall stubs that sit between user-mode software and the kernel. Security
tooling and malware alike care about these functions (e.g. *NTDLL unhooking*):

```text
NtOpenProcess            # open a process
NtAllocateVirtualMemory  # allocate memory
NtWriteVirtualMemory     # write to memory
NtCreateThreadEx         # start a thread in a remote process
```

## Useful standalone tools

- `procexp.exe` — Process Explorer (Sysinternals).
- [NirSoft](https://www.nirsoft.net/) — small free utilities (FullEventLogView,
  WinPrefetchView).
- [ShadowExplorer](https://www.shadowexplorer.com/) — browse Volume Shadow Copies.
- [Eric Zimmerman's tools](https://ericzimmerman.github.io/) — forensic parsers
  (AmcacheParser, RECmd, ShellBags Explorer, AppCompatCacheParser).
- [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) for detailed
  endpoint telemetry; Microsoft PowerToys for quality-of-life utilities.

## Security testing

Tools in this repo for assessing a Windows host or domain:

- **Active Directory** — [Responder](../active-directory/responder.md),
  [NetExec](../active-directory/netexec.md), [BloodHound](../active-directory/bloodhound.md),
  [Snaffler](../active-directory/snaffler.md), [PingCastle](../active-directory/pingcastle.md),
  and the full [Active Directory](../active-directory/) category.
- **Local privesc & post-exploitation** — [WinPEAS](../post-exploitation/linpeas-winpeas.md),
  [potato / SeImpersonate attacks](../post-exploitation/potato-attacks.md),
  [Seatbelt / PrivescCheck](../post-exploitation/windows-enum-tools.md),
  [Mimikatz](../post-exploitation/mimikatz.md).
- **Vuln scanning** — [OpenVAS](../vulnerability-scanners/openvas-greenbone.md) or
  [Nessus](../vulnerability-scanners/nessus.md).
- **Detection side** — [Sysmon](../defense-blueteam/sysmon.md) and the
  [Blue Team](../defense-blueteam/) category.
- **End-to-end** — the [Internal Network & AD](../scenarios/internal-network-ad.md) scenario.

## Notes & references

- Privilege-escalation background:
  <https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/>
- Diagnostic Data Viewer:
  <https://learn.microsoft.com/windows/privacy/diagnostic-data-viewer-overview>
- See [Linux](linux.md) for the Unix-side equivalents and
  [Defensive Security & Blue Team](../defense-blueteam/) for Sysmon-based
  detection.
