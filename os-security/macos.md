# macOS

> A reference of the security mechanisms that define macOS — SIP, Gatekeeper,
> XProtect, TCC, notarization, and the Keychain — plus the administrative
> commands used to inspect them. Handy for system administration, endpoint
> hardening, and understanding where macOS draws its trust boundaries.
>
> ⚠️ **For authorized and educational use only.** Run these on machines you own
> or administer. The mechanisms are described so administrators and defenders
> understand the platform's protections and how to verify them.

## System Integrity Protection (SIP)

SIP ("rootless") restricts what even `root` can modify — protected system
locations (`/System`, `/usr`, `/bin`, `/sbin`), preinstalled apps, and
kernel-extension loading. It is a foundational boundary that stops malware (and
mistakes) from tampering with the OS.

```bash
# Check whether SIP is enabled
csrutil status
```

SIP can only be toggled from the Recovery environment (`csrutil enable/disable`),
never from a normally-booted system — which is itself a security property.

## Gatekeeper & quarantine

Gatekeeper enforces that downloaded software is signed and — for apps from
outside the App Store — **notarized** by Apple before it runs. Files downloaded
via browsers/mail receive a `com.apple.quarantine` extended attribute that
triggers the first-run check.

```bash
# Show global Gatekeeper assessment policy status
spctl --status

# Assess whether a specific app would be allowed to run, verbosely
spctl -a -vvv /Applications/Some.app

# Inspect the quarantine attribute on a downloaded file
xattr -p com.apple.quarantine ~/Downloads/installer.dmg
```

## Code signing & notarization

Every trusted executable is code-signed; notarization is an additional Apple
scan that staples a ticket to the app so Gatekeeper can verify it offline.

```bash
# Display the code signature, identifier, and signing authority of an app
codesign -dv --verbose=4 /Applications/Some.app

# Verify the notarization/Gatekeeper assessment of an installer
spctl -a -t install -vvv installer.pkg
```

## XProtect & malware defenses

macOS ships several built-in anti-malware components, updated silently by Apple:

- **XProtect** — signature-based blocking of known-bad software at launch.
- **XProtect Remediator (MRT successor)** — periodic background scanning and
  removal of detected malware.
- **Gatekeeper** — the trust/notarization gate described above.

```bash
# Show the installed XProtect data version (bundle metadata)
defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist CFBundleShortVersionString
```

## TCC — Transparency, Consent & Control

TCC is the privacy framework behind the permission prompts: an app must be
granted access to sensitive resources (camera, microphone, location, Full Disk
Access, screen recording, and protected folders like Documents/Desktop) by the
user. Grants are recorded in TCC databases (a user-level and a system-level one).

```bash
# Reset all TCC permission grants (forces prompts to appear again)
tccutil reset All

# Reset only a specific service, e.g. Camera access
tccutil reset Camera
```

## Keychain

The Keychain is the encrypted store for passwords, keys, certificates, and
secure notes, managed by the Security framework and unlocked with the user's
login password (backed by the Secure Enclave on Apple silicon).

```bash
# List the keychains on the search path
security list-keychains

# Show metadata for a stored item (does NOT print the secret)
security find-generic-password -l "ItemName"

# Lock the login keychain immediately
security lock-keychain login.keychain
```

## Useful administrative commands

```bash
# Full hardware/software profile (equivalent to About This Mac → System Report)
system_profiler SPHardwareDataType SPSoftwareDataType

# Detailed OS version and build
sw_vers

# FileVault full-disk-encryption status
fdesetup status

# Application firewall global state
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate

# List loaded third-party kernel/system extensions
systemextensionsctl list
kmutil showloaded --list-only
```

## Security testing

macOS-specific offensive tooling is thin, but from this repo:
[Frida](../reverse-engineering-malware/frida.md) and
[objection](../mobile-app-security/objection.md) instrument macOS apps at runtime;
[Ghidra](../reverse-engineering-malware/ghidra.md) and the
[RE & malware](../reverse-engineering-malware/) tools handle Mach-O reversing; and
[Semgrep](../vulnerability-scanners/semgrep.md) covers source review of macOS apps.

## Notes & references

- On Apple silicon, the **Secure Enclave**, boot security levels, and signed
  system volume (SSV) extend these protections further down the boot chain — see
  [iOS](ios.md) for the closely related Secure Enclave / secure-boot concepts.
- Full-disk encryption is **FileVault**; verify with `fdesetup status` before
  assuming a Mac is encrypted at rest.
- Official reference: Apple Platform Security guide —
  <https://support.apple.com/guide/security/welcome/web>
- See [Windows](windows.md) and [Linux](linux.md) for the equivalent references
  on the other platforms.
