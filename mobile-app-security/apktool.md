# Apktool

> Reverse-engineers Android APKs to near-original form — decodes resources and
> bytecode to smali, lets you patch them, and rebuilds a working (re-signable) APK.

- **Link:** https://github.com/iBotPeaches/Apktool
- **Type:** open source
- **Platform:** cross-platform (Java 8+)

## Description

Where jadx gives you readable Java to *understand* an app, Apktool gives you
editable smali and decoded resources to *change* it. It unpacks the
`AndroidManifest.xml`, `resources.arsc`, layouts and DEX into a folder tree you
can modify — flip a debuggable flag, patch a certificate-pinning check in smali,
tweak strings — then repackage it back into an APK. It's the backbone of manual
app patching and repackaging workflows.

## Installation

```bash
# Package managers
brew install apktool              # macOS/Linuxbrew
sudo apt install apktool          # Debian/Kali

# Or the wrapper script + jar from releases (recommended for latest version)
#   https://github.com/iBotPeaches/Apktool/releases
```

## Usage examples

```bash
# Decode an APK into smali + decoded resources (./app/)
apktool d app.apk -o app

# Decode without touching resources (faster, code-only edits)
apktool d --no-res app.apk -o app

# Rebuild the modified folder back into an APK
apktool b app -o app-patched.apk

# After rebuilding you MUST re-sign before installing on a device
apksigner sign --ks debug.keystore app-patched.apk

# Install shared framework resources (needed for some system/OEM APKs)
apktool if framework-res.apk
```

## Notes & references

- Rebuilt APKs are unsigned; sign with `apksigner` (or `jarsigner`) and align
  with `zipalign` before `adb install`.
- Common patch targets in smali: `android:debuggable`, network security config,
  and SSL-pinning routines — read the code in [jadx](jadx.md) first to locate them.
- For runtime patching instead of static repackaging, prefer
  [objection](objection.md) / [Frida](../reverse-engineering-malware/frida.md).
- Docs: https://apktool.org/docs/
