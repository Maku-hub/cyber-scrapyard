# jadx

> Dex-to-Java decompiler: turns an Android APK/DEX back into readable Java source,
> with a searchable GUI (`jadx-gui`) and a scriptable CLI.

- **Link:** https://github.com/skylot/jadx
- **Type:** open source
- **Platform:** cross-platform (Java 11+)

## Description

jadx is the go-to tool for reading what an Android app actually does. It
decompiles Dalvik bytecode into clean, mostly-compilable Java, reconstructs the
manifest and resources, and lets you jump-to-definition, search across the whole
app, and deobfuscate names. When you need to trace a login routine, find an API
key, or understand how a check is implemented before hooking it at runtime, you
open the APK in jadx first.

## Installation

```bash
# Package managers
brew install jadx                 # macOS/Linuxbrew
sudo apt install jadx             # Debian/Kali (may lag upstream)

# Or grab the release zip (contains jadx and jadx-gui launchers)
#   https://github.com/skylot/jadx/releases
```

## Usage examples

```bash
# Decompile an APK to Java sources in ./out
jadx app.apk -d out

# Open the interactive GUI for browsing/searching (best for exploration)
jadx-gui app.apk

# Also export resources and the decoded AndroidManifest.xml
jadx --export-gradle -d project app.apk

# Only extract sources for a single class/package (faster on big apps)
jadx app.apk -d out --classes com.example.app.auth

# Skip resource decoding when you only care about code
jadx --no-res app.apk -d out
```

## Notes & references

- The GUI's global search (Navigation → Text search) is the quickest way to find
  strings like `http`, `password`, `Base64`, or API keys.
- Decompilation isn't perfect on heavily obfuscated apps; use the built-in
  deobfuscation (`--deobf`) and fall back to smali via [Apktool](apktool.md).
- To confirm behaviour at runtime after reading the code, hook the app with
  [objection](objection.md) or [Frida](../reverse-engineering-malware/frida.md).
- Docs & FAQ: https://github.com/skylot/jadx/wiki
