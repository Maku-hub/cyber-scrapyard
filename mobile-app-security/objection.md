# objection

> Frida-powered runtime mobile exploration: explore and manipulate Android/iOS apps
> from an interactive console — no jailbreak/root strictly required, no custom
> scripts to write for common tasks.

- **Link:** https://github.com/sensepost/objection
- **Type:** open source
- **Platform:** cross-platform host (targets Android & iOS)

## Description

objection wraps [Frida](../reverse-engineering-malware/frida.md) — the dynamic
instrumentation engine it runs on — in a friendly REPL so you don't have to write
JavaScript hooks for the common jobs. From one console you can bypass SSL pinning,
disable root/jailbreak detection, dump the keychain/keystore, list classes and
methods, hook functions, read files from the app sandbox, and watch method calls
live. It's the fastest path from "app is running" to "I can see and change what it
does at runtime."

## Installation

```bash
# Install via pipx (pulls in Frida as a dependency)
pipx install objection

# Android also needs a matching frida-server running on the device:
#   https://github.com/frida/frida/releases  (frida-server-<ver>-android-arm64)
adb push frida-server /data/local/tmp/ && adb shell "/data/local/tmp/frida-server &"
```

## Usage examples

```bash
# Attach to a running app and drop into the interactive console (USB device)
objection -g com.example.app explore

# Spawn the app fresh instead of attaching to a running instance
objection -g com.example.app explore --startup-command "android hooking watch class ..."
```

```text
# Inside the objection console:

# Disable common SSL certificate pinning implementations
android sslpinning disable

# Bypass root-detection checks
android root disable

# List the app's activities / dump loaded classes
android hooking list activities
android hooking list classes

# Watch every call to a method (with args/return) as it happens
android hooking watch class_method com.example.app.Login.check --dump-args --dump-return

# iOS equivalents
ios sslpinning disable
ios keychain dump
```

## Notes & references

- objection is a thin, task-oriented layer over Frida — anything it can't do,
  you can still script directly with [Frida](../reverse-engineering-malware/frida.md).
- Android needs a running `frida-server` (typically rooted device/emulator); iOS
  needs a jailbroken device with the Frida runtime.
- Great for a quick pinning bypass so you can proxy HTTPS traffic through Burp/ZAP.
- Docs & wiki: https://github.com/sensepost/objection/wiki
