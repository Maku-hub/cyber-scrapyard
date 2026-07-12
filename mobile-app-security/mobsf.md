# MobSF (Mobile Security Framework)

> All-in-one automated pen-testing framework for Android, iOS and Windows apps:
> static analysis, dynamic analysis, and a web dashboard that turns a raw APK/IPA
> into a readable security report.

- **Link:** https://github.com/MobSF/Mobile-Security-Framework-MobSF
- **Type:** open source
- **Platform:** cross-platform (Docker, or Python on Linux/Windows/macOS)

## Description

MobSF is usually the first thing you point at a mobile app. Upload an APK, IPA
or ZIP of source and it decompiles the binary, maps the manifest and permissions,
flags hardcoded secrets, insecure crypto and network config, and scores the app
against CWE/OWASP MASVS. The dynamic analyzer (Android VM/emulator or a rooted
device) instruments the running app with Frida to log API calls, capture traffic,
and bypass SSL pinning. It's the fastest way to get a broad, structured picture
before diving into manual work with jadx, objection or drozer.

## Installation

```bash
# Quickest: run the maintained Docker image and open http://localhost:8000
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest

# From source (needs Python 3.10+, JDK, and — for dynamic analysis — an Android SDK)
git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git
cd Mobile-Security-Framework-MobSF && ./setup.sh   # setup.bat on Windows
```

## Typical workflow

1. Start MobSF (`docker run ...`) and browse to `http://localhost:8000`.
2. **Drag-and-drop** an `.apk`, `.ipa`, or source `.zip` onto the upload box.
3. Read the **static report**: manifest analysis, permissions, code findings,
   hardcoded secrets, certificate/signing info, and the MASVS/CWE scorecard.
4. For **dynamic analysis**, attach a rooted Android device or the bundled
   emulator (Genymotion/AVD), launch the app, and use the live API monitor,
   HTTPS traffic capture, and one-click SSL-pinning bypass.
5. **Export** the findings as PDF/JSON, or drive it headless via the REST API
   (`/api/v1/upload` → `/api/v1/scan` → `/api/v1/report_json`) in CI.

## Notes & references

- Static analysis needs no device; dynamic analysis needs a rooted Android VM or
  device (iOS dynamic analysis requires a jailbroken device).
- The REST API + `mobsfscan` sibling project make it easy to gate builds in CI.
- Pair the decompiled output with [jadx](jadx.md) for deeper manual reading and
  [objection](objection.md) for interactive runtime work.
- Docs: https://mobsf.github.io/docs/
