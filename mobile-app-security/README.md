# Mobile Application Security

Tools for assessing the security of Android and iOS applications: decompiling and
reading app code, decoding and patching resources, scanning for leaked secrets,
and driving apps at runtime to bypass controls and observe behaviour. Most work
starts from an APK/IPA and moves from static analysis (what the app *contains*) to
dynamic analysis (what the app *does* while running).

## Tools

| Tool | Summary |
| --- | --- |
| [MobSF](mobsf.md) | Flagship all-in-one framework: automated static + dynamic analysis for Android/iOS with a web dashboard |
| [jadx](jadx.md) | Decompiles Android APK/DEX back to readable Java, with a searchable GUI |
| [Apktool](apktool.md) | Decodes and rebuilds APK resources and smali — the basis for manual patching/repackaging |
| [objection](objection.md) | Frida-powered runtime exploration: SSL-pinning/root bypass, hooking and sandbox access from a REPL |
| [drozer](drozer.md) | Assesses Android IPC/attack surface: exported activities, services, receivers and content providers |
| [APKLeaks](apkleaks.md) | Scans APKs for hardcoded secrets, URLs and API endpoints |
| [Frida](../reverse-engineering-malware/frida.md) | Dynamic instrumentation engine underpinning objection — hook and rewrite calls in a live app |

See also: [Android](../os-security/android.md) and [iOS](../os-security/ios.md)
for platform/OS-level hardening and device security, and
[Frida](../reverse-engineering-malware/frida.md) for low-level dynamic
instrumentation beyond what objection wraps.

## Mobile testing workflow

1. **Obtain the build** — pull the APK from the device
   (`adb shell pm path <pkg>` → `adb pull ...`) or use the IPA you're authorized
   to test.
2. **Automated first pass** — run [MobSF](mobsf.md) for a broad static report
   (manifest, permissions, secrets, MASVS scorecard).
3. **Read the code** — decompile with [jadx](jadx.md) to trace auth, crypto and
   network logic; scan strings with [APKLeaks](apkleaks.md) for keys/endpoints.
4. **Map the attack surface** — enumerate and exercise exported IPC components
   with [drozer](drozer.md).
5. **Patch or hook** — repackage statically with [Apktool](apktool.md), or hook
   at runtime with [objection](objection.md) /
   [Frida](../reverse-engineering-malware/frida.md) (bypass SSL pinning, then
   proxy traffic through Burp/ZAP).
6. **Confirm dynamically** — replay the finding against the running app and
   capture evidence.

> Educational and authorized use only: test apps you own or have explicit written
> permission to assess. Reverse-engineering and instrumenting third-party apps may
> breach their terms of service or local law.
