# Android

> How Android boots, the security mechanisms that isolate apps and protect data,
> and what rooting actually changes. Reference notes for understanding the
> platform's security model.
>
> ⚠️ **For authorized and educational use only.** Analyse devices and apps you
> own or are permitted to test.

## Boot chain

Each stage verifies and hands off to the next, forming a chain of trust:

1. **BootROM** — read-only code hard-wired into the chip; the start of the
   root-of-trust. Immutable in theory.
2. **Bootloader** — vendor-supplied code (not part of Android itself). It locates
   the OS to boot, loads the Linux kernel, and starts the Trusted Execution
   Environment (TEE; e.g. Trusty on Pixel, QSEE/Kinibi on others). *Unlocking* the
   bootloader disables signature
   verification of the loaded software — a key prerequisite for easy rooting.
3. **Kernel** — the Linux-based core layer between the OS and hardware; manages
   processes, memory, filesystems, and permissions.
4. **Init** — the first key userspace process; defines the initial actions and
   directories and loads config for system services (bluetooth, networking, …).
5. **Zygote** — manages app startup in a client-server model. Every app is a
   `fork` of the base Zygote process, launched via the `/dev/socket/zygote`
   socket.
6. **System** — `SystemServer` loads the core system services, then the UI and
   remaining components come up.

```bash
# Device logs, and just the SystemServer entries
adb logcat
adb logcat | grep SystemServer
```

## Security mechanisms

**SELinux** — tightly scopes what each process may do and denies access to
anything beyond its needs, enforced through Mandatory Access Control (MAC)
policies stored in `/system/etc/selinux/`.

```bash
# Watch SELinux access-control decisions (denials)
adb logcat | grep "avc:"
```

**Sandbox** — every installed app runs as its own Linux user, with default access
only to its private "home" directory plus basic system services.

**Data encryption:**

- **FDE (Full Disk Encryption)** — Android 5.0–9.0. One key for everything; hence
  services could not run before the first unlock after a reboot.
- **FBE (File-Based Encryption)** — introduced in Android 7, mandatory from
  Android 10. Each file encrypted with its own key, split into two storage areas:
  - **Device Encrypted Storage** — available before the first unlock after reboot
    (keys derived from the device's unique ID / UID).
  - **Credential Encrypted Storage** — available only after the first unlock (keys
    derived from UID + the unlock PIN).

## Root & Magisk

Rooting requires an unlocked bootloader. The most popular solution is
[Magisk](https://github.com/topjohnwu/Magisk), which works by modifying the boot
image (`boot.img`) loaded during startup, granting root while keeping the change
relatively contained ("systemless" root).

## Security testing

App-level testing tools live in the [Mobile App Security](../mobile-app-security/)
category: [MobSF](../mobile-app-security/mobsf.md) (automated static + dynamic),
[jadx](../mobile-app-security/jadx.md) + [apktool](../mobile-app-security/apktool.md)
(decompile/rebuild), [Drozer](../mobile-app-security/drozer.md) (IPC/attack surface),
[objection](../mobile-app-security/objection.md) +
[Frida](../reverse-engineering-malware/frida.md) (runtime instrumentation), and
[APKLeaks](../mobile-app-security/apkleaks.md) (secret discovery in APKs).

## Notes & references

- App manifest reference:
  <https://developer.android.com/guide/topics/manifest/manifest-intro>
- SELinux validation:
  <https://source.android.com/docs/security/features/selinux/validate>
- Direct Boot (FBE storage areas):
  <https://developer.android.com/training/articles/direct-boot>
- Monthly Android security bulletins:
  <https://source.android.com/docs/security/bulletin/>
- Drozer (app analysis) and Dirty COW rooting write-ups on sekurak.pl *(Polish)*;
  APKLeaks for secret discovery in APKs.
- See [iOS](ios.md) for the comparable Apple model.
