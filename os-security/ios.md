# iOS

> How iOS boots, the hardware and software mechanisms that isolate apps and
> protect data, and what jailbreaking involves. Reference notes on Apple's mobile
> security model.
>
> ⚠️ **For authorized and educational use only.** Analyse devices and apps you
> own or are permitted to test.

## Boot chain

A verified chain of trust, similar in spirit to [Android](android.md):

1. **BootROM** — read-only code hard-wired into the chip; the start of the
   root-of-trust. Immutable in theory.
2. **LLB (Low-Level Bootloader)** — on older SoCs, a transitional stage before
   iBoot; performs early boot operations and verifies the signature of the next
   stage.
3. **iBoot** — the second-stage bootloader that loads the operating system.
   Recovery mode is reached from here.
4. **Kernel** — loads the XNU kernel (hybrid Mach microkernel + BSD, the core of
   Darwin).
5. Remaining iOS components load.

## Security mechanisms

**Secure Enclave** — a separate, parallel coprocessor isolated from the main
application processor, designed to store sensitive device data safely even if the
main processor is compromised. It runs its own low-level OS, `sepOS`.

**Sandbox** — each app runs in its own isolated container. Unlike Android, apps
are installed by the `installd` user and run as the `mobile` user, rather than
each app getting its own user.

**Data Protection Classes** — developers can choose the encryption/availability
level for their app's files (e.g. accessible only after first unlock).

## Jailbreaking

Gaining root on iOS requires chaining a privilege-escalation exploit. Notable
tools by era:

- **Checkra1n** (<https://checkra.in/>, checkm8-based, bound to A5–A11 hardware)
  and **Unc0ver** (<https://unc0ver.dev/>, up to ~iOS 14.x).
- **Palera1n** (<https://github.com/palera1n/palera1n>) — currently the working
  option for iOS 15+.

## Security testing

For iOS app assessment see the [Mobile App Security](../mobile-app-security/)
category — especially [objection](../mobile-app-security/objection.md) and
[Frida](../reverse-engineering-malware/frida.md) for runtime instrumentation on a
jailbroken device, and [MobSF](../mobile-app-security/mobsf.md) for automated
static/dynamic analysis of IPAs.

## Notes & references

- The 0-day acquisition market drives much iOS exploitation — e.g. Zerodium
  (<https://zerodium.com/program.html>) buys exploits for advanced spyware.
- See [Android](android.md) for a side-by-side comparison of the two mobile
  security models.
