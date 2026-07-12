# drozer

> Android attack-surface assessment framework: interact with an app's exported
> IPC endpoints — activities, services, broadcast receivers and content providers
> — the way a malicious app on the same device could.

- **Link:** https://github.com/WithSecureLabs/drozer
- **Type:** open source
- **Platform:** Linux/Windows/macOS console + an Android agent app

## Description

drozer probes what one app exposes to others through Android's IPC. From the
console you enumerate exported components, then poke at them: launch activities to
bypass auth screens, query content providers for SQL-injection or path-traversal,
send intents to receivers, and check for leaky permissions. It turns the vague
question "is this app's attack surface safe?" into concrete, repeatable
interactions, and is the standard tool for assessing exported-component and
provider security.

## Installation

```bash
# Console (Python) — install via pipx; grab the agent APK from releases
pipx install drozer
#   agent.apk: https://github.com/WithSecureLabs/drozer/releases

# Install the agent on the device and forward the drozer port
adb install agent.apk
adb forward tcp:31415 tcp:31415
```

## Usage examples

```bash
# Start the console session (open the Agent app + "Embedded Server" first)
drozer console connect
```

```text
# Inside the drozer console:

# Show the app's package info, permissions and exported components
run app.package.info -a com.example.app
run app.package.attacksurface com.example.app

# Enumerate exported activities and try launching one directly
run app.activity.info -a com.example.app
run app.activity.start --component com.example.app com.example.app.SecretActivity

# List content providers and query one (look for data leaks / SQLi)
run app.provider.info -a com.example.app
run app.provider.query content://com.example.app.provider/users
run scanner.provider.injection -a com.example.app

# Probe exported broadcast receivers and services
run app.broadcast.info -a com.example.app
run app.service.info -a com.example.app
```

## Notes & references

- Use the maintained WithSecure fork above; the original `mwrlabs` repo is archived.
- Content-provider modules (`scanner.provider.injection`,
  `scanner.provider.traversal`) are the highest-yield checks on most apps.
- Complements static review in [jadx](jadx.md): find an exported component in the
  manifest, then exercise it live with drozer.
- Docs: https://labs.withsecure.com/tools/drozer
