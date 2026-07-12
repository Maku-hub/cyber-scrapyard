# Misc Utilities

A short list of small, general-purpose tools that keep turning up in security
and lab work — for flashing microcontrollers, poking at databases, drawing
diagrams, remote access, comparing files, and unpacking archives.

## Arduino IDE

> The reference toolchain for programming microcontrollers.

- **Link:** https://www.arduino.cc/en/software
- **Type:** open source · cross-platform

Write, compile, and flash firmware to Arduino and compatible boards (including
the **ATmega32U4** boards used for [DIY BadUSB / HID injectors](../hardware/diy-alternatives.md)
and ESP8266/ESP32 projects). The go-to environment for the hardware DIY builds.

## DB Browser for SQLite

> A visual editor for SQLite database files.

- **Link:** https://sqlitebrowser.org
- **Type:** open source · cross-platform

Open, browse, query, and edit `.sqlite`/`.db` files without writing SQL by
hand. Handy for inspecting app data pulled from mobile/desktop apps, browser
history/credential stores, and CTF artifacts.

## draw.io (diagrams.net)

> Free diagramming for network maps and architecture.

- **Link:** https://www.drawio.com
- **Type:** free · web + desktop (Electron)

Sketch network topologies, attack paths, and infrastructure diagrams. Works
fully offline in the desktop app and stores diagrams as portable files.

## MobaXterm

> An all-in-one remote-access terminal for Windows.

- **Link:** https://mobaxterm.mobatek.net
- **Type:** freemium · Windows

Bundles SSH, RDP, VNC, SFTP, a tabbed terminal, an X11 server, and a bundled
Unix toolset in one app — a popular Windows jump-box for reaching lab machines.

## WinMerge

> Visual file and folder diff/merge for Windows.

- **Link:** https://winmerge.org
- **Type:** open source · Windows

Compare two files or directory trees side by side and merge differences. Useful
for spotting config drift, diffing captured artifacts, or reviewing what a
change touched.

## Notepad++

> A fast, lightweight text/code editor for Windows.

- **Link:** https://notepad-plus-plus.org
- **Type:** open source · Windows

Quickly open logs, configs, wordlist snippets, and captured artifacts with
syntax highlighting, powerful find/replace (regex), encoding conversion, and hex
plugins. A handy scratch editor when a full IDE is overkill.

## 7-Zip

> A high-ratio, format-omnivorous archiver.

- **Link:** https://www.7-zip.org
- **Type:** open source · Windows (p7zip/`7z` on Linux/macOS)

Extract and create archives across many formats (7z, zip, tar, gz, rar, iso,
and more). Indispensable for unpacking samples, wordlists, and firmware images;
supports password-protected archives.

```bash
# Extract an archive (Linux/macOS p7zip)
7z x firmware.zip

# List contents without extracting
7z l suspicious.7z
```
