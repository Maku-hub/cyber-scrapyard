# Visual Studio Code

> A free, cross-platform, heavily extensible code editor — the default
> workbench for writing scripts, keeping notes, editing configs, and remoting
> into lab machines.

- **Link:** https://code.visualstudio.com
- **Type:** free (open-source core, "Code - OSS")
- **Platform:** cross-platform (Windows / Linux / macOS)

## Description

VS Code sits between a plain text editor and a full IDE: fast to start, but with
an enormous extension marketplace that adds language support, linters,
debuggers, containers, and remote development. For security work it's handy for
Python/Bash tooling, reviewing source during code audits, editing YAML/JSON
configs, and — via Remote-SSH — working directly on a lab box or VM.

## Installation

```bash
# Debian/Kali/Ubuntu (Microsoft apt repo), or download the .deb from the site
sudo apt install code

# Windows: winget
winget install Microsoft.VisualStudioCode
```

## Usage examples

```bash
# Open the current directory as a workspace
code .

# Open a specific file at a line number
code -g script.py:42

# Install an extension from the CLI
code --install-extension ms-python.python

# Edit files on a remote lab box (needs the Remote - SSH extension)
code --remote ssh-remote+labuser@10.0.0.5 /home/labuser
```

## Notes & references

- Useful extensions: **Remote - SSH** (edit files on remote hosts), **Python**,
  **hexdump / Hex Editor**, **Even Better TOML/YAML**, **GitLens**.
- Integrated terminal (`` Ctrl+` ``) keeps your shell next to the code.
- Fully open-source builds without Microsoft telemetry: **VSCodium**
  (https://vscodium.com).
- Docs: https://code.visualstudio.com/docs
