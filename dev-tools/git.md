# Git

> The distributed version control system behind almost every open-source
> security tool — clone repos, track your scripts and notes, and roll back
> mistakes without fear.

- **Link:** https://git-scm.com
- **Type:** open source
- **Platform:** cross-platform

## Description

You'll use Git constantly in security work, even if you never "develop"
anything: cloning tools and exploit PoCs from GitHub, pulling updates, keeping
your own scripts and engagement notes under version control, and pinning a tool
to a known-good commit. Understanding a handful of commands means you can grab
the latest code, check what changed, undo edits safely, and share your own work.
It's the connective tissue of the whole ecosystem.

## Installation

```bash
sudo apt install git          # Debian/Kali/Ubuntu
```

## Usage examples

```bash
# One-time identity setup (used on every commit)
git config --global user.name "Your Name"
git config --global user.email "you@example.com"

# Clone a tool or PoC from GitHub
git clone https://github.com/gchq/CyberChef.git

# Clone a single branch shallowly (faster, less history)
git clone --depth 1 --branch main https://github.com/user/repo.git

# Start tracking your own notes/scripts
git init

# See what changed, then stage and commit
git status
git add notes.md scripts/
git commit -m "Add recon notes and helper script"

# Pull the latest changes for a cloned tool
git pull

# Pin a repo to a specific commit or tag (reproducible tooling)
git checkout v2.1.0

# Discard local edits to a file (careful — irreversible)
git checkout -- somefile.py

# View concise history
git log --oneline --graph --decorate
```

## Notes & references

- Free book (excellent, beginner → advanced): https://git-scm.com/book
- Command reference and man pages:
  https://git-scm.com/docs
- `git clone --recurse-submodules` when a tool bundles dependencies as
  submodules (common with C exploits and firmware repos).
- Keep secrets out of history — add a `.gitignore` and never commit keys,
  captures, or client data.
- Hosting platforms you'll clone from most: GitHub, GitLab, and Codeberg.
