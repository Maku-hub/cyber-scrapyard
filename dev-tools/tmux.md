# tmux

> A terminal multiplexer: run many terminal sessions inside one window, split
> panes side by side, and — crucially — keep long-running jobs alive after you
> disconnect.

- **Link:** https://github.com/tmux/tmux
- **Type:** open source
- **Platform:** Linux / macOS / BSD (via WSL on Windows)

## Description

tmux lets you manage many command-line tasks in a single window — essential when
a test spawns several long-running processes. Detach from a session and it keeps
running on the server; reattach later (even from another machine over SSH) and
find everything exactly as you left it. That persistence alone makes it standard
kit for anyone working on remote boxes.

## Installation

```bash
sudo apt install tmux        # Debian/Kali/Ubuntu
```

## Usage examples

```bash
tmux              # start tmux
tmux new -s bob   # start a new named session "bob"
tmux a            # attach to the last session
tmux ls           # list sessions
```

### Key bindings

These notes assume the **prefix is remapped to `C-a` (Ctrl+a)** — closer to
`screen` — instead of the tmux default `C-b`. Press the prefix, release, then
the key:

```text
Ctrl+a c        # open a new window (tab)
Ctrl+a %        # split the pane vertically
Ctrl+a "        # split the pane horizontally
Ctrl+a <arrow>  # move between panes
Ctrl+a n        # next window
Ctrl+a p        # previous window
Ctrl+a <number> # jump to a specific window
Ctrl+a d        # detach (minimize) the session — it keeps running
Ctrl+a [        # copy mode — scroll back through output (press q to exit)
Ctrl+a z        # zoom the current pane (repeat to un-zoom)
```

## Notes & references

- To remap the prefix, add to `~/.tmux.conf`:
  ```text
  set -g prefix C-a
  unbind C-b
  bind C-a send-prefix
  ```
- Reload config without restarting: `tmux source-file ~/.tmux.conf`.
- Enable mouse mode with `set -g mouse on` for click-to-select panes and scroll.
- Manual: https://man.openbsd.org/tmux
