# osquery

> Exposes the operating system as a relational database you query with SQL —
> processes, users, listening ports, packages, and more become tables.

- **Link:** https://github.com/osquery/osquery
- **Type:** open source
- **Platform:** cross-platform (Linux, Windows, macOS, FreeBSD)

## Description

osquery (originally from Facebook) turns endpoint state into SQL tables. Want to
know which processes have a network connection, which binaries have no owning
package, or which users have empty passwords? Write a `SELECT`. Run it
interactively with `osqueryi`, or run `osqueryd` as a daemon that executes
scheduled query packs and streams the differences — a powerful, low-noise source
of endpoint telemetry for detection, threat hunting, and compliance. Fleet
managers (Fleet, Kolide) let you query thousands of hosts at once.

## Installation

```bash
# Debian/Ubuntu (from the osquery apt repo) or download the .deb/.msi
sudo apt install osquery
```

## Usage examples

```sql
-- Interactive shell: list running processes with their command line
SELECT pid, name, path, cmdline FROM processes;
```

```sql
-- Open listening sockets joined to the owning process
SELECT p.name, l.address, l.port
FROM listening_ports l JOIN processes p ON l.pid = p.pid;
```

```sql
-- Logged-in users right now
SELECT user, host, time FROM logged_in_users;
```

```sql
-- Find processes running from an unusual path (outside /usr — possible malware)
SELECT name, path FROM processes WHERE on_disk = 1 AND path NOT LIKE '/usr/%';
```

```bash
# Run a single query from the CLI and get JSON out
osqueryi --json "SELECT * FROM os_version;"

# Run the daemon with a scheduled query pack
osqueryd --config_path=/etc/osquery/osquery.conf
```

## Notes & references

- Schema/table reference (the most useful bookmark): https://osquery.io/schema/
- `osqueryd` scheduled queries produce **diff** logs (added/removed rows) —
  perfect for feeding [Wazuh](wazuh.md) or a SIEM.
- Pairs with [Sysmon](sysmon.md) on Windows for even richer visibility.
- Use packs (osquery + Fleet) to standardise hunts across a fleet.
