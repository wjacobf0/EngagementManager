# Engagement Manager

A local, **Python-only** tool for keeping track of a penetration test: hosts,
services, users, credentials (passwords and hashes), and the output of `nmap`
and NetExec (`nxc`) scans. No Node, no Docker, no database server. It runs on
Kali with a single `pipx install` and one command, stores everything in a local
SQLite file, and opens a web UI in your browser.

> For authorized assessments only. This is record-keeping for tests you already
> have permission to run.

## Why it stays out of your way

- **One install, one command.** `pipx install .` then `engagement-manager`.
- **Runs on localhost.** Binds to `127.0.0.1` by default; nothing is exposed.
- **Zero config.** The SQLite database and a per-user encryption key are created
  automatically on first run under `~/.local/share/engagement-manager/`.
- **Terminal-first import.** Pipe your scans straight in without opening the UI.
- **Secrets encrypted at rest.** Captured passwords and hashes are Fernet-
  encrypted before they touch the database.

## Install

```bash
# from the project directory, on Kali
pipx install .          # or: pip install --user .
```

This gives you two commands: `engagement-manager` and the short alias `em`.

For development: `python3 -m venv .venv && . .venv/bin/activate && pip install -e .`

Runs on Python 3.11 through 3.14. Kali's system Python works as-is.

## Use it

### Web UI

```bash
engagement-manager          # starts the server and opens your browser
engagement-manager serve --no-open --port 8000   # headless / custom port
```

Create an engagement, then add hosts and credentials or import scans. The active
engagement is remembered across pages and shown in the top selector.

### Import scans from the terminal

```bash
# nmap: produce XML with -oX, then import it
nmap -oX acme.xml 10.0.0.0/24
engagement-manager import nmap acme.xml -e "ACME Internal"

# NetExec: redirect console output to a file, then import it
nxc smb 10.0.0.0/24 -u users.txt -p passwords.txt | tee acme-nxc.txt
engagement-manager import nxc acme-nxc.txt -e "ACME Internal"
```

The engagement is created automatically if the name is new. Re-importing merges
by IP, so running the same scan twice updates hosts instead of duplicating them.
NetExec lines ending in `Pwn3d!` are recorded as admin access on that host.

### Other commands

```bash
engagement-manager engagements   # list engagements
engagement-manager where         # print the data directory, db, and key paths
```

## What gets parsed

- **nmap XML** (`nmap -oX`): hosts, status, hostname, OS guess, and open
  ports with service/product/version. Parsed with `defusedxml` so malformed or
  hostile scan files cannot trigger XXE.
- **NetExec / CrackMapExec** console output: hosts, domain, OS banner, and
  `domain\user:secret` results, including which succeeded and where they gained
  admin. Hashes vs. passwords are detected heuristically.

## Where your data lives

```
~/.local/share/engagement-manager/
├── engagement.db     SQLite database (all engagements)
└── secret.key        Fernet encryption key, created at 0600
```

Override the location with `EM_DATA_DIR=/path`. Back up both files together: the
database is useless without the key, and losing the key makes stored secrets
unrecoverable. To move an engagement to another machine, copy both files.

## Data model

```
Engagement                   one assessment; scopes everything below
  Host                       a target computer (IP, hostname, OS, domain, tags)
    Service                  an open port / service on that host
  Credential                 username + secret (Fernet-encrypted at rest)
  ScanImport                 raw nmap/nxc upload + parsed summary
HostCredential               a credential proven against a host, with access level
```

## Security notes

- Designed to run on your own machine, bound to localhost. There is no login,
  because the tool assumes the local user is you. Do not expose the port to a
  network; put it behind SSH or a reverse proxy with auth if you must reach it
  remotely.
- Captured secrets are encrypted at rest with Fernet (AES-128-CBC + HMAC). They
  are decrypted only when rendered in the UI, on your local machine.
- The key file is written with owner-only permissions.

## Extending it

The parsers in `engagement_manager/parsers/` are plain functions independent of
the web layer, so adding a format (Nessus `.nessus`, masscan, BloodHound) is a
new parser plus a few lines in `ingest.py`. Natural next features the schema
already supports: findings/vulnerabilities per host, evidence attachments, and
report export.
