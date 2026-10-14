# Engagement Manager

A local, **Python-only** tool for keeping track of a penetration test: hosts,
services, users, credentials (passwords and hashes), and the output of `nmap`
and NetExec (`nxc`) scans. No Node, no Docker, no database server. It runs on
Kali or Windows with a single `pipx install` and one command, stores everything
in a local SQLite file, and opens a web UI in your browser.

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

Runs on Python 3.11 through 3.14. Either path gives you two commands:
`engagement-manager` and the short alias `em`.

### Linux (Kali)

```bash
# from the project directory
pipx install .          # or: pip install --user .
```

Kali's system Python works as-is.

For development:

```bash
python3 -m venv .venv && . .venv/bin/activate && pip install -e .
```

### Windows

```powershell
# from the project directory, in PowerShell
py -m pip install --user pipx     # skip if pipx is already installed
py -m pipx ensurepath             # adds pipx + installed apps to PATH
py -m pipx install .
```

`py -m pipx` works immediately; the bare `pipx`, `engagement-manager`, and `em`
commands become available after you open a **new** terminal (the `ensurepath`
PATH change doesn't apply to the terminal you ran it in).

For development, use the venv's interpreter directly — no activation needed:

```powershell
py -m venv .venv
.venv\Scripts\python.exe -m pip install -e .
.venv\Scripts\engagement-manager.exe where   # run it from the venv
```

(`.venv\Scripts\Activate.ps1` also works, but fails with a "not digitally
signed" error if your execution policy is `AllSigned` or `Restricted`; either
use the direct paths above or run
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once.)

## Use it

### Web UI

```bash
engagement-manager          # starts the server and opens your browser
engagement-manager serve --no-open --port 8000   # headless / custom port
```

Create an engagement, then add hosts and credentials or import scans. The active
engagement is remembered across pages and shown in the top selector.

### Import scans from the terminal

On Linux (Kali):

```bash
# nmap: produce XML with -oX, then import it
nmap -oX acme.xml 10.0.0.0/24
engagement-manager import nmap acme.xml -e "ACME Internal"

# NetExec: redirect console output to a file, then import it
nxc smb 10.0.0.0/24 -u users.txt -p passwords.txt | tee acme-nxc.txt
engagement-manager import nxc acme-nxc.txt -e "ACME Internal"
```

On Windows the same commands work, with one catch: the importer expects UTF-8,
and Windows PowerShell 5.1's `tee` and `>` write UTF-16 by default. Save the
NetExec output with an explicit encoding instead:

```powershell
nmap -oX acme.xml 10.0.0.0/24
engagement-manager import nmap acme.xml -e "ACME Internal"

nxc smb 10.0.0.0/24 -u users.txt -p passwords.txt | Out-File -Encoding utf8 acme-nxc.txt
engagement-manager import nxc acme-nxc.txt -e "ACME Internal"
```

(PowerShell 7+ and `cmd.exe` redirection write UTF-8 already, so plain `tee` or
`>` is fine there.)

The engagement is created automatically if the name is new. Re-importing merges
by IP, so running the same scan twice updates hosts instead of duplicating them.
NetExec lines ending in `Pwn3d!` are recorded as admin access on that host.

### Topology and pivots

A scan run straight from your box reaches hosts directly; a scan you run after
tunneling through a foothold reaches the hosts behind it. Tell the importer
where a scan was run from and it records that reachability for you:

```bash
# scanned directly from your operator box (the default)
engagement-manager import nmap acme.xml -e "ACME Internal"

# scanned after tunneling through a pivot (by IP or host id)
engagement-manager import nmap internal.xml -e "ACME Internal" --from 10.0.0.5
```

The **Topology** page then draws the reach graph rooted at your operator box,
laid out by hop count: directly reachable hosts in the first rank, hosts behind
a pivot in the next, with the pivot marked and each tunnel labeled by method.
Pivots with no recorded inbound path are attached to the operator with a dashed
"assumed" edge so nothing behind them disappears. In the web UI the same
"Scanned from" choice appears on the import dialog, and each host page lists and
lets you edit how that host is reached.

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

On Linux (respects `XDG_DATA_HOME`):

```
~/.local/share/engagement-manager/
├── engagement.db     SQLite database (all engagements)
└── secret.key        Fernet encryption key, created at 0600
```

On Windows:

```
C:\Users\<you>\.local\share\engagement-manager\
├── engagement.db     SQLite database (all engagements)
└── secret.key        Fernet encryption key
```

Override the location with the `EM_DATA_DIR` environment variable —
`EM_DATA_DIR=/path engagement-manager` on Linux, or
`$env:EM_DATA_DIR = "D:\path"` in PowerShell before launching. Back up both
files together: the database is useless without the key, and losing the key
makes stored secrets unrecoverable. To move an engagement to another machine
(including Linux ↔ Windows), copy both files.

`engagement-manager where` prints the paths in use on either platform.

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
- The key file is written with owner-only permissions (0600) on Linux. On
  Windows it relies on the NTFS ACLs of your user profile directory, which
  already restrict access to your account.

## Extending it

The parsers in `engagement_manager/parsers/` are plain functions independent of
the web layer, so adding a format (Nessus `.nessus`, masscan, BloodHound) is a
new parser plus a few lines in `ingest.py`. Natural next features the schema
already supports: findings/vulnerabilities per host, evidence attachments, and
report export.
