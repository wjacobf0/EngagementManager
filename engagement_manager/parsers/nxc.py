"""Parse NetExec / CrackMapExec console output lines into host + auth records.

NetExec's line format is roughly:
    SMB  10.0.0.5  445  DC01  [*] Windows 10.0 x64 (name:DC01) (domain:corp.local)
    SMB  10.0.0.5  445  DC01  [+] corp.local\\admin:P@ss  (Pwn3d!)

This parser is line-oriented and tolerant: it extracts what it can and
ignores lines it does not recognise. It covers the common SMB/WINRM/SSH
forms; exotic modules may not match, which is fine for an import aid.
"""
import re
from dataclasses import dataclass, field

# Leading protocol, IP, port, hostname columns.
_HEADER = re.compile(
    r"^(?P<proto>\w+)\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?P<port>\d+)\s+(?P<host>\S+)\s+(?P<rest>.*)$"
)
_DOMAIN_INFO = re.compile(r"\(domain:(?P<domain>[^)]+)\)")
_OS_INFO = re.compile(r"\[\*\]\s+(?P<os>.+?)\s+\(name:")
# [+] success or [-] failure, then domain\user:secret, optionally (Pwn3d!).
# Both are captured so the matrix can tell "tried and failed" from "never tried".
_CRED = re.compile(
    r"\[(?P<result>[+\-])\]\s+(?:(?P<domain>[^\\\s]+)\\)?(?P<user>[^:\s]+):(?P<secret>\S+)(?P<pwned>.*)$"
)


@dataclass
class ParsedAuth:
    ip: str
    proto: str
    domain: str | None
    username: str
    secret: str
    success: bool  # [+] succeeded vs [-] failed
    admin: bool  # Pwn3d! => admin on this host


@dataclass
class ParsedNxcHost:
    ip: str
    hostname: str | None = None
    domain: str | None = None
    os: str | None = None


@dataclass
class ParsedNxc:
    hosts: dict[str, ParsedNxcHost] = field(default_factory=dict)
    auths: list[ParsedAuth] = field(default_factory=list)


def parse_nxc_output(text: str) -> ParsedNxc:
    result = ParsedNxc()

    for raw_line in text.splitlines():
        line = _strip_ansi(raw_line).strip()
        if not line:
            continue
        m = _HEADER.match(line)
        if not m:
            continue

        ip = m.group("ip")
        proto = m.group("proto").lower()
        host = m.group("host")
        rest = m.group("rest")

        entry = result.hosts.setdefault(ip, ParsedNxcHost(ip=ip))
        if host and host != ip:
            entry.hostname = host

        dom = _DOMAIN_INFO.search(rest)
        if dom:
            entry.domain = dom.group("domain")

        os_m = _OS_INFO.search(rest)
        if os_m:
            entry.os = os_m.group("os").strip()

        cred_m = _CRED.search(rest)
        if cred_m:
            success = cred_m.group("result") == "+"
            result.auths.append(
                ParsedAuth(
                    ip=ip,
                    proto=proto,
                    domain=cred_m.group("domain"),
                    username=cred_m.group("user"),
                    secret=cred_m.group("secret"),
                    success=success,
                    admin=success and "pwn3d" in cred_m.group("pwned").lower(),
                )
            )

    return result


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(s: str) -> str:
    return _ANSI.sub("", s)
