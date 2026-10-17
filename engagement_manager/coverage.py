"""Credential-spray coverage analysis.

A "gap" is a credential that has not been tried against a box it could reach,
either at all, or over a specific auth protocol the box exposes. We infer which
protocols a host exposes from its open ports, and which (credential, host, proto)
combinations have been attempted from the HostCredential links.
"""
from dataclasses import dataclass, field

from sqlmodel import Session, select

from .models import AccessLevel, Credential, Host

# Auth protocols NetExec/most sprays use, mapped to the ports that imply them.
AUTH_PROTOS: dict[str, set[int]] = {
    "smb": {445, 139},
    "winrm": {5985, 5986},
    "ssh": {22},
    "rdp": {3389},
    "mssql": {1433},
    "ldap": {389, 636},
    "ftp": {21},
    "wmi": {135},
}

_ALL = set(AUTH_PROTOS)
# Windows protocols that accept an NT/NTLM hash via pass-the-hash.
_PTH = {"smb", "winrm", "wmi", "mssql", "ldap", "rdp"}

# Which protocols a credential can actually authenticate to, by secret type.
# A plaintext password works almost everywhere; a hash cannot be used over SSH
# or FTP; an SSH key is SSH-only. "other" is left permissive so nothing hides.
PROTO_FOR_SECRET: dict[str, set[str]] = {
    "password": set(_ALL),
    "ntlm": set(_PTH),
    "nt_hash": set(_PTH),
    "lm_hash": set(_PTH),
    "kerberos": {"smb", "winrm", "wmi", "mssql", "ldap", "rdp"},
    "ssh_key": {"ssh"},
    "other": set(_ALL),
}


def usable_protocols(secret_type: str) -> set[str]:
    return PROTO_FOR_SECRET.get(secret_type, set(_ALL))


def host_protocols(host: Host) -> list[str]:
    """Protocols this host exposes, inferred from its open service ports."""
    open_ports = {s.port for s in host.services if s.state == "open"}
    return sorted(p for p, ports in AUTH_PROTOS.items() if ports & open_ports)


@dataclass
class Cell:
    status: str  # admin | user | fail | gap | na
    tried_protos: list[str] = field(default_factory=list)
    untried_protos: list[str] = field(default_factory=list)

    @property
    def partial(self) -> bool:
        # Untried protocols remain on a host we've touched — but admin is root,
        # so once this credential has admin here the rest isn't a gap worth the +.
        return self.status in ("user", "fail") and bool(self.untried_protos)


@dataclass
class GapItem:
    host: Host
    untried: list[str]
    untested: bool  # True = never tried on this host at all


@dataclass
class Coverage:
    hosts: list[Host]
    creds: list[Credential]
    host_protos: dict[int, list[str]]
    cells: dict[tuple[int, int], Cell]
    gaps: dict[int, list[GapItem]]  # credential id -> gap items
    untested_count: int  # (cred, host) never-tried combos where host is reachable
    partial_count: int   # combos tried but missing some protocols


def build_coverage(session: Session, engagement_id: int) -> Coverage:
    hosts = session.exec(
        select(Host).where(Host.engagement_id == engagement_id).order_by(Host.ip)
    ).all()
    creds = session.exec(
        select(Credential)
        .where(Credential.engagement_id == engagement_id)
        .order_by(Credential.domain, Credential.username)
    ).all()

    host_protos = {h.id: host_protocols(h) for h in hosts}
    cells: dict[tuple[int, int], Cell] = {}
    gaps: dict[int, list[GapItem]] = {c.id: [] for c in creds}
    untested_count = partial_count = 0

    admin_levels = {AccessLevel.admin, AccessLevel.domain_admin}

    # Hosts already owned at admin by *any* credential: there's nothing left to
    # spray there, so they're dropped from the gaps list (the matrix still shows
    # them). A host is owned once one credential proves admin / domain admin.
    owned_hosts = {
        host.id
        for host in hosts
        if any(
            hc.proven and hc.access_level in admin_levels
            for hc in host.host_credentials
        )
    }

    for cred in creds:
        # A cracked hash gives you the plaintext, so it reaches everywhere a
        # password does — not just the pass-the-hash protocols.
        if cred.cracked_encrypted:
            usable = set(_ALL)
        else:
            usable = usable_protocols(cred.secret_type.value)
        for host in hosts:
            # Only protocols the host exposes AND this credential type can use.
            applicable = sorted(set(host_protos[host.id]) & usable)
            links = [hc for hc in host.host_credentials if hc.credential_id == cred.id]
            tried_protos = sorted({hc.proto for hc in links if hc.proto})
            untried = sorted(set(applicable) - set(tried_protos))

            if not applicable and not links:
                status = "na"  # this credential type can't reach this host
            elif not links:
                status = "gap"
            elif any(l.proven and l.access_level in admin_levels for l in links):
                status = "admin"
            elif any(l.proven for l in links):
                status = "user"
            else:
                status = "fail"

            cell = Cell(status=status, tried_protos=tried_protos, untried_protos=untried)
            cells[(cred.id, host.id)] = cell

            # Owned boxes are done — keep them in the matrix but not in the gaps.
            if host.id in owned_hosts:
                continue

            if status == "gap":
                untested_count += 1
                gaps[cred.id].append(GapItem(host=host, untried=applicable, untested=True))
            elif cell.partial:
                partial_count += 1
                gaps[cred.id].append(GapItem(host=host, untried=untried, untested=False))

    return Coverage(
        hosts=hosts,
        creds=creds,
        host_protos=host_protos,
        cells=cells,
        gaps=gaps,
        untested_count=untested_count,
        partial_count=partial_count,
    )
