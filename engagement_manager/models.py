"""Database models.

    Engagement                   -- one assessment; scopes everything below
      |- Host                    -- a target computer
      |    |- Service            -- an open port / service on that host
      |- Credential              -- a username + secret (encrypted at rest)
      |- ScanImport              -- a raw nmap/nxc upload + parsed summary
    HostCredential               -- which credential works on which host, and how
    Reachability                 -- a reach edge: you get to host X *via* host Y
                                    (via = null means straight from the operator box)
"""
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from sqlmodel import Field, Relationship, SQLModel


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class EngagementStatus(str, Enum):
    planning = "planning"
    active = "active"
    reporting = "reporting"
    closed = "closed"


class HostStatus(str, Enum):
    unknown = "unknown"
    alive = "alive"
    down = "down"


class SecretType(str, Enum):
    password = "password"
    ntlm = "ntlm"
    nt_hash = "nt_hash"
    lm_hash = "lm_hash"
    kerberos = "kerberos"
    ssh_key = "ssh_key"
    other = "other"


class CredentialSource(str, Enum):
    manual = "manual"
    nxc = "nxc"
    dump = "dump"
    guess = "guess"
    other = "other"


class AccessLevel(str, Enum):
    none = "none"
    user = "user"
    admin = "admin"
    domain_admin = "domain_admin"


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Engagement(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    client: Optional[str] = None
    scope: Optional[str] = None
    status: EngagementStatus = Field(default=EngagementStatus.active)
    created_at: datetime = Field(default_factory=_utcnow)

    hosts: list["Host"] = Relationship(
        back_populates="engagement",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )
    credentials: list["Credential"] = Relationship(
        back_populates="engagement",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )
    scans: list["ScanImport"] = Relationship(
        back_populates="engagement",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )
    findings: list["Finding"] = Relationship(
        back_populates="engagement",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )


class Host(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    engagement_id: int = Field(foreign_key="engagement.id", index=True)
    ip: str = Field(index=True)
    hostname: Optional[str] = Field(default=None, index=True)
    os: Optional[str] = None
    domain: Optional[str] = Field(default=None, index=True)
    status: HostStatus = Field(default=HostStatus.unknown)
    tags: Optional[str] = None
    notes: Optional[str] = None
    first_seen: datetime = Field(default_factory=_utcnow)
    last_seen: datetime = Field(default_factory=_utcnow)

    # OSCP progress: a shell, the user flag, privesc, and the proof flag. The
    # flag fields hold the actual local.txt / proof.txt contents when captured.
    foothold: bool = Field(default=False)
    local_flag: Optional[str] = None
    rooted: bool = Field(default=False)
    proof_flag: Optional[str] = None

    engagement: Optional[Engagement] = Relationship(back_populates="hosts")
    services: list["Service"] = Relationship(
        back_populates="host",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )
    host_credentials: list["HostCredential"] = Relationship(
        back_populates="host",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )
    scripts: list["Script"] = Relationship(
        back_populates="host",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )
    evidence: list["Evidence"] = Relationship(
        back_populates="host",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )
    exploits: list["Exploit"] = Relationship(
        back_populates="host",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )


class Service(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    host_id: int = Field(foreign_key="host.id", index=True)
    port: int
    protocol: str = Field(default="tcp")
    state: str = Field(default="open")
    service_name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None

    host: Optional[Host] = Relationship(back_populates="services")


class Credential(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    engagement_id: int = Field(foreign_key="engagement.id", index=True)
    domain: Optional[str] = Field(default=None, index=True)
    username: str = Field(index=True)
    secret_encrypted: str  # ciphertext only; see crypto.py
    # Recovered plaintext for a hash credential (e.g. hashcat cracked the NTLM).
    # Lets one credential hold both the hash and the password it cracked to.
    cracked_encrypted: Optional[str] = None
    secret_type: SecretType = Field(default=SecretType.password)
    source: CredentialSource = Field(default=CredentialSource.manual)
    validated: bool = Field(default=False)
    notes: Optional[str] = None
    created_at: datetime = Field(default_factory=_utcnow)

    engagement: Optional[Engagement] = Relationship(back_populates="credentials")
    host_credentials: list["HostCredential"] = Relationship(
        back_populates="credential",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )


class HostCredential(SQLModel, table=True):
    """A credential proven (or attempted) against a host."""
    id: Optional[int] = Field(default=None, primary_key=True)
    host_id: int = Field(foreign_key="host.id", index=True)
    credential_id: int = Field(foreign_key="credential.id", index=True)
    access_level: AccessLevel = Field(default=AccessLevel.user)
    proven: bool = Field(default=True)
    proto: Optional[str] = None
    notes: Optional[str] = None
    created_at: datetime = Field(default_factory=_utcnow)

    host: Optional[Host] = Relationship(back_populates="host_credentials")
    credential: Optional[Credential] = Relationship(back_populates="host_credentials")


class Script(SQLModel, table=True):
    """A script or note attached to a host (e.g. a tunnel/pivot script)."""
    id: Optional[int] = Field(default=None, primary_key=True)
    host_id: int = Field(foreign_key="host.id", index=True)
    name: str
    description: Optional[str] = None
    filename: Optional[str] = None  # suggested download name
    content: str = ""
    created_at: datetime = Field(default_factory=_utcnow)

    host: Optional[Host] = Relationship(back_populates="scripts")


class Exploit(SQLModel, table=True):
    """An exploit used against a host, documented to OSCP report standard.

    Unmodified exploit  -> record only the title and the source `url`.
    Modified exploit     -> also record the modified `code`, the `shellcode_cmd`
    used to generate any shellcode, the `changes` made (highlighted), and the
    `explanation` of why. The report renders the two cases accordingly.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    host_id: int = Field(foreign_key="host.id", index=True)
    title: str
    url: Optional[str] = None       # source / original exploit location
    modified: bool = Field(default=False)
    code: Optional[str] = None      # modified exploit code (only if modified)
    shellcode_cmd: Optional[str] = None  # command used to generate shellcode
    changes: Optional[str] = None   # highlighted changes made
    explanation: Optional[str] = None    # why those changes were made
    created_at: datetime = Field(default_factory=_utcnow)

    host: Optional["Host"] = Relationship(back_populates="exploits")


class EvidenceKind(str, Enum):
    local = "local"    # local.txt proof screenshot
    proof = "proof"    # proof.txt proof screenshot
    other = "other"


class Evidence(SQLModel, table=True):
    """A proof screenshot attached to a host.

    The OSCP requires each local.txt / proof.txt to be shown in a screenshot
    that also shows the target's IP (ipconfig / ip addr) in the same frame.
    The image bytes live in the database (not on disk) so an engagement stays
    two portable files: copy engagement.db + secret.key and the proof comes too.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    host_id: int = Field(foreign_key="host.id", index=True)
    kind: EvidenceKind = Field(default=EvidenceKind.other)
    filename: Optional[str] = None
    content_type: str = Field(default="image/png")
    data: bytes = b""
    caption: Optional[str] = None
    created_at: datetime = Field(default_factory=_utcnow)

    host: Optional["Host"] = Relationship(back_populates="evidence")


class ReachMethod(str, Enum):
    direct = "direct"        # straight from the operator box, no tunnel
    ssh = "ssh"              # ssh -L / -D port forward
    socks = "socks"          # socks proxy (e.g. proxychains over a pivot)
    chisel = "chisel"
    ligolo = "ligolo"
    rdp = "rdp"
    other = "other"


class Reachability(SQLModel, table=True):
    """How a host was reached: directly, or tunneled through another host.

    `via_host_id` is the pivot you went through; null means you reached it
    straight from the operator/engagement box. The graph of these edges, rooted
    at the operator box, is the engagement's network topology.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    engagement_id: int = Field(foreign_key="engagement.id", index=True)
    host_id: int = Field(foreign_key="host.id", index=True)
    via_host_id: Optional[int] = Field(default=None, foreign_key="host.id", index=True)
    method: ReachMethod = Field(default=ReachMethod.direct)
    port: Optional[int] = None
    script_id: Optional[int] = Field(default=None, foreign_key="script.id")
    discovered_by_scan_id: Optional[int] = Field(default=None, foreign_key="scanimport.id")
    notes: Optional[str] = None
    created_at: datetime = Field(default_factory=_utcnow)


class Finding(SQLModel, table=True):
    """A vulnerability / finding, optionally tied to a host.

    Severity and the free-text fields map onto the usual report sections:
    `description` (what it is / impact) and `steps` (how it was exploited).
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    engagement_id: int = Field(foreign_key="engagement.id", index=True)
    host_id: Optional[int] = Field(default=None, foreign_key="host.id", index=True)
    title: str
    severity: Severity = Field(default=Severity.medium)
    description: Optional[str] = None
    steps: Optional[str] = None
    created_at: datetime = Field(default_factory=_utcnow)

    engagement: Optional[Engagement] = Relationship(back_populates="findings")
    host: Optional[Host] = Relationship()


class ScanImport(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    engagement_id: int = Field(foreign_key="engagement.id", index=True)
    tool: str
    vantage_host_id: Optional[int] = Field(default=None, foreign_key="host.id")
    filename: Optional[str] = None
    raw: str
    summary: Optional[str] = None
    hosts_created: int = Field(default=0)
    hosts_updated: int = Field(default=0)
    imported_at: datetime = Field(default_factory=_utcnow)

    engagement: Optional[Engagement] = Relationship(back_populates="scans")
