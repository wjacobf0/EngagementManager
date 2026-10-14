"""Database models.

    Engagement                   -- one assessment; scopes everything below
      |- Host                    -- a target computer
      |    |- Service            -- an open port / service on that host
      |- Credential              -- a username + secret (encrypted at rest)
      |- ScanImport              -- a raw nmap/nxc upload + parsed summary
    HostCredential               -- which credential works on which host, and how
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


class ScanImport(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    engagement_id: int = Field(foreign_key="engagement.id", index=True)
    tool: str
    filename: Optional[str] = None
    raw: str
    summary: Optional[str] = None
    hosts_created: int = Field(default=0)
    hosts_updated: int = Field(default=0)
    imported_at: datetime = Field(default_factory=_utcnow)

    engagement: Optional[Engagement] = Relationship(back_populates="scans")
