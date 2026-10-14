"""Scan ingestion shared by the web UI and the CLI.

Both the browser upload and `engagement-manager import ...` call these, so
parsing and merge behaviour stays identical regardless of entry point.
"""
from datetime import datetime, timezone

from sqlmodel import Session, select

from .crypto import encrypt_secret
from .models import (
    AccessLevel,
    Credential,
    CredentialSource,
    Host,
    HostCredential,
    HostStatus,
    Reachability,
    ReachMethod,
    ScanImport,
    SecretType,
    Service,
)
from .parsers.nmap import parse_nmap_xml
from .parsers.nxc import parse_nxc_output


def _get_or_create_host(session: Session, engagement_id: int, ip: str) -> tuple[Host, bool]:
    host = session.exec(
        select(Host).where(Host.engagement_id == engagement_id, Host.ip == ip)
    ).first()
    if host:
        return host, False
    host = Host(engagement_id=engagement_id, ip=ip)
    session.add(host)
    session.flush()
    return host, True


def _record_reach(
    session: Session,
    engagement_id: int,
    host_id: int,
    vantage_host_id: int | None,
    scan_id: int | None,
) -> None:
    """Ensure a reach edge from the scan's vantage to this host exists.

    A host scanned from the operator box (vantage None) is reachable directly; a
    host scanned from a pivot is reachable through it. We don't self-link a pivot
    to itself, and we don't duplicate an edge that's already recorded.
    """
    if host_id == vantage_host_id:
        return
    existing = session.exec(
        select(Reachability).where(
            Reachability.engagement_id == engagement_id,
            Reachability.host_id == host_id,
            Reachability.via_host_id == vantage_host_id,
        )
    ).first()
    if existing:
        return
    session.add(
        Reachability(
            engagement_id=engagement_id,
            host_id=host_id,
            via_host_id=vantage_host_id,
            method=ReachMethod.direct if vantage_host_id is None else ReachMethod.other,
            discovered_by_scan_id=scan_id,
        )
    )


def _guess_secret_type(secret: str) -> SecretType:
    if ":" in secret and all(len(p) == 32 for p in secret.split(":")[:2]):
        return SecretType.ntlm
    if len(secret) == 32 and all(c in "0123456789abcdefABCDEF" for c in secret):
        return SecretType.nt_hash
    return SecretType.password


def import_nmap(
    session: Session,
    engagement_id: int,
    raw: str,
    filename: str | None = None,
    vantage_host_id: int | None = None,
) -> ScanImport:
    parsed_hosts = parse_nmap_xml(raw)
    created = updated = 0
    touched: list[int] = []
    for ph in parsed_hosts:
        host, is_new = _get_or_create_host(session, engagement_id, ph.ip)
        created += is_new
        updated += not is_new
        touched.append(host.id)
        if ph.hostname:
            host.hostname = ph.hostname
        if ph.os:
            host.os = ph.os
        if ph.status in HostStatus.__members__:
            host.status = HostStatus(ph.status)
        host.last_seen = datetime.now(timezone.utc)

        existing = {(s.port, s.protocol) for s in host.services}
        for svc in ph.services:
            if (svc.port, svc.protocol) in existing:
                continue
            session.add(
                Service(
                    host_id=host.id,
                    port=svc.port,
                    protocol=svc.protocol,
                    state=svc.state,
                    service_name=svc.service_name,
                    product=svc.product,
                    version=svc.version,
                    banner=svc.banner,
                )
            )

    summary = f"Parsed {len(parsed_hosts)} host(s): {created} new, {updated} updated."
    record = ScanImport(
        engagement_id=engagement_id,
        tool="nmap",
        vantage_host_id=vantage_host_id,
        filename=filename,
        raw=raw,
        summary=summary,
        hosts_created=created,
        hosts_updated=updated,
    )
    session.add(record)
    session.flush()
    for host_id in touched:
        _record_reach(session, engagement_id, host_id, vantage_host_id, record.id)
    session.commit()
    session.refresh(record)
    return record


def import_nxc(
    session: Session,
    engagement_id: int,
    raw: str,
    filename: str | None = None,
    vantage_host_id: int | None = None,
) -> ScanImport:
    parsed = parse_nxc_output(raw)
    created = updated = 0
    touched: list[int] = []
    for ip, ph in parsed.hosts.items():
        host, is_new = _get_or_create_host(session, engagement_id, ip)
        created += is_new
        updated += not is_new
        touched.append(host.id)
        if ph.hostname:
            host.hostname = ph.hostname
        if ph.domain:
            host.domain = ph.domain
        if ph.os:
            host.os = ph.os
        host.status = HostStatus.alive
        host.last_seen = datetime.now(timezone.utc)

    creds_added = 0
    for auth in parsed.auths:
        host = session.exec(
            select(Host).where(Host.engagement_id == engagement_id, Host.ip == auth.ip)
        ).first()
        cred = session.exec(
            select(Credential).where(
                Credential.engagement_id == engagement_id,
                Credential.username == auth.username,
                Credential.domain == auth.domain,
            )
        ).first()
        if not cred:
            cred = Credential(
                engagement_id=engagement_id,
                domain=auth.domain,
                username=auth.username,
                secret_encrypted=encrypt_secret(auth.secret),
                secret_type=_guess_secret_type(auth.secret),
                source=CredentialSource.nxc,
                validated=True,
            )
            session.add(cred)
            session.flush()
            creds_added += 1
        if host:
            session.add(
                HostCredential(
                    host_id=host.id,
                    credential_id=cred.id,
                    access_level=AccessLevel.admin if auth.admin else AccessLevel.user,
                    proven=True,
                    proto=auth.proto,
                )
            )

    summary = (
        f"Parsed {len(parsed.hosts)} host(s): {created} new, {updated} updated; "
        f"{creds_added} new credential(s), {len(parsed.auths)} auth result(s)."
    )
    record = ScanImport(
        engagement_id=engagement_id,
        tool="nxc",
        vantage_host_id=vantage_host_id,
        filename=filename,
        raw=raw,
        summary=summary,
        hosts_created=created,
        hosts_updated=updated,
    )
    session.add(record)
    session.flush()
    for host_id in touched:
        _record_reach(session, engagement_id, host_id, vantage_host_id, record.id)
    session.commit()
    session.refresh(record)
    return record
