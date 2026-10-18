"""Server-rendered FastAPI app. No build step, no JavaScript framework.

Runs as a single local process backed by SQLite. The active engagement is
remembered in a cookie so links and forms stay clean.
"""
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select

from .crypto import decrypt_secret, encrypt_secret
from .database import get_session, init_db
from .ingest import import_nmap, import_nxc
from .models import (
    _utcnow,
    AccessLevel,
    Credential,
    CredentialSource,
    Engagement,
    Evidence,
    EvidenceKind,
    Exploit,
    Finding,
    Host,
    HostCredential,
    Reachability,
    ReachMethod,
    ScanImport,
    Script,
    SecretType,
    Service,
    Severity,
)

BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

app = FastAPI(title="Engagement Manager")
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

COOKIE = "em_eng"


@app.on_event("startup")
def _startup() -> None:
    init_db()


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _engagements(session: Session) -> list[Engagement]:
    return session.exec(select(Engagement).order_by(Engagement.created_at.desc())).all()


def _active_engagement(request: Request, session: Session) -> Optional[Engagement]:
    """Resolve the active engagement from the cookie, else the newest one."""
    raw = request.cookies.get(COOKIE)
    if raw and raw.isdigit():
        eng = session.get(Engagement, int(raw))
        if eng:
            return eng
    return next(iter(_engagements(session)), None)


def _ctx(request: Request, session: Session, **extra):
    engagements = _engagements(session)
    active = _active_engagement(request, session)
    return {
        "request": request,
        "engagements": engagements,
        "active": active,
        **extra,
    }


# --------------------------------------------------------------------------- #
# Engagements
# --------------------------------------------------------------------------- #
@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, session: Session = Depends(get_session)):
    active = _active_engagement(request, session)
    stats = None
    if active:
        hosts = session.exec(select(Host).where(Host.engagement_id == active.id)).all()
        creds = session.exec(
            select(Credential).where(Credential.engagement_id == active.id)
        ).all()
        open_ports = sum(len(h.services) for h in hosts)
        stats = {
            "hosts": len(hosts),
            "alive": sum(1 for h in hosts if h.status.value == "alive"),
            "open_ports": open_ports,
            "creds": len(creds),
            "validated": sum(1 for c in creds if c.validated),
            "rooted": sum(1 for h in hosts if h.proof_flag or h.rooted),
        }
    return templates.TemplateResponse(
        request, "dashboard.html", _ctx(request, session, stats=stats)
    )


@app.post("/engagements")
def create_engagement(
    name: str = Form(...),
    client: str = Form(""),
    scope: str = Form(""),
    session: Session = Depends(get_session),
):
    eng = Engagement(name=name.strip(), client=client or None, scope=scope or None)
    session.add(eng)
    session.commit()
    session.refresh(eng)
    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie(COOKIE, str(eng.id), httponly=True, samesite="lax")
    return resp


@app.get("/select/{engagement_id}")
def select_engagement(engagement_id: int, request: Request):
    resp = RedirectResponse(request.headers.get("referer", "/"), status_code=303)
    resp.set_cookie(COOKIE, str(engagement_id), httponly=True, samesite="lax")
    return resp


@app.post("/engagements/{engagement_id}/delete")
def delete_engagement(
    engagement_id: int, request: Request, session: Session = Depends(get_session)
):
    eng = session.get(Engagement, engagement_id)
    if eng:
        session.delete(eng)  # cascades to hosts, services, creds, scans, scripts
        session.commit()
    resp = RedirectResponse("/", status_code=303)
    # Drop the cookie if it pointed at the engagement we just removed.
    if request.cookies.get(COOKIE) == str(engagement_id):
        resp.delete_cookie(COOKIE)
    return resp


# --------------------------------------------------------------------------- #
# Hosts
# --------------------------------------------------------------------------- #
@app.get("/hosts", response_class=HTMLResponse)
def hosts_page(request: Request, session: Session = Depends(get_session)):
    active = _active_engagement(request, session)
    hosts = []
    if active:
        hosts = session.exec(
            select(Host).where(Host.engagement_id == active.id).order_by(Host.ip)
        ).all()
    return templates.TemplateResponse(request, "hosts.html", _ctx(request, session, hosts=hosts))


@app.post("/hosts")
def add_host(
    request: Request,
    ip: str = Form(...),
    hostname: str = Form(""),
    domain: str = Form(""),
    session: Session = Depends(get_session),
):
    active = _active_engagement(request, session)
    if active and ip.strip():
        session.add(
            Host(
                engagement_id=active.id,
                ip=ip.strip(),
                hostname=hostname or None,
                domain=domain or None,
            )
        )
        session.commit()
    return RedirectResponse("/hosts", status_code=303)


@app.post("/hosts/{host_id}/delete")
def delete_host(host_id: int, session: Session = Depends(get_session)):
    host = session.get(Host, host_id)
    if host:
        # Reach edges have two FKs to host and no ORM cascade, so clear any edge
        # that points at this host as target or pivot before deleting it.
        edges = session.exec(
            select(Reachability).where(
                (Reachability.host_id == host_id)
                | (Reachability.via_host_id == host_id)
            )
        ).all()
        for e in edges:
            session.delete(e)
        session.delete(host)
        session.commit()
    return RedirectResponse("/hosts", status_code=303)


@app.get("/hosts/{host_id}", response_class=HTMLResponse)
def host_detail(host_id: int, request: Request, session: Session = Depends(get_session)):
    host = session.get(Host, host_id)
    if not host:
        return RedirectResponse("/hosts", status_code=303)
    cred_rows = []
    for link in host.host_credentials:
        cred = link.credential
        try:
            secret = decrypt_secret(cred.secret_encrypted) if cred else ""
        except ValueError:
            secret = "<decrypt error>"
        cred_rows.append({"link": link, "cred": cred, "secret": secret})

    reach_edges = session.exec(
        select(Reachability).where(Reachability.host_id == host_id)
    ).all()
    host_findings = sorted(
        session.exec(select(Finding).where(Finding.host_id == host_id)).all(),
        key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), f.created_at),
    )
    pivot_names = {
        h.id: (h.hostname or h.ip)
        for h in session.exec(
            select(Host).where(Host.engagement_id == host.engagement_id)
        ).all()
    }
    pivot_choices = [
        {"id": hid, "label": name}
        for hid, name in sorted(pivot_names.items(), key=lambda kv: kv[1])
        if hid != host_id
    ]
    return templates.TemplateResponse(
        request,
        "host_detail.html",
        _ctx(
            request,
            session,
            host=host,
            cred_rows=cred_rows,
            secret_types=list(SecretType),
            access_levels=list(AccessLevel),
            host_findings=host_findings,
            severities=list(Severity),
            reach_edges=reach_edges,
            pivot_names=pivot_names,
            pivot_choices=pivot_choices,
            reach_methods=list(ReachMethod),
        ),
    )


@app.post("/hosts/{host_id}/notes")
def update_host_notes(
    host_id: int,
    notes: str = Form(""),
    session: Session = Depends(get_session),
):
    host = session.get(Host, host_id)
    if host:
        host.notes = notes.strip() or None
        session.add(host)
        session.commit()
    return RedirectResponse(f"/hosts/{host_id}", status_code=303)


@app.post("/hosts/{host_id}/nickname")
def update_host_nickname(
    host_id: int,
    nickname: str = Form(""),
    session: Session = Depends(get_session),
):
    host = session.get(Host, host_id)
    if host:
        # Storing the hostname itself is redundant: the label already falls
        # back to it, and leaving it unset keeps tracking hostname changes.
        nickname = nickname.strip()
        host.nickname = nickname if nickname and nickname != host.hostname else None
        session.add(host)
        session.commit()
    return RedirectResponse(f"/hosts/{host_id}", status_code=303)


@app.post("/hosts/{host_id}/progress")
def update_progress(
    host_id: int,
    foothold: str = Form(""),
    local_flag: str = Form(""),
    rooted: str = Form(""),
    proof_flag: str = Form(""),
    session: Session = Depends(get_session),
):
    host = session.get(Host, host_id)
    if host:
        host.foothold = bool(foothold)
        host.rooted = bool(rooted)
        host.local_flag = local_flag.strip() or None
        host.proof_flag = proof_flag.strip() or None
        session.add(host)
        session.commit()
    return RedirectResponse(f"/hosts/{host_id}", status_code=303)


@app.post("/hosts/{host_id}/evidence")
async def upload_evidence(
    host_id: int,
    kind: str = Form("other"),
    caption: str = Form(""),
    file: UploadFile = File(...),
    session: Session = Depends(get_session),
):
    host = session.get(Host, host_id)
    if host:
        data = await file.read()
        ctype = file.content_type or "image/png"
        if data and ctype.startswith("image/"):
            try:
                k = EvidenceKind(kind)
            except ValueError:
                k = EvidenceKind.other
            session.add(
                Evidence(
                    host_id=host_id,
                    kind=k,
                    filename=file.filename,
                    content_type=ctype,
                    data=data,
                    caption=caption or None,
                )
            )
            session.commit()
    return RedirectResponse(f"/hosts/{host_id}", status_code=303)


@app.get("/evidence/{evidence_id}")
def get_evidence(evidence_id: int, session: Session = Depends(get_session)):
    ev = session.get(Evidence, evidence_id)
    if not ev:
        return RedirectResponse("/hosts", status_code=303)
    return Response(content=ev.data, media_type=ev.content_type)


_IMG_EXT = {
    "image/png": "png", "image/jpeg": "jpg", "image/jpg": "jpg",
    "image/gif": "gif", "image/webp": "webp", "image/bmp": "bmp",
    "image/svg+xml": "svg", "image/tiff": "tif",
}


def _evidence_filename(ev: Evidence) -> str:
    """A sensible download name: the uploaded name, else <ip>_<kind>.<ext>."""
    if ev.filename and ev.filename.strip():
        return ev.filename.strip()
    ip = (ev.host.ip if ev.host else "host").replace("/", "_").replace(":", "_")
    ext = _IMG_EXT.get(ev.content_type, "img")
    return f"{ip}_{ev.kind.value}_{ev.id}.{ext}"


@app.get("/evidence/{evidence_id}/download")
def download_evidence(evidence_id: int, session: Session = Depends(get_session)):
    ev = session.get(Evidence, evidence_id)
    if not ev:
        return RedirectResponse("/hosts", status_code=303)
    return Response(
        content=ev.data,
        media_type=ev.content_type or "application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{_evidence_filename(ev)}"'},
    )


@app.post("/evidence/{evidence_id}/delete")
def delete_evidence(evidence_id: int, session: Session = Depends(get_session)):
    ev = session.get(Evidence, evidence_id)
    host_id = ev.host_id if ev else None
    if ev:
        session.delete(ev)
        session.commit()
    return RedirectResponse(f"/hosts/{host_id}" if host_id else "/hosts", status_code=303)


@app.post("/hosts/{host_id}/exploits")
def add_exploit(
    host_id: int,
    title: str = Form(...),
    url: str = Form(""),
    modified: str = Form(""),
    code: str = Form(""),
    shellcode_cmd: str = Form(""),
    changes: str = Form(""),
    explanation: str = Form(""),
    session: Session = Depends(get_session),
):
    host = session.get(Host, host_id)
    if host and title.strip():
        session.add(
            Exploit(
                host_id=host_id,
                title=title.strip(),
                url=url.strip() or None,
                modified=bool(modified),
                code=code or None,
                shellcode_cmd=shellcode_cmd or None,
                changes=changes or None,
                explanation=explanation or None,
            )
        )
        session.commit()
    return RedirectResponse(f"/hosts/{host_id}", status_code=303)


@app.post("/exploits/{exploit_id}/edit")
def edit_exploit(
    exploit_id: int,
    title: str = Form(...),
    url: str = Form(""),
    modified: str = Form(""),
    code: str = Form(""),
    shellcode_cmd: str = Form(""),
    changes: str = Form(""),
    explanation: str = Form(""),
    session: Session = Depends(get_session),
):
    exp = session.get(Exploit, exploit_id)
    if not exp:
        return RedirectResponse("/hosts", status_code=303)
    if title.strip():
        exp.title = title.strip()
    exp.url = url.strip() or None
    exp.modified = bool(modified)
    exp.code = code or None
    exp.shellcode_cmd = shellcode_cmd or None
    exp.changes = changes or None
    exp.explanation = explanation or None
    session.add(exp)
    session.commit()
    return RedirectResponse(f"/hosts/{exp.host_id}", status_code=303)


@app.post("/exploits/{exploit_id}/delete")
def delete_exploit(exploit_id: int, session: Session = Depends(get_session)):
    exp = session.get(Exploit, exploit_id)
    host_id = exp.host_id if exp else None
    if exp:
        session.delete(exp)
        session.commit()
    return RedirectResponse(f"/hosts/{host_id}" if host_id else "/hosts", status_code=303)


@app.post("/hosts/{host_id}/reach")
def add_reach(
    request: Request,
    host_id: int,
    via: str = Form(""),
    method: str = Form("direct"),
    port: str = Form(""),
    notes: str = Form(""),
    session: Session = Depends(get_session),
):
    host = session.get(Host, host_id)
    if host:
        via_id = int(via) if via.strip().isdigit() else None
        try:
            m = ReachMethod(method)
        except ValueError:
            m = ReachMethod.other
        session.add(
            Reachability(
                engagement_id=host.engagement_id,
                host_id=host_id,
                via_host_id=via_id,
                method=m,
                port=int(port) if port.strip().isdigit() else None,
                notes=notes or None,
            )
        )
        session.commit()
    return RedirectResponse(f"/hosts/{host_id}", status_code=303)


@app.post("/reach/{edge_id}/delete")
def delete_reach(edge_id: int, session: Session = Depends(get_session)):
    edge = session.get(Reachability, edge_id)
    host_id = edge.host_id if edge else None
    if edge:
        session.delete(edge)
        session.commit()
    target = f"/hosts/{host_id}" if host_id else "/topology"
    return RedirectResponse(target, status_code=303)


# --------------------------------------------------------------------------- #
# Findings attached to a host (add / edit / delete, redirecting back to host)
# --------------------------------------------------------------------------- #
@app.post("/hosts/{host_id}/findings")
def add_host_finding(
    host_id: int,
    title: str = Form(...),
    severity: str = Form("medium"),
    description: str = Form(""),
    steps: str = Form(""),
    session: Session = Depends(get_session),
):
    host = session.get(Host, host_id)
    if host and title.strip():
        try:
            sev = Severity(severity)
        except ValueError:
            sev = Severity.medium
        session.add(
            Finding(
                engagement_id=host.engagement_id,
                host_id=host_id,
                title=title.strip(),
                severity=sev,
                description=description or None,
                steps=steps or None,
            )
        )
        session.commit()
    return RedirectResponse(f"/hosts/{host_id}", status_code=303)


@app.post("/hosts/{host_id}/findings/{finding_id}/edit")
def edit_host_finding(
    host_id: int,
    finding_id: int,
    title: str = Form(...),
    severity: str = Form("medium"),
    description: str = Form(""),
    steps: str = Form(""),
    session: Session = Depends(get_session),
):
    finding = session.get(Finding, finding_id)
    if finding and title.strip():
        try:
            finding.severity = Severity(severity)
        except ValueError:
            pass
        finding.title = title.strip()
        finding.description = description or None
        finding.steps = steps or None
        session.add(finding)
        session.commit()
    return RedirectResponse(f"/hosts/{host_id}", status_code=303)


@app.post("/hosts/{host_id}/findings/{finding_id}/delete")
def delete_host_finding(
    host_id: int, finding_id: int, session: Session = Depends(get_session)
):
    finding = session.get(Finding, finding_id)
    if finding:
        session.delete(finding)
        session.commit()
    return RedirectResponse(f"/hosts/{host_id}", status_code=303)


# --------------------------------------------------------------------------- #
# Scripts (attached per host)
# --------------------------------------------------------------------------- #
def _slug_filename(name: str, given: str | None) -> str:
    if given and given.strip():
        return given.strip()
    slug = "".join(c if c.isalnum() or c in "-_." else "-" for c in name.strip().lower())
    slug = slug.strip("-") or "script"
    return slug if "." in slug else f"{slug}.sh"


@app.post("/hosts/{host_id}/scripts")
def create_script(
    host_id: int,
    name: str = Form(...),
    description: str = Form(""),
    filename: str = Form(""),
    content: str = Form(""),
    session: Session = Depends(get_session),
):
    host = session.get(Host, host_id)
    if host and name.strip():
        session.add(
            Script(
                host_id=host_id,
                name=name.strip(),
                description=description or None,
                filename=_slug_filename(name, filename),
                content=content,
            )
        )
        session.commit()
    return RedirectResponse(f"/hosts/{host_id}", status_code=303)


@app.post("/hosts/{host_id}/scripts/upload")
async def upload_script(
    host_id: int,
    file: UploadFile = File(...),
    name: str = Form(""),
    description: str = Form(""),
    session: Session = Depends(get_session),
):
    host = session.get(Host, host_id)
    if host:
        content = (await file.read()).decode("utf-8", errors="replace")
        display = name.strip() or (file.filename or "uploaded script")
        session.add(
            Script(
                host_id=host_id,
                name=display,
                description=description or None,
                filename=file.filename or _slug_filename(display, None),
                content=content,
            )
        )
        session.commit()
    return RedirectResponse(f"/hosts/{host_id}", status_code=303)


@app.get("/scripts/{script_id}/download")
def download_script(script_id: int, session: Session = Depends(get_session)):
    script = session.get(Script, script_id)
    if not script:
        return RedirectResponse("/hosts", status_code=303)
    fname = script.filename or _slug_filename(script.name, None)
    return Response(
        content=script.content,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@app.post("/scripts/{script_id}/delete")
def delete_script(script_id: int, session: Session = Depends(get_session)):
    script = session.get(Script, script_id)
    host_id = script.host_id if script else None
    if script:
        session.delete(script)
        session.commit()
    return RedirectResponse(f"/hosts/{host_id}" if host_id else "/hosts", status_code=303)


# --------------------------------------------------------------------------- #
# Open ports / services (manual add / edit / delete)
# --------------------------------------------------------------------------- #
@app.post("/hosts/{host_id}/services")
def add_service(
    host_id: int,
    port: int = Form(...),
    protocol: str = Form("tcp"),
    state: str = Form("open"),
    service_name: str = Form(""),
    product: str = Form(""),
    version: str = Form(""),
    session: Session = Depends(get_session),
):
    host = session.get(Host, host_id)
    if host:
        session.add(
            Service(
                host_id=host_id,
                port=port,
                protocol=protocol or "tcp",
                state=state or "open",
                service_name=service_name or None,
                product=product or None,
                version=version or None,
            )
        )
        session.commit()
    return RedirectResponse(f"/hosts/{host_id}", status_code=303)


@app.post("/services/{service_id}/edit")
def edit_service(
    service_id: int,
    port: int = Form(...),
    protocol: str = Form("tcp"),
    state: str = Form("open"),
    service_name: str = Form(""),
    product: str = Form(""),
    version: str = Form(""),
    session: Session = Depends(get_session),
):
    svc = session.get(Service, service_id)
    if not svc:
        return RedirectResponse("/hosts", status_code=303)
    svc.port = port
    svc.protocol = protocol or "tcp"
    svc.state = state or "open"
    svc.service_name = service_name or None
    svc.product = product or None
    svc.version = version or None
    session.add(svc)
    session.commit()
    return RedirectResponse(f"/hosts/{svc.host_id}", status_code=303)


@app.post("/services/{service_id}/delete")
def delete_service(service_id: int, session: Session = Depends(get_session)):
    svc = session.get(Service, service_id)
    host_id = svc.host_id if svc else None
    if svc:
        session.delete(svc)
        session.commit()
    return RedirectResponse(f"/hosts/{host_id}" if host_id else "/hosts", status_code=303)


# --------------------------------------------------------------------------- #
# Credentials attached to a host (add / edit / unlink)
# --------------------------------------------------------------------------- #
@app.post("/hosts/{host_id}/host-credentials")
def add_host_credential(
    host_id: int,
    username: str = Form(...),
    secret: str = Form(""),
    domain: str = Form(""),
    secret_type: str = Form("password"),
    access_level: str = Form("user"),
    proto: str = Form(""),
    session: Session = Depends(get_session),
):
    host = session.get(Host, host_id)
    if host and username.strip():
        cred = Credential(
            engagement_id=host.engagement_id,
            domain=domain or None,
            username=username.strip(),
            secret_encrypted=encrypt_secret(secret),
            secret_type=SecretType(secret_type),
            source=CredentialSource.manual,
            validated=True,
        )
        session.add(cred)
        session.flush()
        session.add(
            HostCredential(
                host_id=host_id,
                credential_id=cred.id,
                access_level=AccessLevel(access_level),
                proven=True,
                proto=proto or None,
            )
        )
        session.commit()
    return RedirectResponse(f"/hosts/{host_id}", status_code=303)


@app.post("/host-credentials/{link_id}/edit")
def edit_host_credential(
    link_id: int,
    username: str = Form(...),
    secret: str = Form(""),
    domain: str = Form(""),
    secret_type: str = Form("password"),
    access_level: str = Form("user"),
    proto: str = Form(""),
    session: Session = Depends(get_session),
):
    link = session.get(HostCredential, link_id)
    if not link:
        return RedirectResponse("/hosts", status_code=303)
    cred = link.credential
    if cred:
        cred.domain = domain or None
        cred.username = username.strip()
        cred.secret_type = SecretType(secret_type)
        if secret:  # leave the stored secret untouched when left blank
            cred.secret_encrypted = encrypt_secret(secret)
        session.add(cred)
    link.access_level = AccessLevel(access_level)
    link.proto = proto or None
    session.add(link)
    session.commit()
    return RedirectResponse(f"/hosts/{link.host_id}", status_code=303)


@app.post("/host-credentials/{link_id}/delete")
def delete_host_credential(link_id: int, session: Session = Depends(get_session)):
    link = session.get(HostCredential, link_id)
    host_id = link.host_id if link else None
    if link:
        session.delete(link)  # unlink; the credential stays in the engagement
        session.commit()
    return RedirectResponse(f"/hosts/{host_id}" if host_id else "/hosts", status_code=303)


# --------------------------------------------------------------------------- #
# Credentials
# --------------------------------------------------------------------------- #
@app.get("/credentials", response_class=HTMLResponse)
def credentials_page(request: Request, session: Session = Depends(get_session)):
    active = _active_engagement(request, session)
    rows = []
    if active:
        creds = session.exec(
            select(Credential).where(Credential.engagement_id == active.id)
        ).all()
        for c in creds:
            try:
                secret = decrypt_secret(c.secret_encrypted)
            except ValueError:
                secret = "<decrypt error>"
            cracked = ""
            if c.cracked_encrypted:
                try:
                    cracked = decrypt_secret(c.cracked_encrypted)
                except ValueError:
                    cracked = "<decrypt error>"
            # Protocols this credential has been used over, from its host links.
            protos = sorted({hc.proto for hc in c.host_credentials if hc.proto})
            rows.append(
                {"c": c, "secret": secret, "cracked": cracked,
                 "protos": ", ".join(protos) or "—"}
            )
    return templates.TemplateResponse(
        request,
        "credentials.html",
        _ctx(request, session, rows=rows, secret_types=list(SecretType)),
    )


@app.post("/credentials")
def add_credential(
    request: Request,
    username: str = Form(...),
    secret: str = Form(...),
    cracked: str = Form(""),
    domain: str = Form(""),
    secret_type: str = Form("password"),
    notes: str = Form(""),
    session: Session = Depends(get_session),
):
    active = _active_engagement(request, session)
    if active and username.strip() and secret:
        session.add(
            Credential(
                engagement_id=active.id,
                domain=domain or None,
                username=username.strip(),
                secret_encrypted=encrypt_secret(secret),
                cracked_encrypted=encrypt_secret(cracked) if cracked else None,
                secret_type=SecretType(secret_type),
                notes=notes or None,
            )
        )
        session.commit()
    return RedirectResponse("/credentials", status_code=303)


@app.post("/credentials/{cred_id}/edit")
def edit_credential(
    cred_id: int,
    username: str = Form(...),
    secret: str = Form(""),
    cracked: str = Form(""),
    domain: str = Form(""),
    secret_type: str = Form("password"),
    notes: str = Form(""),
    session: Session = Depends(get_session),
):
    cred = session.get(Credential, cred_id)
    if cred:
        cred.domain = domain or None
        cred.username = username.strip()
        cred.secret_type = SecretType(secret_type)
        cred.notes = notes or None
        if secret:  # blank leaves the stored secret unchanged
            cred.secret_encrypted = encrypt_secret(secret)
        # The cracked field is shown in full in the edit form, so take it as
        # given: a value sets it, blank clears it.
        cred.cracked_encrypted = encrypt_secret(cracked) if cracked else None
        session.add(cred)
        session.commit()
    return RedirectResponse("/credentials", status_code=303)


@app.post("/credentials/{cred_id}/delete")
def delete_credential(cred_id: int, session: Session = Depends(get_session)):
    cred = session.get(Credential, cred_id)
    if cred:
        session.delete(cred)
        session.commit()
    return RedirectResponse("/credentials", status_code=303)


# Rank access levels so a merge keeps the strongest result on each host.
_ACCESS_RANK = {
    AccessLevel.none: 0,
    AccessLevel.user: 1,
    AccessLevel.admin: 2,
    AccessLevel.domain_admin: 3,
}


@app.post("/credentials/{cred_id}/merge")
def merge_credential(
    cred_id: int, target: str = Form(""), session: Session = Depends(get_session)
):
    """Fold `cred_id` (the duplicate) into `target`, then delete it.

    Each of the source's host results moves onto the target. Where the target
    already has a result for the same host+protocol, the two are combined,
    keeping the stronger access level and any proven flag, so nothing is lost.
    """
    source = session.get(Credential, cred_id)
    tgt_id = int(target) if target.strip().isdigit() else None
    if source and tgt_id and tgt_id != cred_id:
        dest = session.get(Credential, tgt_id)
        if dest and dest.engagement_id == source.engagement_id:
            dest_links = {(l.host_id, l.proto): l for l in dest.host_credentials}
            for link in list(source.host_credentials):
                key = (link.host_id, link.proto)
                existing = dest_links.get(key)
                if existing is None:
                    # Move the link across the ORM relationship (not just the FK)
                    # so deleting the source doesn't cascade-delete it.
                    source.host_credentials.remove(link)
                    dest.host_credentials.append(link)
                    dest_links[key] = link
                else:
                    if _ACCESS_RANK.get(link.access_level, 0) > _ACCESS_RANK.get(
                        existing.access_level, 0
                    ):
                        existing.access_level = link.access_level
                    existing.proven = existing.proven or link.proven
                    session.add(existing)
                    # duplicate link stays on the source and is removed with it
            # Keep a cracked password from the source if the kept one lacks it.
            if not dest.cracked_encrypted and source.cracked_encrypted:
                dest.cracked_encrypted = source.cracked_encrypted
                session.add(dest)
            session.delete(source)
            session.commit()
    return RedirectResponse("/credentials", status_code=303)


@app.get("/coverage", response_class=HTMLResponse)
def coverage_page(request: Request, session: Session = Depends(get_session)):
    from .coverage import build_coverage

    active = _active_engagement(request, session)
    cov = build_coverage(session, active.id) if active else None
    return templates.TemplateResponse(
        request, "coverage.html", _ctx(request, session, cov=cov)
    )


@app.get("/topology", response_class=HTMLResponse)
def topology_page(request: Request, session: Session = Depends(get_session)):
    from .topology import build_topology

    active = _active_engagement(request, session)
    topo = build_topology(session, active.id) if active else None
    return templates.TemplateResponse(
        request, "topology.html", _ctx(request, session, topo=topo)
    )


@app.get("/topology/data")
def topology_data(request: Request, session: Session = Depends(get_session)):
    from fastapi.responses import JSONResponse

    from .topology import build_topology, graph_payload

    active = _active_engagement(request, session)
    if not active:
        return JSONResponse({"elements": [], "max_depth": 0})
    return JSONResponse(graph_payload(build_topology(session, active.id)))


@app.post("/credentials/{cred_id}/validate")
def toggle_validated(cred_id: int, session: Session = Depends(get_session)):
    cred = session.get(Credential, cred_id)
    if cred:
        cred.validated = not cred.validated
        session.add(cred)
        session.commit()
    return RedirectResponse("/credentials", status_code=303)


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
_SEVERITY_ORDER = {
    Severity.critical: 0,
    Severity.high: 1,
    Severity.medium: 2,
    Severity.low: 3,
    Severity.info: 4,
}


def _findings_for(session: Session, engagement_id: int) -> list[Finding]:
    rows = session.exec(
        select(Finding).where(Finding.engagement_id == engagement_id)
    ).all()
    return sorted(rows, key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), f.created_at))


@app.get("/findings", response_class=HTMLResponse)
def findings_page(request: Request, session: Session = Depends(get_session)):
    active = _active_engagement(request, session)
    findings, hosts = [], []
    if active:
        findings = _findings_for(session, active.id)
        hosts = session.exec(
            select(Host).where(Host.engagement_id == active.id).order_by(Host.ip)
        ).all()
    host_names = {h.id: (h.hostname or h.ip) for h in hosts}
    return templates.TemplateResponse(
        request,
        "findings.html",
        _ctx(
            request,
            session,
            findings=findings,
            hosts=hosts,
            host_names=host_names,
            severities=list(Severity),
        ),
    )


@app.post("/findings")
def add_finding(
    request: Request,
    title: str = Form(...),
    severity: str = Form("medium"),
    host_id: str = Form(""),
    description: str = Form(""),
    steps: str = Form(""),
    session: Session = Depends(get_session),
):
    active = _active_engagement(request, session)
    if active and title.strip():
        try:
            sev = Severity(severity)
        except ValueError:
            sev = Severity.medium
        session.add(
            Finding(
                engagement_id=active.id,
                host_id=int(host_id) if host_id.strip().isdigit() else None,
                title=title.strip(),
                severity=sev,
                description=description or None,
                steps=steps or None,
            )
        )
        session.commit()
    return RedirectResponse("/findings", status_code=303)


@app.post("/findings/{finding_id}/edit")
def edit_finding(
    finding_id: int,
    title: str = Form(...),
    severity: str = Form("medium"),
    host_id: str = Form(""),
    description: str = Form(""),
    steps: str = Form(""),
    session: Session = Depends(get_session),
):
    finding = session.get(Finding, finding_id)
    if finding and title.strip():
        try:
            finding.severity = Severity(severity)
        except ValueError:
            pass
        finding.title = title.strip()
        finding.host_id = int(host_id) if host_id.strip().isdigit() else None
        finding.description = description or None
        finding.steps = steps or None
        session.add(finding)
        session.commit()
    return RedirectResponse("/findings", status_code=303)


@app.post("/findings/{finding_id}/delete")
def delete_finding(finding_id: int, session: Session = Depends(get_session)):
    finding = session.get(Finding, finding_id)
    if finding:
        session.delete(finding)
        session.commit()
    return RedirectResponse("/findings", status_code=303)


# --------------------------------------------------------------------------- #
# Scan imports
# --------------------------------------------------------------------------- #
@app.get("/scans", response_class=HTMLResponse)
def scans_page(request: Request, session: Session = Depends(get_session)):
    active = _active_engagement(request, session)
    scans = []
    hosts = []
    if active:
        scans = session.exec(
            select(ScanImport)
            .where(ScanImport.engagement_id == active.id)
            .order_by(ScanImport.imported_at.desc())
        ).all()
        hosts = session.exec(
            select(Host).where(Host.engagement_id == active.id).order_by(Host.ip)
        ).all()
    host_names = {h.id: (h.hostname or h.ip) for h in hosts}
    return templates.TemplateResponse(
        request,
        "scans.html",
        _ctx(request, session, scans=scans, hosts=hosts, host_names=host_names),
    )


@app.post("/scans/{tool}")
async def upload_scan(
    tool: str,
    request: Request,
    files: list[UploadFile] = File(...),
    vantage: str = Form(""),
    session: Session = Depends(get_session),
):
    active = _active_engagement(request, session)
    errors: list[str] = []
    if active and tool in ("nmap", "nxc"):
        eng_id = active.id
        vantage_id = int(vantage) if vantage.strip().isdigit() else None
        importer = import_nmap if tool == "nmap" else import_nxc
        # Import each file on its own so one bad scan doesn't abort the batch.
        for f in files:
            if not f.filename:
                continue
            try:
                raw = (await f.read()).decode("utf-8", errors="replace")
                importer(session, eng_id, raw, f.filename, vantage_id)
            except Exception as exc:  # noqa: BLE001 - show parse errors in the UI
                session.rollback()
                errors.append(f"{f.filename}: {exc}")

    if errors:
        scans, hosts = [], []
        if active:
            scans = session.exec(
                select(ScanImport)
                .where(ScanImport.engagement_id == active.id)
                .order_by(ScanImport.imported_at.desc())
            ).all()
            hosts = session.exec(
                select(Host).where(Host.engagement_id == active.id).order_by(Host.ip)
            ).all()
        return templates.TemplateResponse(
            request,
            "scans.html",
            _ctx(
                request, session, scans=scans, hosts=hosts,
                host_names={h.id: (h.hostname or h.ip) for h in hosts},
                error="Some files failed to import — " + "; ".join(errors),
            ),
            status_code=422,
        )
    return RedirectResponse("/scans", status_code=303)


@app.post("/scans/{scan_id}/vantage")
def update_scan_vantage(
    scan_id: int, vantage: str = Form(""), session: Session = Depends(get_session)
):
    """Correct the 'scanned from' host of an already-imported scan.

    Re-points the reach edges this scan created at the new vantage, so the
    topology stays consistent without re-importing.
    """
    scan = session.get(ScanImport, scan_id)
    if not scan:
        return RedirectResponse("/scans", status_code=303)
    new_vantage = int(vantage) if vantage.strip().isdigit() else None
    scan.vantage_host_id = new_vantage
    session.add(scan)

    edges = session.exec(
        select(Reachability).where(Reachability.discovered_by_scan_id == scan_id)
    ).all()
    for e in edges:
        if e.host_id == new_vantage:
            session.delete(e)  # a host can't be reached via itself
            continue
        dup = session.exec(
            select(Reachability).where(
                Reachability.engagement_id == e.engagement_id,
                Reachability.host_id == e.host_id,
                Reachability.via_host_id == new_vantage,
                Reachability.id != e.id,
            )
        ).first()
        if dup:
            session.delete(e)  # an equivalent path already exists
            continue
        if new_vantage is None:
            e.method = ReachMethod.direct
        elif e.method == ReachMethod.direct:
            e.method = ReachMethod.other
        e.via_host_id = new_vantage
        session.add(e)
    session.commit()
    return RedirectResponse("/scans", status_code=303)
