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
    AccessLevel,
    Credential,
    CredentialSource,
    Engagement,
    Host,
    HostCredential,
    Script,
    SecretType,
    Service,
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
        ),
    )


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
            # Protocols this credential has been used over, from its host links.
            protos = sorted({hc.proto for hc in c.host_credentials if hc.proto})
            rows.append(
                {"c": c, "secret": secret, "protos": ", ".join(protos) or "—"}
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


@app.get("/coverage", response_class=HTMLResponse)
def coverage_page(request: Request, session: Session = Depends(get_session)):
    from .coverage import build_coverage

    active = _active_engagement(request, session)
    cov = build_coverage(session, active.id) if active else None
    return templates.TemplateResponse(
        request, "coverage.html", _ctx(request, session, cov=cov)
    )


@app.post("/credentials/{cred_id}/validate")
def toggle_validated(cred_id: int, session: Session = Depends(get_session)):
    cred = session.get(Credential, cred_id)
    if cred:
        cred.validated = not cred.validated
        session.add(cred)
        session.commit()
    return RedirectResponse("/credentials", status_code=303)


# --------------------------------------------------------------------------- #
# Scan imports
# --------------------------------------------------------------------------- #
@app.get("/scans", response_class=HTMLResponse)
def scans_page(request: Request, session: Session = Depends(get_session)):
    from .models import ScanImport

    active = _active_engagement(request, session)
    scans = []
    if active:
        scans = session.exec(
            select(ScanImport)
            .where(ScanImport.engagement_id == active.id)
            .order_by(ScanImport.imported_at.desc())
        ).all()
    return templates.TemplateResponse(request, "scans.html", _ctx(request, session, scans=scans))


@app.post("/scans/{tool}")
async def upload_scan(
    tool: str,
    request: Request,
    file: UploadFile = File(...),
    session: Session = Depends(get_session),
):
    active = _active_engagement(request, session)
    if active and tool in ("nmap", "nxc"):
        raw = (await file.read()).decode("utf-8", errors="replace")
        try:
            if tool == "nmap":
                import_nmap(session, active.id, raw, file.filename)
            else:
                import_nxc(session, active.id, raw, file.filename)
        except Exception as exc:  # noqa: BLE001 - show parse errors in the UI
            return templates.TemplateResponse(
                request,
                "scans.html",
                _ctx(request, session, scans=[], error=f"Import failed: {exc}"),
                status_code=422,
            )
    return RedirectResponse("/scans", status_code=303)
