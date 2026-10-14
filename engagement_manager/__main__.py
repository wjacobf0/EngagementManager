"""Command-line entry point.

    engagement-manager                 start the web UI and open a browser
    engagement-manager serve           start the web UI (no browser)
    engagement-manager engagements     list engagements
    engagement-manager import nmap FILE  --engagement NAME
    engagement-manager import nxc  FILE  --engagement NAME
    engagement-manager where           print data directory and db path

All data lives in a local SQLite file; nothing is sent anywhere.
"""
import argparse
import sys
import threading
import webbrowser

from sqlmodel import Session, select

from .config import get_config
from .database import engine, init_db
from .ingest import import_nmap, import_nxc
from .models import Engagement


def _get_or_create_engagement(session: Session, name: str) -> Engagement:
    eng = session.exec(select(Engagement).where(Engagement.name == name)).first()
    if eng:
        return eng
    eng = Engagement(name=name)
    session.add(eng)
    session.commit()
    session.refresh(eng)
    return eng


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    url = f"http://{args.host}:{args.port}"
    print(f"Engagement Manager → {url}")
    print(f"Data directory: {get_config().data_dir}")
    if args.open:
        # Open the browser shortly after the server starts.
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    uvicorn.run("engagement_manager.app:app", host=args.host, port=args.port, log_level="info")
    return 0


def cmd_import(args: argparse.Namespace) -> int:
    init_db()
    try:
        raw = open(args.file, "r", encoding="utf-8", errors="replace").read()
    except OSError as exc:
        print(f"error: cannot read {args.file}: {exc}", file=sys.stderr)
        return 1
    with Session(engine) as session:
        eng = _get_or_create_engagement(session, args.engagement)
        importer = import_nmap if args.tool == "nmap" else import_nxc
        record = importer(session, eng.id, raw, args.file)
        print(f"[{args.tool}] engagement '{eng.name}': {record.summary}")
    return 0


def cmd_engagements(_: argparse.Namespace) -> int:
    init_db()
    with Session(engine) as session:
        rows = session.exec(select(Engagement).order_by(Engagement.created_at)).all()
        if not rows:
            print("(no engagements yet)")
            return 0
        for e in rows:
            client = f" — {e.client}" if e.client else ""
            print(f"  [{e.id}] {e.name}{client}  ({e.status.value})")
    return 0


def cmd_where(_: argparse.Namespace) -> int:
    cfg = get_config()
    print(f"data directory : {cfg.data_dir}")
    print(f"database       : {cfg.db_path}")
    print(f"encryption key : {cfg.key_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="engagement-manager", description=__doc__)
    sub = p.add_subparsers(dest="command")

    serve = sub.add_parser("serve", help="start the web UI")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--no-open", dest="open", action="store_false", help="do not open a browser")
    serve.set_defaults(func=cmd_serve, open=True)

    imp = sub.add_parser("import", help="import an nmap XML or nxc output file")
    imp.add_argument("tool", choices=["nmap", "nxc"])
    imp.add_argument("file")
    imp.add_argument("-e", "--engagement", required=True, help="engagement name (created if new)")
    imp.set_defaults(func=cmd_import)

    sub.add_parser("engagements", help="list engagements").set_defaults(func=cmd_engagements)
    sub.add_parser("where", help="show local data paths").set_defaults(func=cmd_where)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        # Bare `engagement-manager` → serve and open a browser.
        return cmd_serve(argparse.Namespace(host="127.0.0.1", port=8000, open=True))
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
