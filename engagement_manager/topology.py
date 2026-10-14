"""Network topology: who reaches whom, and how many hops from the operator box.

Reachability edges (see models.Reachability) form a directed graph rooted at a
synthetic "operator" node (the engagement machine). A host reached straight from
the operator sits at depth 1; a host reached only by tunneling through a pivot
sits deeper. This module turns those edges into a graph a UI can draw and into
the per-host hop/pivot facts other pages can show.
"""
from collections import deque
from dataclasses import dataclass, field

from sqlmodel import Session, select

from .models import AccessLevel, Host, HostCredential, Reachability

OPERATOR_ID = "operator"  # synthetic root node id in the rendered graph


@dataclass
class TopoNode:
    host: Host
    depth: int                       # hops from the operator box (1 = direct)
    access: str                      # best access proven on this host
    reached_via: list[int] = field(default_factory=list)  # pivot host ids
    is_pivot: bool = False           # something is reached through this host


@dataclass
class Topology:
    nodes: dict[int, TopoNode]       # host id -> node
    edges: list[Reachability]
    orphans: list[Host]              # hosts with no reach edge yet
    max_depth: int
    # Pivots we attach straight to the operator because nothing records *how*
    # they themselves were reached. Drawn as a dashed "assumed" edge so the
    # subtree behind them stays visible instead of silently disappearing.
    assumed_roots: set[int] = field(default_factory=set)


def _best_access(links: list[HostCredential]) -> str:
    order = [
        AccessLevel.domain_admin,
        AccessLevel.admin,
        AccessLevel.user,
        AccessLevel.none,
    ]
    proven = {l.access_level for l in links if l.proven}
    for level in order:
        if level in proven:
            return level.value
    return "none"


def build_topology(session: Session, engagement_id: int) -> Topology:
    hosts = session.exec(
        select(Host).where(Host.engagement_id == engagement_id).order_by(Host.ip)
    ).all()
    by_id = {h.id: h for h in hosts}

    edges = session.exec(
        select(Reachability).where(Reachability.engagement_id == engagement_id)
    ).all()
    # Drop edges pointing at hosts that no longer exist (defensive).
    edges = [
        e for e in edges
        if e.host_id in by_id and (e.via_host_id is None or e.via_host_id in by_id)
    ]

    # Adjacency from each vantage (None = operator) to the hosts it reaches.
    children: dict[object, list[int]] = {}
    parents: dict[int, list[int]] = {h.id: [] for h in hosts}
    pivots: set[int] = set()
    for e in edges:
        children.setdefault(e.via_host_id, []).append(e.host_id)
        if e.via_host_id is not None:
            parents[e.host_id].append(e.via_host_id)
            pivots.add(e.via_host_id)

    # A pivot that nothing records a path *to* can't anchor its subtree. Attach
    # each such pivot to the operator so what sits behind it stays on the map.
    targeted = {e.host_id for e in edges}
    assumed_roots = {p for p in pivots if p not in targeted}
    for p in assumed_roots:
        children.setdefault(None, []).append(p)

    # BFS from the operator to assign each reachable host its shortest hop depth.
    depth: dict[int, int] = {}
    queue: deque[tuple[object, int]] = deque([(None, 0)])
    seen_vantages: set[object] = {None}
    while queue:
        via, d = queue.popleft()
        for hid in children.get(via, []):
            if hid not in depth or d + 1 < depth[hid]:
                depth[hid] = d + 1
            if hid not in seen_vantages:
                seen_vantages.add(hid)
                queue.append((hid, depth[hid]))

    nodes: dict[int, TopoNode] = {}
    for h in hosts:
        if h.id not in depth:
            continue
        nodes[h.id] = TopoNode(
            host=h,
            depth=depth[h.id],
            access=_best_access(list(h.host_credentials)),
            reached_via=parents[h.id],
            is_pivot=h.id in pivots,
        )

    orphans = [h for h in hosts if h.id not in depth]
    max_depth = max((n.depth for n in nodes.values()), default=0)
    return Topology(
        nodes=nodes,
        edges=edges,
        orphans=orphans,
        max_depth=max_depth,
        assumed_roots={p for p in assumed_roots if p in nodes},
    )


def graph_payload(topo: Topology) -> dict:
    """Cytoscape elements: the operator root, host nodes, and reach edges."""
    elements: list[dict] = [
        {"data": {"id": OPERATOR_ID, "label": "Operator box", "kind": "operator"}}
    ]
    for hid, node in topo.nodes.items():
        h = node.host
        label = h.hostname or h.ip
        elements.append({
            "data": {
                "id": str(hid),
                "label": label,
                "ip": h.ip,
                "kind": "pivot" if node.is_pivot else "host",
                "access": node.access,
                "depth": node.depth,
            }
        })

    # Synthetic operator -> pivot edges for pivots with no recorded inbound path.
    for pid in topo.assumed_roots:
        elements.append({
            "data": {
                "id": f"assumed{pid}",
                "source": OPERATOR_ID,
                "target": str(pid),
                "method": "assumed",
                "assumed": True,
            }
        })

    for e in topo.edges:
        if e.host_id not in topo.nodes:
            continue
        source = OPERATOR_ID if e.via_host_id is None else str(e.via_host_id)
        if e.via_host_id is not None and e.via_host_id not in topo.nodes:
            source = OPERATOR_ID  # pivot itself unreachable; anchor to root
        elements.append({
            "data": {
                "id": f"e{e.id}",
                "source": source,
                "target": str(e.host_id),
                "method": e.method.value,
                "port": e.port,
            }
        })
    return {"elements": elements, "max_depth": topo.max_depth}
