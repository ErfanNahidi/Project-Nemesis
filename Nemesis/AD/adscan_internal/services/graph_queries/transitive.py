from __future__ import annotations

from collections import defaultdict
from typing import Any


def build_membership_index(graph: dict[str, Any]) -> dict[str, set[str]]:
    index: dict[str, set[str]] = defaultdict(set)
    for edge in graph.get("edges") or []:
        if edge.get("relation") == "MemberOf":
            f, t = edge.get("from") or "", edge.get("to") or ""
            if f and t:
                index[f].add(t)
    return dict(index)


def transitive_groups_of(
    member_id: str,
    index: dict[str, set[str]],
    *,
    max_depth: int = 20,
) -> set[str]:
    visited: set[str] = set()
    queue = list(index.get(member_id) or [])
    depth = 0
    while queue and depth < max_depth:
        next_q: list[str] = []
        for gid in queue:
            if gid not in visited:
                visited.add(gid)
                next_q.extend(index.get(gid) or [])
        queue, depth = next_q, depth + 1
    return visited
