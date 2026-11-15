"""Group sibling sites into clusters so none straddles the dev/test split (DESIGN §8.5).

Two sites are linked if they share a registrable domain (as listed, or the one their landing
page redirected to), show the same crypto address, or have the same page structure (a hash of
the landing page's tag skeleton). Clusters are the connected components of those links, found
with union-find. A small first version of the Stage B operator clustering, kept outside the
pipeline."""

import hashlib
from collections import defaultdict
from html.parser import HTMLParser

from pydantic import BaseModel

MIN_TAGS = 30  # fewer opening tags than this: too generic a page to link on (blank, error)


class ClusterInput(BaseModel):
    site_id: str
    registrable_domain: str
    addresses: list[str]  # dedupe keys of the site's primary-tier addresses
    dom_hash: str | None
    judgeable: bool  # the labeller called it scam or not_scam (not excluded, not error)
    final_domain: str | None = None  # registrable domain the landing page ended up on


class _TagCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)


def dom_skeleton_hash(html: str) -> str | None:
    """sha256 of the sequence of opening tag names, ignoring text and attributes, so two copies
    of one scam kit with different brand names and links hash the same. None under 30 tags."""
    collector = _TagCollector()
    collector.feed(html)
    collector.close()
    if len(collector.tags) < MIN_TAGS:
        return None
    return hashlib.sha256(" ".join(collector.tags).encode()).hexdigest()


class _UnionFind:
    def __init__(self, items: list[str]) -> None:
        self.parent = {item: item for item in items}

    def find(self, item: str) -> str:
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]  # path halving
            item = self.parent[item]
        return item

    def union(self, a: str, b: str) -> None:
        root_a, root_b = self.find(a), self.find(b)
        if root_a != root_b:
            self.parent[max(root_a, root_b)] = min(root_a, root_b)


def clusters(rows: list[ClusterInput]) -> dict[str, str]:
    """site_id -> cluster_id ("c0001"…). Clusters are numbered by their smallest site id, so the
    same input always gives the same ids. Sites that are not judgeable take no structure link
    and no redirect link (parked and error pages look alike, and sit on shared hosts); nor does
    a page too small to hash take a structure link."""
    uf = _UnionFind([r.site_id for r in rows])
    by_key: dict[str, list[str]] = defaultdict(list)
    for r in rows:
        by_key[f"domain:{r.registrable_domain}"].append(r.site_id)
        for address in set(r.addresses):
            by_key[f"address:{address}"].append(r.site_id)
        if r.judgeable and r.dom_hash:
            by_key[f"dom:{r.dom_hash}"].append(r.site_id)
        # Where the page ended up counts as a domain too: several listed domains that all
        # redirect to one host are siblings, and so is a site listed under that host itself.
        if r.judgeable and r.final_domain and r.final_domain != r.registrable_domain:
            by_key[f"domain:{r.final_domain}"].append(r.site_id)
    for members in by_key.values():
        for other in members[1:]:
            uf.union(members[0], other)

    roots = sorted({uf.find(r.site_id) for r in rows})
    names = {root: f"c{i:04d}" for i, root in enumerate(roots, start=1)}
    return {r.site_id: names[uf.find(r.site_id)] for r in rows}


def by_cluster(assignment: dict[str, str]) -> dict[str, list[str]]:
    """cluster_id -> its site ids, sorted."""
    out: dict[str, list[str]] = defaultdict(list)
    for site_id, cluster_id in sorted(assignment.items()):
        out[cluster_id].append(site_id)
    return dict(out)
