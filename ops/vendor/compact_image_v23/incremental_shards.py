#!/usr/bin/env python3
"""Sharded incremental BOGI rebuild (LogicalZone-level pilot).

Does not patch a monolithic v2.3 image in place. Each shard is an independent
v2.3 image with a shard-local RDATA pool. A catalog stores ordered key cuts.

Correctness for this pilot: after Apply(Δ), every shard's bytes must match a
full resplit of the updated LogicalZone using the *same* cut keys.
"""
from __future__ import annotations

import bisect
import hashlib
import json
import random
import time
from dataclasses import dataclass
from pathlib import Path

from ops.vendor.checked_image.p1 import LogicalRRset, LogicalZone
from ops.vendor.compact_image_v23.format_v23 import TYPE_ORDER, owner_to_key
from ops.vendor.compact_image_v23.lowerer import lower_bytes


@dataclass(frozen=True)
class DeltaOp:
    op: str  # ADD | DELETE | MODIFY
    owner: str
    rrtype: str
    ttl: int
    rdata: str
    # MODIFY: replace old_rdata with rdata (same owner/type); ADD ignores old
    old_rdata: str | None = None


@dataclass
class ShardCatalog:
    origin: str
    generation: int
    # cut_keys[i] = first owner key of shard i (empty key for shard 0)
    cut_keys: list[bytes]
    shard_paths: list[Path]
    shard_owner_counts: list[int]
    shard_bytes: list[int]

    def to_json(self) -> dict:
        return {
            "origin": self.origin,
            "generation": self.generation,
            "cut_keys_hex": [k.hex() for k in self.cut_keys],
            "shard_paths": [str(p) for p in self.shard_paths],
            "shard_owner_counts": self.shard_owner_counts,
            "shard_bytes": self.shard_bytes,
        }


def _rr_sort_key(origin: str, rr: LogicalRRset):
    # Must match prepare_large_zones._rrset_sort_key (TYPE_ORDER, not alpha).
    return (owner_to_key(rr.owner, origin), TYPE_ORDER.index(rr.rrtype))


def owner_order(zone: LogicalZone) -> list[str]:
    seen: list[str] = []
    last = None
    for rr in zone.rrsets:
        if rr.owner != last:
            seen.append(rr.owner)
            last = rr.owner
    return seen


def choose_cut_owners(owners: list[str], shard_count: int) -> list[str]:
    """Return shard_count cut owners (first owner of each shard)."""
    n = len(owners)
    if n == 0:
        raise ValueError("empty owner list")
    s = max(1, min(shard_count, n))
    cuts = []
    for i in range(s):
        idx = (i * n) // s
        cuts.append(owners[idx])
    # de-dup if tiny zone
    out = []
    for c in cuts:
        if not out or c != out[-1]:
            out.append(c)
    return out


def split_zone(zone: LogicalZone, cut_owners: list[str]) -> list[LogicalZone]:
    """Split zone into |cut_owners| LogicalZones by owner key ranges."""
    origin = zone.origin
    cut_keys = [owner_to_key(o, origin) for o in cut_owners]
    buckets: list[list[LogicalRRset]] = [[] for _ in cut_keys]
    for rr in zone.rrsets:
        k = owner_to_key(rr.owner, origin)
        # largest cut_key <= k
        i = bisect.bisect_right(cut_keys, k) - 1
        if i < 0:
            raise ValueError(f"owner {rr.owner} before first cut")
        buckets[i].append(rr)
    return [LogicalZone(origin, tuple(b)) for b in buckets]


def shard_index_for_owner(origin: str, cut_keys: list[bytes], owner: str) -> int:
    k = owner_to_key(owner, origin)
    i = bisect.bisect_right(cut_keys, k) - 1
    if i < 0:
        raise ValueError(f"owner {owner} before first cut")
    return i


def apply_deltas(zone: LogicalZone, deltas: list[DeltaOp]) -> LogicalZone:
    """Apply ADD/DELETE/MODIFY; return new LogicalZone in canonical order."""
    origin = zone.origin
    # map (owner, type) -> (ttl, set rdatas)
    groups: dict[tuple[str, str], tuple[int, set[str]]] = {}
    for rr in zone.rrsets:
        groups[(rr.owner, rr.rrtype)] = (rr.ttl, set(rr.rdatas))

    for d in deltas:
        key = (d.owner, d.rrtype)
        if d.op == "ADD":
            if key not in groups:
                groups[key] = (d.ttl, {d.rdata})
            else:
                ttl, rds = groups[key]
                rds.add(d.rdata)
                groups[key] = (ttl, rds)
        elif d.op == "DELETE":
            if key not in groups:
                continue
            ttl, rds = groups[key]
            rds.discard(d.rdata)
            if not rds:
                del groups[key]
            else:
                groups[key] = (ttl, rds)
        elif d.op == "MODIFY":
            if key not in groups:
                # treat as add of new
                groups[key] = (d.ttl, {d.rdata})
                continue
            ttl, rds = groups[key]
            if d.old_rdata is not None:
                rds.discard(d.old_rdata)
            rds.add(d.rdata)
            groups[key] = (d.ttl, rds)
        else:
            raise ValueError(d.op)

    # drop empty; rebuild; CNAME exclusivity
    cname_owners = {o for (o, t) in groups if t == "CNAME"}
    rrsets: list[LogicalRRset] = []
    for (owner, rrtype), (ttl, rdatas) in groups.items():
        if owner in cname_owners and rrtype != "CNAME":
            continue
        if not rdatas:
            continue
        rrsets.append(LogicalRRset(owner, ttl, rrtype, tuple(sorted(rdatas))))
    rrsets_t = tuple(sorted(rrsets, key=lambda r: _rr_sort_key(origin, r)))
    # apex contract
    if not any(r.owner == origin and r.rrtype == "SOA" for r in rrsets_t):
        raise ValueError("apex SOA missing after delta")
    if not any(r.owner == origin and r.rrtype == "NS" for r in rrsets_t):
        raise ValueError("apex NS missing after delta")
    return LogicalZone(origin, rrsets_t)


def synthesize_deltas(
    zone: LogicalZone,
    *,
    n_add: int = 20,
    n_delete: int = 10,
    n_modify: int = 20,
    seed: int = 1,
    focus_owners: list[str] | None = None,
) -> list[DeltaOp]:
    """TLD-like synthetic churn, optionally localized to focus_owners.

    When focus_owners is set (canonical contiguous slice), DELETE/MODIFY only
    hit those names, and ADD inserts subdomains under them so new keys stay
    in the same key-range / shards.
    """
    rng = random.Random(seed)
    origin = zone.origin
    owners_all = [o for o in owner_order(zone) if o != origin]
    pool = [o for o in (focus_owners or owners_all) if o != origin]
    if not pool:
        pool = owners_all
    if len(pool) < 20:
        n_add = min(n_add, max(1, len(pool) // 5))
        n_delete = min(n_delete, max(1, len(pool) // 10))
        n_modify = min(n_modify, max(1, len(pool) // 5))

    by_owner: dict[str, list[LogicalRRset]] = {}
    for rr in zone.rrsets:
        by_owner.setdefault(rr.owner, []).append(rr)

    deltas: list[DeltaOp] = []

    # ADD: subdomain under a focus owner → reversed-label key stays nearby
    for i in range(n_add):
        parent = pool[i % len(pool)]
        # parent is absolute; insert one label to the left of origin
        # e.g. parent=foo.swiss. → incr0001.foo.swiss.
        rel = parent[: -(len(origin) + 1)] if parent.endswith("." + origin) else parent.rstrip(".")
        owner = f"incr{seed % 100:02d}{i:04d}.{rel}.{origin}"
        ns = f"ns1.incr{i:04d}.cdn-example.net."
        deltas.append(DeltaOp("ADD", owner, "NS", 3600, ns))
        glue_owner = f"ns1.incr{seed % 100:02d}{i:04d}.{rel}.{origin}"
        deltas.append(DeltaOp("ADD", glue_owner, "A", 3600, f"203.0.113.{(i % 200) + 1}"))

    cand = list(pool)
    rng.shuffle(cand)
    deleted = 0
    for owner in cand:
        if deleted >= n_delete:
            break
        if owner not in by_owner:
            continue
        for rr in by_owner[owner]:
            for rd in rr.rdatas:
                deltas.append(DeltaOp("DELETE", owner, rr.rrtype, rr.ttl, rd))
        deleted += 1

    mod_done = 0
    rng.shuffle(cand)
    for owner in cand:
        if mod_done >= n_modify:
            break
        rrsets = by_owner.get(owner) or []
        ns = next((r for r in rrsets if r.rrtype == "NS"), None)
        a = next((r for r in rrsets if r.rrtype == "A"), None)
        if ns and ns.rdatas:
            old = ns.rdatas[0]
            new = f"ns-alt-{mod_done}.providers.example."
            deltas.append(DeltaOp("MODIFY", owner, "NS", ns.ttl, new, old_rdata=old))
            mod_done += 1
        elif a and a.rdatas:
            old = a.rdatas[0]
            parts = old.split(".")
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                new = f"{parts[0]}.{parts[1]}.{parts[2]}.{(int(parts[3]) + 7) % 250}"
            else:
                new = "198.51.100.10"
            deltas.append(DeltaOp("MODIFY", owner, "A", a.ttl, new, old_rdata=old))
            mod_done += 1

    return deltas


def touched_shard_indices(
    origin: str, cut_keys: list[bytes], deltas: list[DeltaOp]
) -> list[int]:
    idxs = sorted({shard_index_for_owner(origin, cut_keys, d.owner) for d in deltas})
    return idxs


def build_shards(
    zone: LogicalZone,
    out_dir: Path,
    *,
    shard_count: int,
    generation: int = 1,
) -> tuple[ShardCatalog, float, list[LogicalZone]]:
    """Split + lower each shard. Returns catalog, wall_s, shard zones."""
    out_dir.mkdir(parents=True, exist_ok=True)
    owners = owner_order(zone)
    cut_owners = choose_cut_owners(owners, shard_count)
    cut_keys = [owner_to_key(o, zone.origin) for o in cut_owners]
    parts = split_zone(zone, cut_owners)
    t0 = time.perf_counter()
    paths: list[Path] = []
    counts: list[int] = []
    sizes: list[int] = []
    for i, part in enumerate(parts):
        if not part.rrsets:
            img = b""
        else:
            # Only shard 0 carries the apex; other shards omit the apex contract.
            img = lower_bytes(part, require_apex=(i == 0))
        path = out_dir / f"shard_{i:04d}.gen{generation}.bogi"
        path.write_bytes(img)
        paths.append(path)
        counts.append(len({r.owner for r in part.rrsets}))
        sizes.append(len(img))
    wall = time.perf_counter() - t0
    cat = ShardCatalog(
        origin=zone.origin,
        generation=generation,
        cut_keys=cut_keys,
        shard_paths=paths,
        shard_owner_counts=counts,
        shard_bytes=sizes,
    )
    (out_dir / "catalog.json").write_text(json.dumps(cat.to_json(), indent=2), encoding="utf-8")
    return cat, wall, parts


def incremental_rebuild(
    zone_after: LogicalZone,
    cut_keys: list[bytes],
    cut_owners: list[str],
    touched: list[int],
    out_dir: Path,
    *,
    generation: int,
) -> tuple[float, dict[int, bytes]]:
    """Re-lower only touched shards of zone_after using fixed cuts."""
    parts = split_zone(zone_after, cut_owners)
    out_dir.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()
    rebuilt: dict[int, bytes] = {}
    for i in touched:
        img = (
            lower_bytes(parts[i], require_apex=(i == 0))
            if parts[i].rrsets
            else b""
        )
        path = out_dir / f"shard_{i:04d}.gen{generation}.bogi"
        path.write_bytes(img)
        rebuilt[i] = img
    wall = time.perf_counter() - t0
    return wall, rebuilt


def full_resplit_bytes(
    zone_after: LogicalZone, cut_owners: list[str]
) -> list[bytes]:
    parts = split_zone(zone_after, cut_owners)
    out = []
    for i, p in enumerate(parts):
        out.append(lower_bytes(p, require_apex=(i == 0)) if p.rrsets else b"")
    return out


def target_shard_count(owners: int) -> int:
    """Aim ~8k–16k owners/shard; clamp 4..64."""
    if owners < 1000:
        return max(2, min(8, owners // 50 or 2))
    s = max(4, owners // 12000)
    return min(64, s)


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()
