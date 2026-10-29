"""Container Apply backend (working demo path)."""
from __future__ import annotations

from typing import Any

from ops.demo_zone import seed_zone
from ops.schema import ZoneEditBatch
from ops.vendor.compact_image_v23.container_image import (
    apply_container,
    build_container,
    decode_shard_image,
    parse_container,
)
from ops.vendor.compact_image_v23.format_v23 import owner_to_key
from ops.vendor.compact_image_v23.incremental_shards import DeltaOp


class ContainerBackend:
    name = "container_v23"

    def __init__(self, *, target_owners: int = 64) -> None:
        self.target_owners = target_owners

    def build_initial(self, origin: str) -> bytes:
        zone = seed_zone()
        if zone.origin != origin:
            raise ValueError(f"seed origin {zone.origin} != {origin}")
        return build_container(zone, target_owners=self.target_owners, generation=1)

    def apply(self, blob: bytes, batch: ZoneEditBatch) -> tuple[bytes, dict[str, Any]]:
        batch = batch.validate()
        deltas = [
            DeltaOp(
                op=e.op,
                owner=e.owner,
                rrtype=e.rrtype,
                ttl=e.ttl,
                rdata=e.rdata,
                old_rdata=e.old_rdata,
            )
            for e in batch.edits
        ]
        new_blob, stats = apply_container(blob, deltas)
        return new_blob, {
            "touched": list(stats.touched),
            "rewritten": stats.rewritten,
            "shard_count_before": stats.shard_count_before,
            "shard_count_after": stats.shard_count_after,
            "bytes_before": stats.bytes_before,
            "bytes_after": stats.bytes_after,
            "bytes_appended": stats.bytes_appended,
            "touch_rate": (
                len(stats.touched) / stats.shard_count_before
                if stats.shard_count_before
                else 0.0
            ),
        }

    def status_from_blob(self, blob: bytes) -> dict[str, Any]:
        c = parse_container(blob, decode=False)
        return {
            "backend": self.name,
            "origin": c.origin,
            "generation": c.generation,
            "shard_count": len(c.shards),
            "target_owners": c.target_owners,
            "size_bytes": len(blob),
        }

    def preview_owner(self, blob: bytes, owner: str) -> list[dict[str, Any]]:
        owner = owner.lower()
        if not owner.endswith("."):
            owner += "."
        c = parse_container(blob, decode=False)
        key = owner_to_key(owner, c.origin)
        # largest key_lo <= key
        idx = 0
        for i, shard in enumerate(c.shards):
            if shard.key_lo <= key:
                idx = i
            else:
                break
        zone = decode_shard_image(c.shards[idx].image, c.origin)
        rows: list[dict[str, Any]] = []
        for rr in zone.rrsets:
            if rr.owner != owner:
                continue
            for rd in rr.rdatas:
                rows.append(
                    {
                        "owner": rr.owner,
                        "ttl": rr.ttl,
                        "rrtype": rr.rrtype,
                        "rdata": rd,
                    }
                )
        return rows
