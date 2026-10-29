"""Zone edit contract shared by GUI and Apply backends."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Iterable


ALLOWED_OPS = frozenset({"ADD", "MODIFY", "DELETE"})


@dataclass(frozen=True)
class ZoneEdit:
    op: str
    owner: str
    rrtype: str
    ttl: int
    rdata: str
    old_rdata: str | None = None

    def validate(self) -> None:
        op = self.op.upper()
        if op not in ALLOWED_OPS:
            raise ValueError(f"unsupported op: {self.op}")
        if not self.owner or not self.owner.endswith("."):
            raise ValueError(f"owner must be absolute FQDN: {self.owner!r}")
        if not self.rrtype:
            raise ValueError("rrtype required")
        if int(self.ttl) < 0:
            raise ValueError("ttl must be >= 0")
        if self.op.upper() in {"ADD", "MODIFY"} and not self.rdata:
            raise ValueError("rdata required for ADD/MODIFY")
        if self.op.upper() == "DELETE" and not self.rdata and not self.old_rdata:
            raise ValueError("DELETE needs rdata (or old_rdata) to match")

    def normalized(self) -> ZoneEdit:
        self.validate()
        owner = self.owner.lower()
        if not owner.endswith("."):
            owner += "."
        rdata = self.rdata
        old = self.old_rdata
        op = self.op.upper()
        if op == "DELETE" and not rdata and old:
            rdata = old
        return ZoneEdit(
            op=op,
            owner=owner,
            rrtype=self.rrtype.upper(),
            ttl=int(self.ttl),
            rdata=rdata,
            old_rdata=old,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self.normalized())


@dataclass(frozen=True)
class ZoneEditBatch:
    origin: str
    edits: tuple[ZoneEdit, ...]

    def validate(self) -> ZoneEditBatch:
        origin = self.origin.lower()
        if not origin.endswith("."):
            origin += "."
        if not self.edits:
            raise ValueError("edits must be non-empty")
        norms = tuple(e.normalized() for e in self.edits)
        for e in norms:
            if not e.owner.endswith("." + origin) and e.owner != origin:
                raise ValueError(f"owner {e.owner} outside origin {origin}")
        return ZoneEditBatch(origin=origin, edits=norms)

    @classmethod
    def from_dicts(cls, origin: str, rows: Iterable[dict[str, Any]]) -> ZoneEditBatch:
        edits = []
        for row in rows:
            edits.append(
                ZoneEdit(
                    op=str(row.get("op", "")),
                    owner=str(row.get("owner", "")),
                    rrtype=str(row.get("rrtype", row.get("type", ""))),
                    ttl=int(row.get("ttl", 300)),
                    rdata=str(row.get("rdata", "") or ""),
                    old_rdata=(
                        None
                        if row.get("old_rdata") in (None, "")
                        else str(row.get("old_rdata"))
                    ),
                )
            )
        return cls(origin=origin, edits=tuple(edits)).validate()

    def to_dict(self) -> dict[str, Any]:
        b = self.validate()
        return {
            "origin": b.origin,
            "edits": [e.to_dict() for e in b.edits],
        }
