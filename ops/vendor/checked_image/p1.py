"""Minimal LogicalZone types for ops Apply (vendored)."""
from __future__ import annotations
from dataclasses import dataclass


class P1Error(ValueError):
    pass


@dataclass(frozen=True)
class LogicalRRset:
    owner: str
    ttl: int
    rrtype: str
    rdatas: tuple[str, ...]


@dataclass(frozen=True)
class LogicalZone:
    origin: str
    rrsets: tuple[LogicalRRset, ...]

    def canonical_lines(self) -> tuple[str, ...]:
        return tuple(
            f"{rrset.owner}	{rrset.ttl}	IN	{rrset.rrtype}	{rdata}"
            for rrset in self.rrsets
            for rdata in rrset.rdatas
        )
