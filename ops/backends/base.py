"""Apply backend protocol — container today, production .bogi later."""
from __future__ import annotations

from typing import Any, Protocol

from ops.schema import ZoneEditBatch


class ApplyBackend(Protocol):
    name: str

    def build_initial(self, origin: str) -> bytes:
        """Create a fresh image for the demo/seed zone."""

    def apply(self, blob: bytes, batch: ZoneEditBatch) -> tuple[bytes, dict[str, Any]]:
        """Return (new_blob, stats). Must not mutate blob in place."""

    def status_from_blob(self, blob: bytes) -> dict[str, Any]:
        """Parse header-level status without full zone decode when possible."""

    def preview_owner(self, blob: bytes, owner: str) -> list[dict[str, Any]]:
        """Return RR rows for owner from the image."""
