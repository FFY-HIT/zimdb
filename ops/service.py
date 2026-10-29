"""ImageStore: open / status / preview / atomic apply."""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ops.backends.container_backend import ContainerBackend
from ops.demo_zone import ORIGIN
from ops.schema import ZoneEditBatch


@dataclass
class ApplyResult:
    ok: bool
    elapsed_s: float
    generation_before: int
    generation_after: int
    size_before: int
    size_after: int
    stats: dict[str, Any]
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "elapsed_s": round(self.elapsed_s, 4),
            "generation_before": self.generation_before,
            "generation_after": self.generation_after,
            "size_before": self.size_before,
            "size_after": self.size_after,
            "stats": self.stats,
            "error": self.error,
        }


class ImageStore:
    def __init__(
        self,
        path: Path,
        *,
        origin: str = ORIGIN,
        backend: ContainerBackend | None = None,
    ) -> None:
        self.path = Path(path)
        self.origin = origin if origin.endswith(".") else origin + "."
        self.backend = backend or ContainerBackend()
        self.last_apply: ApplyResult | None = None
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def ensure(self) -> None:
        if self.path.is_file() and self.path.stat().st_size > 0:
            return
        blob = self.backend.build_initial(self.origin)
        self._atomic_write(blob)

    def _read(self) -> bytes:
        self.ensure()
        return self.path.read_bytes()

    def _atomic_write(self, blob: bytes) -> None:
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        with open(tmp, "wb") as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)

    def status(self) -> dict[str, Any]:
        blob = self._read()
        st = self.backend.status_from_blob(blob)
        st.update(
            {
                "path": str(self.path.resolve()),
                "mtime": self.path.stat().st_mtime,
                "last_apply": None if self.last_apply is None else self.last_apply.to_dict(),
            }
        )
        return st

    def preview_owner(self, owner: str) -> list[dict[str, Any]]:
        return self.backend.preview_owner(self._read(), owner)

    def apply(self, batch: ZoneEditBatch) -> ApplyResult:
        batch = batch.validate()
        if batch.origin != self.origin:
            raise ValueError(f"batch origin {batch.origin} != store {self.origin}")
        blob = self._read()
        before = self.backend.status_from_blob(blob)
        t0 = time.perf_counter()
        try:
            new_blob, stats = self.backend.apply(blob, batch)
            self._atomic_write(new_blob)
            after = self.backend.status_from_blob(new_blob)
            result = ApplyResult(
                ok=True,
                elapsed_s=time.perf_counter() - t0,
                generation_before=int(before["generation"]),
                generation_after=int(after["generation"]),
                size_before=len(blob),
                size_after=len(new_blob),
                stats=stats,
            )
        except Exception as exc:  # noqa: BLE001 — surface to GUI
            result = ApplyResult(
                ok=False,
                elapsed_s=time.perf_counter() - t0,
                generation_before=int(before.get("generation", 0)),
                generation_after=int(before.get("generation", 0)),
                size_before=len(blob),
                size_after=len(blob),
                stats={},
                error=str(exc),
            )
        self.last_apply = result
        return result
