"""Base class for forum source adapters."""
from __future__ import annotations

from typing import Any, AsyncIterator

from ..models import RawPost
from ..tor import TorClient


class BaseSource:
    def __init__(self, spec: dict[str, Any]):
        self.spec = spec
        self.name: str = spec.get("name", "unnamed")
        self.enabled: bool = spec.get("enabled", True)
        self.base_url: str = spec.get("base_url", "")

    async def fetch(self, client: TorClient, max_pages: int) -> AsyncIterator[RawPost]:
        """Yield RawPost objects. Subclasses must implement."""
        raise NotImplementedError
        yield  # pragma: no cover - makes this an async generator
