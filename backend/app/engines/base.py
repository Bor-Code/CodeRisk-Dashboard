"""Abstract base class for external engine adapters."""

from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class RawFinding:
    """Normalised finding from any engine."""

    engine_id: str
    rule_id: str
    title: str
    description: str
    file_path: str
    line: int | None
    severity: str  # "high" | "medium" | "low" | "info"
    category: str
    evidence: str = ""
    remediation: str = ""
    extra: dict = field(default_factory=dict)


class EngineAdapter(ABC):
    """Base class every external engine adapter must implement."""

    #: Short identifier used in findings, e.g. "gitleaks", "semgrep", "osv-scanner"
    engine_id: str

    def is_available(self) -> bool:
        """Return True if the engine binary is installed and reachable."""
        return shutil.which(self._binary_name()) is not None

    @abstractmethod
    def _binary_name(self) -> str:
        """The binary name to look for on PATH."""

    @abstractmethod
    def run(self, target: str) -> list[RawFinding]:
        """Run the engine against *target* and return normalised findings.

        Implementations must be safe to call even if the binary is missing —
        callers check ``is_available()`` before calling ``run()``.
        """
