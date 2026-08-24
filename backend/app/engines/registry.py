"""Engine registry — discovers and exposes all available external adapters.

Usage::

    from app.engines.registry import get_available_engines, run_all_engines

    findings = run_all_engines("/path/to/repo")
"""

from __future__ import annotations

import logging

from app.engines.base import EngineAdapter, RawFinding
from app.engines.gitleaks import GitleaksAdapter
from app.engines.osv_scanner import OSVScannerAdapter
from app.engines.semgrep import SemgrepAdapter

logger = logging.getLogger(__name__)

_ALL_ADAPTERS: list[EngineAdapter] = [
    GitleaksAdapter(),
    SemgrepAdapter(),
    OSVScannerAdapter(),
]


def get_available_engines() -> list[EngineAdapter]:
    """Return the subset of adapters whose binaries are present on PATH."""
    available = [a for a in _ALL_ADAPTERS if a.is_available()]
    if available:
        logger.info(
            "Available external engines: %s",
            ", ".join(a.engine_id for a in available),
        )
    else:
        logger.info("No external engines found on PATH — using built-in scanner only.")
    return available


def run_all_engines(target: str) -> list[RawFinding]:
    """Run every available engine against *target* and aggregate results."""
    all_findings: list[RawFinding] = []
    for adapter in get_available_engines():
        try:
            results = adapter.run(target)
            logger.info("Engine %s produced %d findings", adapter.engine_id, len(results))
            all_findings.extend(results)
        except Exception:  # noqa: BLE001
            logger.exception("Engine %s raised an unexpected error", adapter.engine_id)
    return all_findings


def engine_availability() -> dict[str, bool]:
    """Return a dict mapping engine_id → is_available for the API status endpoint."""
    return {a.engine_id: a.is_available() for a in _ALL_ADAPTERS}
