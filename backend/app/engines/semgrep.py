"""Semgrep engine adapter.

Runs ``semgrep --config auto --json`` against a local path and normalises
the SARIF-like JSON output into :class:`~app.engines.base.RawFinding` objects.

Semgrep must be installed and available on PATH for this adapter to activate.
"""

from __future__ import annotations

import json
import logging
import subprocess

from app.engines.base import EngineAdapter, RawFinding

logger = logging.getLogger(__name__)

_SEVERITY_MAP: dict[str, str] = {
    "error": "high",
    "warning": "medium",
    "info": "info",
    "low": "low",
}


class SemgrepAdapter(EngineAdapter):
    """Wraps the ``semgrep`` CLI (≥ 1.x)."""

    engine_id = "semgrep"

    def _binary_name(self) -> str:
        return "semgrep"

    def run(self, target: str) -> list[RawFinding]:
        try:
            result = subprocess.run(  # noqa: S603
                [
                    "semgrep",
                    "--config",
                    "auto",
                    "--json",
                    "--quiet",
                    target,
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.warning("semgrep run failed: %s", exc)
            return []

        try:
            payload: dict = json.loads(result.stdout)
        except json.JSONDecodeError:
            logger.warning("semgrep produced invalid JSON")
            return []

        findings: list[RawFinding] = []
        for hit in payload.get("results", []):
            check_id: str = hit.get("check_id", "semgrep")
            rule_id = check_id.split(".")[-1]
            meta: dict = hit.get("extra", {}).get("metadata", {})
            severity_raw = str(hit.get("extra", {}).get("severity", "warning")).lower()
            message: str = hit.get("extra", {}).get("message", check_id)
            path: str = hit.get("path", "")
            start_line: int | None = hit.get("start", {}).get("line")
            lines: str = hit.get("extra", {}).get("lines", "")

            category = str(meta.get("category", "sast")).lower()
            remediation_refs: list = meta.get("references", [])
            default_remediation = "Review the finding and apply the suggested fix."
            remediation = remediation_refs[0] if remediation_refs else default_remediation

            findings.append(
                RawFinding(
                    engine_id=self.engine_id,
                    rule_id=rule_id,
                    title=message[:120],
                    description=message,
                    file_path=path,
                    line=start_line,
                    severity=_SEVERITY_MAP.get(severity_raw, "medium"),
                    category=category,
                    evidence=lines[:200],
                    remediation=remediation,
                    extra={"check_id": check_id},
                )
            )

        return findings
