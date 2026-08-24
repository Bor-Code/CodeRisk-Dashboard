"""Gitleaks engine adapter.

Runs ``gitleaks detect`` against a local path and normalises the JSON report
into :class:`~app.engines.base.RawFinding` objects.

Gitleaks must be installed and available on PATH for this adapter to activate.
When it is not found, ``is_available()`` returns *False* and the adapter is
silently skipped by the engine registry.
"""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from pathlib import Path

from app.engines.base import EngineAdapter, RawFinding

logger = logging.getLogger(__name__)

_SEVERITY_MAP: dict[str, str] = {
    "critical": "high",
    "high": "high",
    "medium": "medium",
    "warning": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}


class GitleaksAdapter(EngineAdapter):
    """Wraps the ``gitleaks`` binary (v8+)."""

    engine_id = "gitleaks"

    def _binary_name(self) -> str:
        return "gitleaks"

    def run(self, target: str) -> list[RawFinding]:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            report_path = tmp.name

        try:
            result = subprocess.run(  # noqa: S603
                [
                    "gitleaks",
                    "detect",
                    "--source",
                    target,
                    "--report-format",
                    "json",
                    "--report-path",
                    report_path,
                    "--no-git",
                    "--exit-code",
                    "0",
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode not in (0, 1):
                logger.warning("gitleaks exited with code %d", result.returncode)
                return []

            raw = Path(report_path).read_text(encoding="utf-8")
            hits: list[dict] = json.loads(raw) if raw.strip() else []
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as exc:
            logger.warning("gitleaks run failed: %s", exc)
            return []
        finally:
            Path(report_path).unlink(missing_ok=True)

        findings: list[RawFinding] = []
        for hit in hits:
            rule_id: str = hit.get("RuleID", "gitleaks-secret")
            description: str = hit.get("Description", "Possible secret exposure")
            file_path: str = hit.get("File", "")
            line: int | None = hit.get("StartLine") or None
            secret: str = hit.get("Secret", "")
            masked = f"{secret[:4]}{'*' * max(0, len(secret) - 4)}" if secret else ""

            findings.append(
                RawFinding(
                    engine_id=self.engine_id,
                    rule_id=rule_id,
                    title=description,
                    description=description,
                    file_path=file_path,
                    line=line,
                    severity=_SEVERITY_MAP.get(str(hit.get("Severity", "")).lower(), "high"),
                    category="secrets",
                    evidence=masked,
                    remediation="Rotate the exposed credential and remove it from source history.",
                )
            )

        return findings
