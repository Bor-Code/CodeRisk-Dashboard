"""OSV-Scanner engine adapter.

Runs ``osv-scanner --format json`` against a local path and normalises
dependency vulnerability results into :class:`~app.engines.base.RawFinding` objects.

OSV-Scanner must be installed and available on PATH for this adapter to activate.
"""

from __future__ import annotations

import json
import logging
import subprocess

from app.engines.base import EngineAdapter, RawFinding

logger = logging.getLogger(__name__)


def _cvss_to_severity(score: float | None) -> str:
    if score is None:
        return "medium"
    if score >= 9.0:
        return "high"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


class OSVScannerAdapter(EngineAdapter):
    """Wraps the ``osv-scanner`` binary."""

    engine_id = "osv-scanner"

    def _binary_name(self) -> str:
        return "osv-scanner"

    def run(self, target: str) -> list[RawFinding]:
        try:
            result = subprocess.run(  # noqa: S603
                [
                    "osv-scanner",
                    "--format",
                    "json",
                    "--recursive",
                    target,
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.warning("osv-scanner run failed: %s", exc)
            return []

        try:
            payload: dict = json.loads(result.stdout)
        except json.JSONDecodeError:
            logger.warning("osv-scanner produced invalid JSON")
            return []

        findings: list[RawFinding] = []
        for result_item in payload.get("results", []):
            source: dict = result_item.get("source", {})
            manifest_path: str = source.get("path", "")

            for pkg in result_item.get("packages", []):
                package_info = pkg.get("package", {})
                pkg_name: str = package_info.get("name", "unknown")
                pkg_version: str = package_info.get("version", "unknown")

                for vuln in pkg.get("vulnerabilities", []):
                    vuln_id: str = vuln.get("id", "OSV-UNKNOWN")
                    summary: str = vuln.get("summary", f"Vulnerability in {pkg_name}")
                    aliases: list[str] = vuln.get("aliases", [])
                    cve = next((a for a in aliases if a.startswith("CVE-")), vuln_id)

                    # Extract CVSS score if present
                    severity_score: float | None = None
                    for sev in vuln.get("severity", []):
                        try:
                            severity_score = float(sev.get("score", 0))
                        except (TypeError, ValueError):
                            pass

                    severity = _cvss_to_severity(severity_score)
                    refs: list[dict] = vuln.get("references", [])
                    ref_url = refs[0].get("url", "") if refs else ""

                    findings.append(
                        RawFinding(
                            engine_id=self.engine_id,
                            rule_id=vuln_id,
                            title=f"{cve}: {summary[:80]}",
                            description=summary,
                            file_path=manifest_path,
                            line=None,
                            severity=severity,
                            category="dependency",
                            evidence=f"{pkg_name}=={pkg_version}",
                            remediation=f"Update {pkg_name} to a patched version. See: {ref_url}",
                            extra={"cve": cve, "vuln_id": vuln_id},
                        )
                    )

        return findings
