"""Tests for external engine adapters (using mocks — binaries not required)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from app.engines.base import RawFinding
from app.engines.gitleaks import GitleaksAdapter
from app.engines.osv_scanner import OSVScannerAdapter
from app.engines.registry import engine_availability, get_available_engines, run_all_engines
from app.engines.semgrep import SemgrepAdapter

# ---------------------------------------------------------------------------
# GitleaksAdapter
# ---------------------------------------------------------------------------


class TestGitleaksAdapter:
    def test_engine_id(self) -> None:
        assert GitleaksAdapter().engine_id == "gitleaks"

    def test_not_available_when_binary_missing(self, tmp_path: Path) -> None:
        adapter = GitleaksAdapter()
        with patch("shutil.which", return_value=None):
            assert adapter.is_available() is False

    def test_available_when_binary_present(self) -> None:
        adapter = GitleaksAdapter()
        with patch("shutil.which", return_value="/usr/local/bin/gitleaks"):
            assert adapter.is_available() is True

    def test_run_returns_empty_on_no_findings(self, tmp_path: Path) -> None:
        adapter = GitleaksAdapter()
        report_json = "[]"

        mock_result = MagicMock()
        mock_result.returncode = 0

        with (
            patch("subprocess.run", return_value=mock_result),
            patch("pathlib.Path.read_text", return_value=report_json),
            patch("pathlib.Path.unlink"),
        ):
            findings = adapter.run(str(tmp_path))

        assert findings == []

    def test_run_normalises_finding(self, tmp_path: Path) -> None:
        adapter = GitleaksAdapter()
        report_data = [
            {
                "RuleID": "stripe-api-key",
                "Description": "Stripe API key detected",
                "File": "config.py",
                "StartLine": 10,
                "Severity": "High",
                "Secret": "sk_live_abc123xyz",
            }
        ]

        mock_result = MagicMock()
        mock_result.returncode = 0

        with (
            patch("subprocess.run", return_value=mock_result),
            patch("pathlib.Path.read_text", return_value=json.dumps(report_data)),
            patch("pathlib.Path.unlink"),
        ):
            findings = adapter.run(str(tmp_path))

        assert len(findings) == 1
        f = findings[0]
        assert f.engine_id == "gitleaks"
        assert f.rule_id == "stripe-api-key"
        assert f.severity == "high"
        assert f.category == "secret"
        assert f.file_path == "config.py"
        assert f.line == 10
        # Secret should be partially masked
        assert "sk_l" in f.evidence
        assert "*" in f.evidence

    def test_run_returns_empty_on_subprocess_error(self, tmp_path: Path) -> None:
        adapter = GitleaksAdapter()
        with patch("subprocess.run", side_effect=OSError("not found")):
            findings = adapter.run(str(tmp_path))
        assert findings == []


# ---------------------------------------------------------------------------
# SemgrepAdapter
# ---------------------------------------------------------------------------


class TestSemgrepAdapter:
    def test_engine_id(self) -> None:
        assert SemgrepAdapter().engine_id == "semgrep"

    def test_not_available_when_binary_missing(self) -> None:
        with patch("shutil.which", return_value=None):
            assert SemgrepAdapter().is_available() is False

    def test_run_returns_empty_on_no_results(self, tmp_path: Path) -> None:
        adapter = SemgrepAdapter()
        payload = {"results": [], "errors": []}
        mock_result = MagicMock()
        mock_result.stdout = json.dumps(payload)
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            findings = adapter.run(str(tmp_path))

        assert findings == []

    def test_run_normalises_finding(self, tmp_path: Path) -> None:
        adapter = SemgrepAdapter()
        payload = {
            "results": [
                {
                    "check_id": "python.lang.security.audit.eval-detected",
                    "path": "src/app.py",
                    "start": {"line": 42},
                    "extra": {
                        "message": "Use of eval() detected",
                        "severity": "ERROR",
                        "lines": "eval(user_input)",
                        "metadata": {
                            "category": "sast",
                            "references": ["https://example.com"],
                        },
                    },
                }
            ],
            "errors": [],
        }
        mock_result = MagicMock()
        mock_result.stdout = json.dumps(payload)
        mock_result.returncode = 1  # semgrep exits 1 on findings

        with patch("subprocess.run", return_value=mock_result):
            findings = adapter.run(str(tmp_path))

        assert len(findings) == 1
        f = findings[0]
        assert f.engine_id == "semgrep"
        assert f.rule_id == "eval-detected"
        assert f.severity == "high"
        assert f.file_path == "src/app.py"
        assert f.line == 42

    def test_run_returns_empty_on_invalid_json(self, tmp_path: Path) -> None:
        adapter = SemgrepAdapter()
        mock_result = MagicMock()
        mock_result.stdout = "not json"

        with patch("subprocess.run", return_value=mock_result):
            findings = adapter.run(str(tmp_path))

        assert findings == []


# ---------------------------------------------------------------------------
# OSVScannerAdapter
# ---------------------------------------------------------------------------


class TestOSVScannerAdapter:
    def test_engine_id(self) -> None:
        assert OSVScannerAdapter().engine_id == "osv-scanner"

    def test_not_available_when_binary_missing(self) -> None:
        with patch("shutil.which", return_value=None):
            assert OSVScannerAdapter().is_available() is False

    def test_run_returns_empty_on_no_vulnerabilities(self, tmp_path: Path) -> None:
        adapter = OSVScannerAdapter()
        payload = {"results": []}
        mock_result = MagicMock()
        mock_result.stdout = json.dumps(payload)

        with patch("subprocess.run", return_value=mock_result):
            findings = adapter.run(str(tmp_path))

        assert findings == []

    def test_run_normalises_vulnerability(self, tmp_path: Path) -> None:
        adapter = OSVScannerAdapter()
        payload = {
            "results": [
                {
                    "source": {"path": "requirements.txt"},
                    "packages": [
                        {
                            "package": {"name": "requests", "version": "2.25.0"},
                            "vulnerabilities": [
                                {
                                    "id": "GHSA-j8r2-6x86-q33q",
                                    "summary": "CRLF injection in requests",
                                    "aliases": ["CVE-2023-32681"],
                                    "severity": [{"score": "7.1"}],
                                    "references": [
                                        {"url": "https://github.com/advisories/GHSA-j8r2-6x86-q33q"}
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ]
        }
        mock_result = MagicMock()
        mock_result.stdout = json.dumps(payload)

        with patch("subprocess.run", return_value=mock_result):
            findings = adapter.run(str(tmp_path))

        assert len(findings) == 1
        f = findings[0]
        assert f.engine_id == "osv-scanner"
        assert f.category == "dependency"
        assert "CVE-2023-32681" in f.title
        assert "requests==2.25.0" in f.evidence


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class TestRegistry:
    def test_get_available_engines_filters_unavailable(self) -> None:
        with patch("shutil.which", return_value=None):
            available = get_available_engines()
        assert available == []

    def test_engine_availability_dict(self) -> None:
        with patch("shutil.which", return_value=None):
            av = engine_availability()
        assert set(av.keys()) == {"gitleaks", "semgrep", "osv-scanner"}
        assert all(v is False for v in av.values())

    def test_run_all_engines_returns_empty_when_none_available(self, tmp_path: Path) -> None:
        with patch("shutil.which", return_value=None):
            findings = run_all_engines(str(tmp_path))
        assert findings == []

    def test_run_all_engines_aggregates_results(self, tmp_path: Path) -> None:
        mock_finding = RawFinding(
            engine_id="gitleaks",
            rule_id="test-rule",
            title="Test finding",
            description="Test",
            file_path="test.py",
            line=1,
            severity="high",
            category="secret",
        )

        mock_adapter = MagicMock()
        mock_adapter.is_available.return_value = True
        mock_adapter.engine_id = "gitleaks"
        mock_adapter.run.return_value = [mock_finding]

        with patch("app.engines.registry._ALL_ADAPTERS", [mock_adapter]):
            findings = run_all_engines(str(tmp_path))

        assert len(findings) == 1
        assert findings[0].engine_id == "gitleaks"
