import json

from app.domain.reports import ScanReport


def report_to_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


def report_to_markdown(report: ScanReport) -> str:
    metadata = report.metadata
    lines = [
        "# CodeRisk Scan Report",
        "",
        f"- Repository: `{metadata.name}`",
        f"- Root: `{metadata.root_path}`",
        f"- Scanned at UTC: `{metadata.scanned_at_utc}`",
        f"- Score: `{report.score}/100`",
        f"- Total files: `{metadata.total_files}`",
        "",
        "## Severity Counts",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]

    for severity in ("high", "medium", "low", "info"):
        lines.append(f"| {severity.title()} | {report.severity_counts[severity]} |")

    lines.extend(["", "## Findings", ""])

    for finding in report.findings:
        location = finding.file_path

        if finding.line is not None:
            location = f"{location}:{finding.line}"

        lines.extend(
            [
                f"### {finding.title}",
                "",
                f"- Severity: `{finding.severity}`",
                f"- Category: `{finding.category}`",
                f"- Location: `{location}`",
                f"- Evidence: `{finding.evidence}`",
                f"- Remediation: {finding.remediation}",
                "",
            ]
        )

    return "\n".join(lines)
