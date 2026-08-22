# Security Policy

## Supported versions

CodeRisk Dashboard is currently pre-1.0. Security fixes are applied to the latest commit on `main`. Tagged release support will be documented before the first stable release.

| Version | Supported |
| --- | --- |
| `main` / latest pre-release | Yes |
| Older commits and unmaintained forks | No |

## Reporting a vulnerability

Do not open a public issue for suspected vulnerabilities. Use GitHub's private vulnerability reporting flow:

<https://github.com/Bor-Code/CodeRisk-Dashboard/security/advisories/new>

Include:

- the affected version or commit SHA;
- impact and realistic attack scenario;
- minimal reproduction steps or a proof of concept;
- any suggested remediation;
- whether the report contains sensitive repository data.

Never include production secrets, third-party credentials, or private source code unless the maintainers explicitly request a secure transfer method.

## Response process

The maintainers aim to:

1. acknowledge a complete report within five business days;
2. validate impact and establish a remediation plan;
3. coordinate disclosure and credit with the reporter;
4. publish a fix and advisory when affected users can update safely.

These are response targets, not contractual service-level guarantees.

## Security scope

CodeRisk processes untrusted repository content and may invoke external scanning tools. Security boundaries include path handling, subprocess execution, secret redaction, report access, temporary workspaces, and dependency/tool supply chains. Reports that show raw secret disclosure, command injection, path traversal, authorization bypass, or cross-tenant data exposure are especially valuable.

Scanner false positives or missed detections without a security boundary bypass should be filed as regular bug reports with sanitized fixtures.
