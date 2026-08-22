# CodeRisk Dashboard

[![CI](https://github.com/Bor-Code/CodeRisk-Dashboard/actions/workflows/ci.yml/badge.svg)](https://github.com/Bor-Code/CodeRisk-Dashboard/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-pre--1.0-orange.svg)](#project-status)

CodeRisk Dashboard is a self-hosted security review workspace for turning repository scans into clear, actionable findings. The current pre-1.0 build scans local repositories for secret-like values, insecure configuration, basic source-code risks, and dependency manifests, then presents the results in a focused web dashboard.

> [!IMPORTANT]
> CodeRisk is under active pre-1.0 development. The built-in scanner is useful for local review and development, but it is not yet a replacement for mature SAST, secret-scanning, or dependency-vulnerability tools.

## Current capabilities

- Scan a local repository without uploading its source code.
- Detect supported dependency manifests and lockfiles.
- Identify secret-like values while masking evidence before it reaches reports.
- Check common insecure configuration and basic Python/React source patterns.
- Filter findings by severity and calculate a deterministic 0–100 score.
- Export the latest report as JSON or Markdown.
- Ignore generated directories and constrain text-file size during scanning.
- Validate scanner, API, and dashboard behavior with automated tests and coverage gates.

## Product direction

CodeRisk is being developed as a **self-hosted-first, SaaS-ready** platform. The planned engine architecture will normalize results from Gitleaks, Semgrep, and OSV-Scanner behind stable adapters while retaining focused built-in checks. See [docs/mvp-scope.md](docs/mvp-scope.md) for the original MVP boundary.

## Architecture

```text
React + TypeScript dashboard
           |
           | HTTP / JSON
           v
      FastAPI API
           |
           v
  Testable scanner core
           |
           +-- repository metadata
           +-- dependency manifests
           +-- secret/config/SAST rules
           +-- JSON and Markdown reports
```

The scanner core lives outside FastAPI so rule behavior can be tested without starting a server. Persistent scans, asynchronous workers, external engine adapters, authentication, and production containers are planned in subsequent milestones.

## Technology

| Area | Stack |
| --- | --- |
| Backend | Python 3.11+, FastAPI, uv, Pytest, Ruff |
| Frontend | React 19, TypeScript 6, Vite 8 |
| Frontend tests | Vitest, Testing Library, jsdom, V8 coverage |
| Automation | GitHub Actions, Dependabot |

## Quick start

### Requirements

- Python 3.11 or newer
- [uv](https://docs.astral.sh/uv/)
- Node.js 24
- npm 11 or newer

### Install

From the repository root:

```bash
git clone https://github.com/Bor-Code/CodeRisk-Dashboard.git
cd CodeRisk-Dashboard
uv --directory backend sync --all-groups
npm --prefix frontend ci
```

### Run

Start the API:

```bash
uv --directory backend run uvicorn app.main:app --reload
```

In a second terminal, start the dashboard:

```bash
npm --prefix frontend run dev
```

Open <http://127.0.0.1:5173>. The API is available at <http://127.0.0.1:8000>, and its interactive OpenAPI documentation is at <http://127.0.0.1:8000/docs>.

Enter an absolute path that is readable by the backend process. On Windows, a path such as `C:\Projects\sample-repository` is supported.

## API

The current MVP API exposes:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Process health check |
| `POST` | `/scan` | Scan a local repository path |
| `GET` | `/reports/latest.json` | Export the latest report as JSON |
| `GET` | `/reports/latest.md` | Export the latest report as Markdown |

Example request:

```bash
curl --request POST http://127.0.0.1:8000/scan \
  --header "Content-Type: application/json" \
  --data '{"target":"/absolute/path/to/repository","target_type":"local_path"}'
```

GitHub URL input is represented in the API model but intentionally disabled until secure clone/workspace handling is implemented.

## Quality checks

Run the same checks used by CI:

```bash
uv --directory backend run ruff check .
uv --directory backend run ruff format --check .
uv --directory backend run pytest --cov=app --cov-report=term-missing
npm --prefix frontend run lint
npm --prefix frontend run typecheck
npm --prefix frontend run test:coverage
npm --prefix frontend run build
```

Backend coverage must remain at or above 85%. Frontend coverage thresholds are configured in `frontend/vite.config.ts`.

## Repository layout

```text
backend/
  app/          FastAPI endpoints, reporting, and scanner core
  tests/        API, report, and scanner tests
frontend/
  src/          React dashboard and component tests
docs/           Scope and architecture documentation
.github/        CI, dependency updates, and contribution templates
```

## Security

Repository contents must be treated as untrusted input. Raw secrets must never appear in logs, API responses, snapshots, or exports. Do not expose the current development server directly to an untrusted network.

Report suspected vulnerabilities privately according to [SECURITY.md](SECURITY.md). Use regular issues only for sanitized scanner false positives, missed rules, and non-sensitive bugs.

## Project status

The project is pre-1.0. Near-term milestones are:

1. governance, CI, and repeatable quality gates;
2. versioned API and persistent scan history;
3. asynchronous scan jobs and normalized engine results;
4. Gitleaks, Semgrep, and OSV-Scanner adapters;
5. production dashboard workflows and GitHub repository ingestion;
6. authentication, self-hosted containers, observability, and release hardening.

The roadmap deliberately favors reviewable pull requests over a single large rewrite.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

Licensed under the [Apache License 2.0](LICENSE).
