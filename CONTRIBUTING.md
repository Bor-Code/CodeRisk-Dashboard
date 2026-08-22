# Contributing to CodeRisk Dashboard

Thank you for improving CodeRisk Dashboard. Contributions should keep scanner behavior reviewable, deterministic, and safe for untrusted repository content.

## Before you start

- Search existing issues and pull requests.
- Open an issue before large architectural or user-facing changes.
- Report vulnerabilities through the private process in [SECURITY.md](SECURITY.md), not a public issue.
- Never submit real credentials, private repository content, or unredacted scanner evidence.

## Development setup

Requirements:

- Python 3.11 or newer
- [uv](https://docs.astral.sh/uv/)
- Node.js 24
- npm 11 or newer

Install dependencies from the repository root:

```bash
uv --directory backend sync --all-groups
npm --prefix frontend ci
```

Run the backend and frontend in separate terminals:

```bash
uv --directory backend run uvicorn app.main:app --reload
npm --prefix frontend run dev
```

## Quality checks

Run the complete local quality suite before opening a pull request:

```bash
uv --directory backend run ruff check .
uv --directory backend run ruff format --check .
uv --directory backend run pytest --cov=app --cov-report=term-missing
npm --prefix frontend run lint
npm --prefix frontend run typecheck
npm --prefix frontend run test:coverage
npm --prefix frontend run build
```

New scanner rules require positive, negative, masking, and false-positive regression fixtures where applicable. User-visible behavior requires frontend tests.

## Pull requests

1. Branch from the latest `main`.
2. Keep each pull request focused on one theme.
3. Use clear imperative commit messages.
4. Explain behavior changes, security implications, validation, and rollback risk.
5. Keep generated files and lockfiles in sync.
6. Wait for required checks and review before merge.

Pull requests are squash-merged. By participating, you agree that your contribution is licensed under the repository's Apache-2.0 license.

## Code style

- Match existing naming, typing, and comment density.
- Keep scanner core independent of FastAPI.
- Prefer typed domain structures over unvalidated dictionaries.
- Pass subprocess arguments as lists; never interpolate repository-controlled content into shell commands.
- Redact secrets before logging, serialization, snapshots, or exports.
- Avoid silently swallowing partial scan failures.
