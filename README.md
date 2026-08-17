# CodeRisk Dashboard

CodeRisk Dashboard is a mini DevSecOps security dashboard for scanning local repositories and showing repository risk in a clear, reviewable format.

The MVP focuses on local repository analysis:

- repository metadata
- file tree summary
- dependency manifest detection
- possible secret exposure detection with masked values
- insecure configuration checks
- basic SAST-style rules
- 0-100 security score
- JSON and Markdown report export

The project is inspired by tools such as Snyk, GitHub Advanced Security, GitLab Security Dashboard, Semgrep, Gitleaks, Trivy, OSV-Scanner, and OWASP Dependency-Track.

## Tech Stack

Backend:

- FastAPI
- uv
- Pytest
- Ruff
- SQLite later in the MVP

Frontend:

- React
- Vite
- TypeScript
- dashboard-first UI

## Development Rules

- Work on feature branches.
- Do not push or open a PR until explicitly requested.
- Use small commits.
- Use squash merge when merging PRs.
- Do not expose raw secret values in scan output.
- Keep scanner logic testable outside FastAPI.
