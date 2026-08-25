# MVP Scope

## Goal

Build a realistic mini security dashboard that scans repositories and produces actionable security findings.

## Included In MVP

### Input

- Local repository path
- GitHub repository URL field and API support for controlled remote repository ingestion

### Repository Analysis

- repository name
- root path
- scanned file count
- total file count
- file tree preview

### Dependency Detection

Detect these files:

- package.json
- package-lock.json
- requirements.txt
- pyproject.toml
- poetry.lock

The built-in scanner records dependency manifests. When OSV-Scanner is installed, dependency vulnerability results are normalized into the same findings model.

### Secret Scanning

Detect possible:

- API keys
- tokens
- private keys
- DATABASE_URL
- JWT secrets
- GitHub-like tokens

Secret values must always be masked before they are persisted, returned by the API, or exported.

### Config Checks

Detect:

- .env file inside repository
- .gitignore missing .env
- DEBUG enabled
- wildcard CORS
- default secret values
- localStorage token usage warning

### Basic SAST

Detect:

- Python SQL string concatenation
- hardcoded password
- subprocess with shell=True
- React dangerouslySetInnerHTML
- insecure HTTP URL

Semgrep results are also normalized when the Semgrep binary is installed.

### Reporting

- JSON export
- Markdown export
- SBOM export when Syft is installed
- severity counts
- 0-100 score

### Platform

- JWT authentication
- PostgreSQL production deployment
- Docker Compose self-hosting
- durable scan queue and persisted scan history

## Deferred / Hardening Follow-Up

- deeper GitHub workspace isolation and cleanup controls
- richer dependency and SAST rule configuration
- integration credential encryption at rest
- production observability and release hardening
