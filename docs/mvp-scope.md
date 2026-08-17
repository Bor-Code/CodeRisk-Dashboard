# MVP Scope

## Goal

Build a realistic mini security dashboard that scans a local repository and produces actionable security findings.

## Included In MVP

### Input

- Local repository path
- GitHub repository URL field in the UI, but remote cloning will be deferred

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

Known vulnerability lookup is not included in the first scanner version. OSV-Scanner or Trivy can be integrated later.

### Secret Scanning

Detect possible:

- API keys
- tokens
- private keys
- DATABASE_URL
- JWT secrets
- GitHub-like tokens

Secret values must always be masked.

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

### Reporting

- JSON export
- Markdown export
- severity counts
- 0-100 score

## Deferred

- GitHub remote clone
- real dependency CVE lookup
- Semgrep integration
- Gitleaks integration
- SBOM generation
- authentication
- PostgreSQL
- Docker
