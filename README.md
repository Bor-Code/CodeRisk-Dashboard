> [!CAUTION]
> **CREATE YOUR OWN SAFETY ZONE AROUND YOU**

<div align="center">
  <img src="https://img.shields.io/badge/Security-CodeRisk-6366f1?style=for-the-badge&logo=shield" alt="CodeRisk Badge" />
  <h1>CodeRisk Dashboard</h1>
  <p><em>Developed by Bor-Code</em></p>
  
  <p>
    <strong>A comprehensive, automated Static Application Security Testing (SAST) and Software Composition Analysis (SCA) platform.</strong>
  </p>

  <p>
    <img src="https://img.shields.io/badge/React-20232A?style=flat-square&logo=react&logoColor=61DAFB" alt="React" />
    <img src="https://img.shields.io/badge/TypeScript-007ACC?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript" />
    <img src="https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI" />
    <img src="https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python" />
    <img src="https://img.shields.io/badge/SQLite-003B57?style=flat-square&logo=sqlite&logoColor=white" alt="SQLite" />
  </p>
</div>

<br />

CodeRisk allows engineering and security teams to seamlessly scan local repositories or public GitHub URLs to detect critical vulnerabilities, leaked secrets, and infrastructure misconfigurations. **This is a local-first application designed for testing and learning.**

## Key Features & Engine Details

CodeRisk is powered by industry-standard security engines that run locally on your machine.

* **Secret Detection (`Gitleaks`):** 
  Scans entire commit histories for hardcoded secrets, passwords, API keys, and access tokens. It uses a rich set of regular expressions tailored to identify over 100+ different token types (AWS, GitHub, Slack, etc.).

* **Vulnerability Analysis (`Semgrep`):** 
  A fast and highly customizable static analysis tool. We use it to detect insecure coding patterns, business logic flaws, and OWASP Top 10 vulnerabilities (e.g., SQL Injection, XSS, Command Injection) across multiple languages including Python, JavaScript, TypeScript, and Go.

* **Software Composition Analysis (`OSV-Scanner`):** 
  Powered by Google's Open Source Vulnerabilities database. It deeply inspects `package.json`, `requirements.txt`, `pom.xml`, and lock files to find known CVEs and vulnerabilities in your third-party open-source dependencies.

* **Interactive Dashboard:** 
  A premium, dark-themed glassmorphism UI built with React. It provides real-time progress updates via WebSockets (or polling), dynamic severity metrics (High, Medium, Low), and historical score trends calculated by an intelligent risk-scoring algorithm.

---

## Interface Previews

### Security Scan Dashboard
Provides a unified view to initiate scans, track progress, and view security scores in real-time.

![Security Scan](./docs/scan-page.png)

### Scan History & Analytics
Track your organization's security posture over time with historical score trends and detailed vulnerability breakdowns.

![Scan History](./docs/history-page.png)

---

## Architecture & Tech Stack

CodeRisk is designed as a local-first application utilizing modern web technologies.

### Frontend
* **Framework:** React 18 with Vite
* **Language:** TypeScript
* **Styling:** Custom Vanilla CSS utilizing advanced Glassmorphism and CSS variables
* **State Management:** React Hooks

### Backend
* **Framework:** FastAPI (High-performance async Python framework)
* **Language:** Python 3.11
* **ORM:** SQLAlchemy (Async) with Alembic for database migrations
* **Task Execution:** Built-in Python `asyncio.subprocess` to orchestrate Gitleaks, Semgrep, and OSV-Scanner seamlessly.

### Database
* **Database:** SQLite (Local)
* **Structure:** Designed to securely store scan histories, user profiles, and vulnerability metadata locally on your machine.

---

## Local Development Setup

CodeRisk is designed to run locally on your own hardware. Follow these steps to get started:

### Prerequisites
* Node.js (v18 or higher)
* Python (3.11 or higher)
* [uv](https://github.com/astral-sh/uv) (Extremely fast Python package installer)
* Git

### 1. Clone the Repository
```bash
git clone https://github.com/Bor-Code-Code-Dashboard/CodeRisk-Dashboard.git
cd CodeRisk-Dashboard
```

### 2. Backend Setup
The backend runs the API and orchestrates the security scans.
```bash
cd backend
# Install Python dependencies using uv
uv sync

# Initialize the local SQLite database
uv run alembic upgrade head

# Start the FastAPI server on port 8000
uv run uvicorn app.main:app --reload
```
The backend API will be available at `http://127.0.0.1:8000`.

### 3. Frontend Setup
Open a new terminal window to start the user interface:
```bash
uv --directory backend run alembic upgrade head
```

Production configuration fails fast unless `CODERISK_DATABASE_URL` uses PostgreSQL with the psycopg driver and `CODERISK_JWT_SECRET_KEY` is a non-default secret with at least 32 characters. Automatic schema creation is restricted to isolated tests; production migrations must be applied explicitly. Integration credentials are redacted from API responses; use deployment-level secret storage and database protections for sensitive values.

## Quality checks

Run the same checks used by CI:

```bash
uv --directory backend run ruff check .
uv --directory backend run ruff format --check .
uv --directory backend run pytest --cov=app --cov-report=term-missing
uv --directory backend run python -m scripts.openapi_contract --check
npm --prefix frontend run lint
npm --prefix frontend run typecheck
npm --prefix frontend run test:coverage
npm --prefix frontend run build
```

Backend coverage must remain at or above 80%. Frontend coverage thresholds are configured in `frontend/vite.config.ts`.

## Repository layout

```text
backend/
  alembic/      Database migrations
  app/          API, domain, service, persistence, and scanner layers
  tests/        API, migration, persistence, report, and scanner tests
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
4. Gitleaks, Semgrep, OSV-Scanner, and SBOM integration;
5. authenticated dashboard workflows and self-hosted containers;
6. GitHub repository ingestion, observability, and release hardening.

The roadmap deliberately favors reviewable pull requests over a single large rewrite.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

Licensed under the [Apache License 2.0](LICENSE).
