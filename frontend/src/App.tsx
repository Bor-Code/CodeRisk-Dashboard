import type { FormEvent } from "react"
import { useMemo, useState } from "react"
import "./App.css"

type Severity = "high" | "medium" | "low" | "info"

type Finding = {
  id: string
  rule_id?: string | null
  category: string
  severity: Severity
  title: string
  file_path: string
  line: number | null
  evidence: string
  remediation: string
}

type ScanReport = {
  metadata: {
    name: string
    root_path: string
    scanned_at_utc: string
    total_files: number
    dependency_files: string[]
  }
  findings: Finding[]
  severity_counts: Record<Severity, number>
  score: number
  file_tree: string[]
}

const apiBaseUrl = "http://127.0.0.1:8000"

function App() {
  const [target, setTarget] = useState("")
  const [severity, setSeverity] = useState<Severity | "all">("all")
  const [report, setReport] = useState<ScanReport | null>(null)
  const [error, setError] = useState("")
  const [isLoading, setIsLoading] = useState(false)

  const filteredFindings = useMemo(() => {
    if (!report) {
      return []
    }

    if (severity === "all") {
      return report.findings
    }

    return report.findings.filter((finding) => finding.severity === severity)
  }, [report, severity])

  async function handleScan(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError("")
    setIsLoading(true)

    try {
      const response = await fetch(`${apiBaseUrl}/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          target,
          target_type: "local_path",
        }),
      })

      const payload = await response.json()

      if (!response.ok) {
        throw new Error(payload.detail ?? "Scan failed")
      }

      setReport(payload)
      setSeverity("all")
    } catch (scanError) {
      setError(scanError instanceof Error ? scanError.message : "Scan failed")
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <main className="app-shell">
      <section className="hero">
        <div>
          <p className="eyebrow">Mini DevSecOps Security Dashboard</p>
          <h1>CodeRisk Dashboard</h1>
          <p className="hero-copy">
            Scan a local repository and review dependency, secret, configuration,
            and basic SAST findings in one place.
          </p>
        </div>

        <form className="scan-panel" onSubmit={handleScan}>
          <label htmlFor="target">Repository Path</label>
          <div className="scan-row">
            <input
              id="target"
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              placeholder="/path/to/repository"
            />
            <button disabled={target.trim().length === 0 || isLoading} type="submit">
              {isLoading ? "Scanning" : "Scan"}
            </button>
          </div>
          {error ? <p className="error-message">{error}</p> : null}
        </form>
      </section>

      {report ? (
        <>
          <section className="summary-grid">
            <article
              className={`summary-card score-card ${
                report.score >= 80 ? "good" : report.score >= 50 ? "warn" : "bad"
              }`}
            >
              <span>Security Score</span>
              <strong>{report.score}/100</strong>
            </article>
            <article className="summary-card">
              <span>High</span>
              <strong>{report.severity_counts.high}</strong>
            </article>
            <article className="summary-card">
              <span>Medium</span>
              <strong>{report.severity_counts.medium}</strong>
            </article>
            <article className="summary-card">
              <span>Low</span>
              <strong>{report.severity_counts.low}</strong>
            </article>
          </section>

          <section className="dashboard-grid">
            <div className="findings-panel">
              <div className="panel-header">
                <div>
                  <h2>Findings</h2>
                  <p>{filteredFindings.length} risk item shown</p>
                </div>
                <select
                  aria-label="Severity filter"
                  value={severity}
                  onChange={(event) => setSeverity(event.target.value as Severity | "all")}
                >
                  <option value="all">All severities</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                  <option value="info">Info</option>
                </select>
              </div>

              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Severity</th>
                      <th>Category</th>
                      <th>Rule</th>
                      <th>Finding</th>
                      <th>Path</th>
                      <th>Remediation</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredFindings.map((finding) => (
                      <tr key={finding.id}>
                        <td>
                          <span className={`badge ${finding.severity}`}>
                            {finding.severity}
                          </span>
                        </td>
                        <td>{finding.category}</td>
                        <td>{finding.rule_id ?? (finding.id.split('-')[1] ?? '-')}</td>
                        <td>
                          <strong>{finding.title}</strong>
                          <span>{finding.evidence}</span>
                        </td>
                        <td>
                          {finding.line !== null
                            ? `${finding.file_path}:${finding.line}`
                            : finding.file_path}
                        </td>
                        <td>{finding.remediation}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <aside className="repo-panel">
              <h2>Repo Summary</h2>
              <dl>
                <div>
                  <dt>Name</dt>
                  <dd>{report.metadata.name}</dd>
                </div>
                <div>
                  <dt>Total Files</dt>
                  <dd>{report.metadata.total_files}</dd>
                </div>
                <div>
                  <dt>Dependency Files</dt>
                  <dd>{report.metadata.dependency_files.join(", ") || "None"}</dd>
                </div>
                <div>
                  <dt>Exports</dt>
                  <dd>
                    <a
                      href={`${apiBaseUrl}/reports/latest.json`}
                      target="_blank"
                      rel="noreferrer"
                    >
                      JSON
                    </a>
                    <a
                      href={`${apiBaseUrl}/reports/latest.md`}
                      target="_blank"
                      rel="noreferrer"
                    >
                      Markdown
                    </a>
                  </dd>
                </div>
              </dl>
            </aside>
          </section>
        </>
      ) : (
        <section className="empty-state">
          <h2>Waiting for scan</h2>
          <p>
            Start the backend, enter a local repository path, and generate your first
            security report.
          </p>
        </section>
      )}
    </main>
  )
}

export default App
