import { useState, useEffect, useCallback } from "react"
import type { FormEvent } from "react"
import "./App.css"

// ─── Types ──────────────────────────────────────────────────────────────────

type Severity = "high" | "medium" | "low" | "info"
type ScanStatus = "queued" | "running" | "completed" | "failed" | "cancelled"
type TargetType = "local_path" | "github_url"

interface Repository {
  id: string
  name: string
  target: string
  target_type: TargetType
  created_at: string
  updated_at: string
}

interface ScanSummary {
  id: string
  repository_id: string
  status: ScanStatus
  score: number | null
  total_files: number | null
  severity_counts: { high: number; medium: number; low: number; info: number }
  scanned_at_utc: string | null
  created_at: string
  started_at: string | null
  completed_at: string | null
  error_message: string | null
  attempt_count: number
  cancellation_requested_at: string | null
}

interface Finding {
  id: string
  scan_id: string
  source_finding_id: string
  category: string
  severity: Severity
  title: string
  file_path: string
  line: number | null
  evidence: string
  remediation: string
  engine_id: string
  rule_id: string | null
  created_at: string
}

interface Page<T> {
  items: T[]
  total: number
  offset: number
  limit: number
}

interface EngineAvailability {
  gitleaks: boolean
  semgrep: boolean
  "osv-scanner": boolean
}

// ─── API ────────────────────────────────────────────────────────────────────

const API = "http://127.0.0.1:8000/api/v1"

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const apiKey = window.localStorage?.getItem("coderisk_api_key")
  const headers: Record<string, string> = { "Content-Type": "application/json" }
  if (apiKey) {
    headers["X-API-Key"] = apiKey
  }

  const res = await fetch(`${API}${path}`, {
    headers: { ...headers, ...init?.headers },
    ...init,
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Request failed" }))
    throw new Error(err.detail ?? "Request failed")
  }
  return res.json() as Promise<T>
}

// ─── Hooks ───────────────────────────────────────────────────────────────────

function useScanPoller(
  scanId: string | null,
  onComplete: (scan: ScanSummary) => void
) {
  useEffect(() => {
    if (!scanId) return
    let stopped = false
    let timer: ReturnType<typeof setTimeout>

    async function poll() {
      if (stopped) return
      try {
        const scan = await apiFetch<ScanSummary>(`/scans/${scanId}`)
        if (scan.status === "completed" || scan.status === "failed" || scan.status === "cancelled") {
          onComplete(scan)
          return
        }
      } catch {
        // keep polling
      }
      timer = setTimeout(poll, 2000)
    }

    poll()
    return () => {
      stopped = true
      clearTimeout(timer)
    }
  }, [scanId, onComplete])
}

// ─── Sub-components ──────────────────────────────────────────────────────────

function ScoreBadge({ score }: { score: number | null }) {
  if (score === null) return <span className="score-badge neutral">—</span>
  const cls = score >= 80 ? "good" : score >= 50 ? "warn" : "bad"
  return <span className={`score-badge ${cls}`}>{score}/100</span>
}

function StatusPill({ status }: { status: ScanStatus }) {
  return <span className={`status-pill status-${status}`}>{status}</span>
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge sev-${severity}`}>{severity}</span>
}

function EngineBadge({ engineId }: { engineId: string }) {
  const cls =
    engineId === "gitleaks"
      ? "engine-gitleaks"
      : engineId === "semgrep"
        ? "engine-semgrep"
        : engineId === "osv-scanner"
          ? "engine-osv"
          : "engine-builtin"
  return <span className={`engine-badge ${cls}`}>{engineId}</span>
}

function EngineStatusBar({ engines }: { engines: EngineAvailability | null }) {
  if (!engines) return null
  const entries = Object.entries(engines) as [string, boolean][]
  return (
    <div className="engine-status-bar">
      <span className="engine-status-label">Engines:</span>
      {entries.map(([name, available]) => (
        <span
          key={name}
          className={`engine-status-pill ${available ? "engine-available" : "engine-unavailable"}`}
          title={available ? `${name} is installed` : `${name} not found on PATH`}
        >
          <span className="engine-dot" />
          {name}
        </span>
      ))}
    </div>
  )
}

// ─── Main App ────────────────────────────────────────────────────────────────

type Tab = "scan" | "history" | "settings"

export default function App() {
  const [tab, setTab] = useState<Tab>("scan")
  
  // Settings
  const [apiKey, setApiKey] = useState(() => window.localStorage?.getItem("coderisk_api_key") || "")

  const handleApiKeyChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = e.target.value
    setApiKey(val)
    if (val) {
      window.localStorage?.setItem("coderisk_api_key", val)
    } else {
      window.localStorage?.removeItem("coderisk_api_key")
    }
  }

  // scan form
  const [target, setTarget] = useState("")
  const [targetType, setTargetType] = useState<TargetType>("local_path")
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [formError, setFormError] = useState("")

  // active scan polling
  const [activeScanId, setActiveScanId] = useState<string | null>(null)
  const [activeScan, setActiveScan] = useState<ScanSummary | null>(null)
  const [isCancelling, setIsCancelling] = useState(false)

  // findings
  const [findings, setFindings] = useState<Finding[]>([])
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all")
  const [findingsLoading, setFindingsLoading] = useState(false)

  // history
  const [scanHistory, setScanHistory] = useState<ScanSummary[]>([])
  const [historyLoading, setHistoryLoading] = useState(false)

  // engines
  const [engines, setEngines] = useState<EngineAvailability | null>(null)

  // Load engine availability
  useEffect(() => {
    apiFetch<EngineAvailability>("/engines")
      .then(setEngines)
      .catch(() => null)
  }, [])

  // Poll active scan
  const handleScanComplete = useCallback(
    async (scan: ScanSummary) => {
      setActiveScan(scan)
      setActiveScanId(null)
      if (scan.status === "completed") {
        setFindingsLoading(true)
        try {
          const page = await apiFetch<Page<Finding>>(
            `/scans/${scan.id}/findings?limit=100`
          )
          setFindings(page.items)
        } catch {
          setFindings([])
        } finally {
          setFindingsLoading(false)
        }
      }
    },
    []
  )

  useScanPoller(activeScanId, handleScanComplete)

  // Submit scan
  async function handleScan(e: FormEvent<HTMLFormElement>) {
    e.preventDefault()
    setFormError("")
    setIsSubmitting(true)
    setActiveScan(null)
    setFindings([])

    try {
      // 1) Upsert repository
      const repo = await apiFetch<Repository>("/repositories", {
        method: "POST",
        body: JSON.stringify({ target: target.trim(), target_type: targetType }),
      })

      // 2) Enqueue scan
      const scan = await apiFetch<ScanSummary>(
        `/repositories/${repo.id}/scans`,
        { method: "POST" }
      )

      setActiveScan(scan)
      setActiveScanId(scan.id)
    } catch (err) {
      setFormError(err instanceof Error ? err.message : "Scan failed")
    } finally {
      setIsSubmitting(false)
    }
  }

  // Cancel scan
  async function handleCancel() {
    if (!activeScanId && !activeScan?.id) return
    const id = activeScanId ?? activeScan!.id
    setIsCancelling(true)
    try {
      await apiFetch(`/scans/${id}/cancel`, { method: "POST" })
    } catch {
      /* ignore */
    } finally {
      setIsCancelling(false)
    }
  }

  // Load history tab
  useEffect(() => {
    if (tab !== "history") return
    let active = true

    const load = async () => {
      // Defer state update to avoid synchronous cascade warnings
      await Promise.resolve()
      if (!active) return

      setHistoryLoading(true)
      try {
        const p = await apiFetch<Page<ScanSummary>>("/scans?limit=50")
        if (active) setScanHistory(p.items)
      } catch {
        if (active) setScanHistory([])
      } finally {
        if (active) setHistoryLoading(false)
      }
    }

    void load()

    return () => {
      active = false
    }
  }, [tab])

  const filteredFindings =
    severityFilter === "all"
      ? findings
      : findings.filter((f) => f.severity === severityFilter)

  const isScanning =
    activeScanId !== null ||
    activeScan?.status === "queued" ||
    activeScan?.status === "running"

  return (
    <div className="app-root">
      {/* ── Sidebar ── */}
      <nav className="sidebar">
        <div className="sidebar-brand">
          <span className="brand-icon">⚡</span>
          <span className="brand-name">CodeRisk</span>
        </div>

        <ul className="nav-list">
          {(["scan", "history", "settings"] as Tab[]).map((t) => (
            <li key={t}>
              <button
                className={`nav-item ${tab === t ? "active" : ""}`}
                onClick={() => setTab(t)}
              >
                <span className="nav-icon">
                  {t === "scan" ? "🔍" : t === "history" ? "📋" : "⚙️"}
                </span>
                {t.charAt(0).toUpperCase() + t.slice(1)}
              </button>
            </li>
          ))}
        </ul>

        <EngineStatusBar engines={engines} />
      </nav>

      {/* ── Main content ── */}
      <main className="main-content">
        {/* ══ SCAN TAB ══ */}
        {tab === "scan" && (
          <div className="tab-content">
            <header className="page-header">
              <div>
                <h1>Security Scan</h1>
                <p className="page-sub">
                  Scan a local repo path or a public GitHub URL for secrets,
                  misconfigurations, and vulnerabilities.
                </p>
              </div>
            </header>

            {/* Scan Form */}
            <form className="scan-form glass-panel" onSubmit={handleScan}>
              <div className="form-row">
                <div className="form-group flex-1">
                  <label htmlFor="target">Target</label>
                  <div className="input-group">
                    <select
                      id="target-type"
                      value={targetType}
                      onChange={(e) =>
                        setTargetType(e.target.value as TargetType)
                      }
                      className="type-select"
                    >
                      <option value="local_path">Local Path</option>
                      <option value="github_url">GitHub URL</option>
                    </select>
                    <input
                      id="target"
                      value={target}
                      onChange={(e) => setTarget(e.target.value)}
                      placeholder={
                        targetType === "local_path"
                          ? "C:\\Projects\\my-repo"
                          : "https://github.com/owner/repo"
                      }
                    />
                  </div>
                </div>

                <div className="form-actions">
                  <button
                    type="submit"
                    className="btn-primary"
                    disabled={!target.trim() || isSubmitting || isScanning}
                  >
                    {isSubmitting ? (
                      <>
                        <span className="spinner" /> Queuing…
                      </>
                    ) : (
                      "▶ Scan"
                    )}
                  </button>

                  {isScanning && (
                    <button
                      type="button"
                      className="btn-danger"
                      onClick={handleCancel}
                      disabled={isCancelling}
                    >
                      {isCancelling ? "Cancelling…" : "✕ Cancel"}
                    </button>
                  )}
                </div>
              </div>

              {formError && <p className="error-msg">{formError}</p>}
            </form>

            {/* Scan Status */}
            {activeScan && (
              <div className="status-card glass-panel">
                <div className="status-header">
                  <span className="status-title">
                    Scan {activeScan.id.slice(0, 8)}…
                  </span>
                  <StatusPill status={activeScan.status} />
                  <ScoreBadge score={activeScan.score} />
                </div>

                {isScanning && (
                  <div className="progress-track">
                    <div className="progress-bar-indeterminate" />
                  </div>
                )}

                <div className="status-meta">
                  <span>
                    Files:{" "}
                    <strong>{activeScan.total_files ?? "…"}</strong>
                  </span>
                  <span>
                    High:{" "}
                    <strong className="sev-high-text">
                      {activeScan.severity_counts.high}
                    </strong>
                  </span>
                  <span>
                    Medium:{" "}
                    <strong className="sev-medium-text">
                      {activeScan.severity_counts.medium}
                    </strong>
                  </span>
                  <span>
                    Low:{" "}
                    <strong className="sev-low-text">
                      {activeScan.severity_counts.low}
                    </strong>
                  </span>
                </div>

                {activeScan.error_message && (
                  <p className="error-msg">{activeScan.error_message}</p>
                )}
              </div>
            )}

            {/* Findings */}
            {activeScan?.status === "completed" && (
              <div className="findings-section glass-panel">
                <div className="findings-header">
                  <h2>
                    Findings{" "}
                    <span className="count-chip">{findings.length}</span>
                  </h2>
                  <select
                    aria-label="Filter by severity"
                    value={severityFilter}
                    onChange={(e) =>
                      setSeverityFilter(e.target.value as Severity | "all")
                    }
                  >
                    <option value="all">All severities</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="info">Info</option>
                  </select>
                </div>

                {findingsLoading ? (
                  <div className="loading-state">Loading findings…</div>
                ) : filteredFindings.length === 0 ? (
                  <div className="empty-findings">
                    <span>🎉</span>
                    <p>No findings at this severity level.</p>
                  </div>
                ) : (
                  <div className="table-scroll">
                    <table className="findings-table">
                      <thead>
                        <tr>
                          <th>Sev</th>
                          <th>Engine</th>
                          <th>Rule</th>
                          <th>Title</th>
                          <th>Location</th>
                          <th>Remediation</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredFindings.map((f) => (
                          <tr key={f.id}>
                            <td>
                              <SeverityBadge severity={f.severity} />
                            </td>
                            <td>
                              <EngineBadge engineId={f.engine_id} />
                            </td>
                            <td className="rule-cell">
                              {f.rule_id ?? f.source_finding_id.split("-")[1] ?? "—"}
                            </td>
                            <td>
                              <strong className="finding-title">{f.title}</strong>
                              <br />
                              <code className="evidence">{f.evidence}</code>
                            </td>
                            <td className="location-cell">
                              {f.file_path}
                              {f.line !== null ? (
                                <span className="line-num">:{f.line}</span>
                              ) : null}
                            </td>
                            <td className="remediation-cell">
                              {f.remediation}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {!activeScan && (
              <div className="empty-state glass-panel">
                <div className="empty-icon">🛡️</div>
                <h2>Ready to scan</h2>
                <p>
                  Enter a local repository path or a public GitHub URL above,
                  then press <strong>▶ Scan</strong>.
                </p>
              </div>
            )}
          </div>
        )}

        {/* ══ HISTORY TAB ══ */}
        {tab === "history" && (
          <div className="tab-content">
            <header className="page-header">
              <div>
                <h1>Scan History</h1>
                <p className="page-sub">All previous scans across repositories.</p>
              </div>
              <button
                className="btn-secondary"
                onClick={() => {
                  setHistoryLoading(true)
                  apiFetch<Page<ScanSummary>>("/scans?limit=50")
                    .then((p) => setScanHistory(p.items))
                    .catch(() => setScanHistory([]))
                    .finally(() => setHistoryLoading(false))
                }}
              >
                ↻ Refresh
              </button>
            </header>

            {historyLoading ? (
              <div className="loading-state glass-panel">Loading history…</div>
            ) : scanHistory.length === 0 ? (
              <div className="empty-state glass-panel">
                <div className="empty-icon">📋</div>
                <h2>No scans yet</h2>
                <p>Run your first scan from the Scan tab.</p>
              </div>
            ) : (
              <div className="history-table-wrap glass-panel">
                <table className="history-table">
                  <thead>
                    <tr>
                      <th>ID</th>
                      <th>Status</th>
                      <th>Score</th>
                      <th>High</th>
                      <th>Med</th>
                      <th>Low</th>
                      <th>Files</th>
                      <th>Created</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scanHistory.map((s) => (
                      <tr key={s.id}>
                        <td className="mono">{s.id.slice(0, 8)}…</td>
                        <td>
                          <StatusPill status={s.status} />
                        </td>
                        <td>
                          <ScoreBadge score={s.score} />
                        </td>
                        <td className="sev-high-text">
                          {s.severity_counts.high}
                        </td>
                        <td className="sev-medium-text">
                          {s.severity_counts.medium}
                        </td>
                        <td className="sev-low-text">{s.severity_counts.low}</td>
                        <td>{s.total_files ?? "—"}</td>
                        <td className="mono">
                          {new Date(s.created_at).toLocaleString()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* ══ SETTINGS TAB ══ */}
        {tab === "settings" && (
          <div className="tab-content">
            <header className="page-header">
              <div>
                <h1>Settings</h1>
                <p className="page-sub">Engine status and configuration.</p>
              </div>
            </header>

            <div className="settings-grid">
              <div className="settings-card glass-panel">
                <h2>External Engines</h2>
                <p className="settings-desc">
                  CodeRisk can augment its built-in scanner with third-party
                  tools. Install any of the engines below and restart the
                  backend to activate them.
                </p>
                <div className="engine-cards">
                  {engines &&
                    (
                      Object.entries(engines) as [string, boolean][]
                    ).map(([name, available]) => (
                      <div
                        key={name}
                        className={`engine-card ${available ? "engine-card-on" : "engine-card-off"}`}
                      >
                        <div className="engine-card-header">
                          <strong>{name}</strong>
                          <span
                            className={`engine-status-dot ${available ? "dot-on" : "dot-off"}`}
                          />
                        </div>
                        <p className="engine-card-status">
                          {available ? "✅ Available" : "⚠️ Not installed"}
                        </p>
                        <p className="engine-card-hint">
                          {name === "gitleaks" &&
                            "Secret scanning — detects leaked credentials in git history."}
                          {name === "semgrep" &&
                            "SAST — static analysis with thousands of community rules."}
                          {name === "osv-scanner" &&
                            "Dependency scanning — checks packages against the OSV vulnerability database."}
                        </p>
                      </div>
                    ))}
                </div>
              </div>

              <div className="settings-card glass-panel">
                <h2>API Authentication</h2>
                <p className="settings-desc">
                  If your backend requires an API key, enter it here. It will be stored locally in your browser.
                </p>
                <div className="form-group" style={{ marginTop: "1rem" }}>
                  <label htmlFor="api-key">API Key</label>
                  <input
                    id="api-key"
                    type="password"
                    value={apiKey}
                    onChange={handleApiKeyChange}
                    placeholder="Enter X-API-Key"
                    style={{ width: "100%", maxWidth: "400px" }}
                  />
                </div>
              </div>

              <div className="settings-card glass-panel">
                <h2>API Reference</h2>
                <p className="settings-desc">
                  The backend API documentation is available at{" "}
                  <a
                    href="http://127.0.0.1:8000/docs"
                    target="_blank"
                    rel="noreferrer"
                    className="link"
                  >
                    http://127.0.0.1:8000/docs
                  </a>
                  .
                </p>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  )
}
