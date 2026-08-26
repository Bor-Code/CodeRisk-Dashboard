import { useState, useEffect, useCallback } from "react"
import type { FormEvent } from "react"
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts"
import { Zap, Search, History, Settings, Shield, LayoutDashboard, Blocks, FileCheck, Users, FileText, Download } from "lucide-react"
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
  is_ignored: boolean
}

interface Page<T> {
  items: T[]
  total: number
  offset: number
  limit: number
}

interface ScanDiff {
  new: Finding[]
  resolved: Finding[]
  persistent: Finding[]
}

interface EngineAvailability {
  gitleaks: boolean
  semgrep: boolean
  "osv-scanner": boolean
}

interface UserProfile {
  id: string
  username: string
  first_name: string
  last_name: string
  phone_number: string
  created_at: string
}

interface GlobalFinding {
  id: string
  scan_id: string
  title: string
  severity: Severity
  category: string
  file_path: string
  created_at: string
}

interface ScanHistoryPoint {
  date: string
  scans: number
}

interface DashboardStats {
  total_scans: number
  total_findings: number
  high_findings: number
  history: ScanHistoryPoint[]
}

interface Integration {
  id: string
  name: string
  type: string
}

interface Policy {
  id: string
  name: string
  rule_type: string
  rule_value: string
}

// ─── API ────────────────────────────────────────────────────────────────────

const API = (import.meta.env.VITE_API_BASE_URL ?? "/api/v1").replace(/\/$/, "")

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const token = window.localStorage?.getItem("coderisk_token")
  const headers: Record<string, string> = { "Content-Type": "application/json" }
  if (token) {
    headers["Authorization"] = `Bearer ${token}`
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

type Tab = "dashboard" | "scan" | "vulnerabilities" | "reports" | "integrations" | "policies" | "team" | "history" | "settings"

function LoginScreen({ onLogin }: { onLogin: (token: string) => void }) {
  const [isRegister, setIsRegister] = useState(false)
  const [username, setUsername] = useState("")
  const [firstName, setFirstName] = useState("")
  const [lastName, setLastName] = useState("")
  const [phone, setPhone] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setError("")
    setLoading(true)
    try {
      if (isRegister) {
        await fetch(`${API}/auth/register`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ 
            username, 
            password,
            first_name: firstName,
            last_name: lastName,
            phone_number: phone
          })
        }).then(async r => {
          if (!r.ok) {
            const err = await r.json()
            throw new Error(err.detail || "Registration failed")
          }
        })
      }
      
      const formData = new URLSearchParams()
      formData.append("username", username)
      formData.append("password", password)
      
      const res = await fetch(`${API}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: formData
      })
      if (!res.ok) {
        const err = await res.json()
        throw new Error(err.detail || "Login failed")
      }
      const data = await res.json()
      onLogin(data.access_token)
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message)
      } else {
        setError("An unknown error occurred")
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-container">
      {/* Animated Background Elements */}
      <div className="bg-shape shape1"></div>
      <div className="bg-shape shape2"></div>
      <div className="bg-shape shape3"></div>

      <div className="login-content">
        <div className="glass-panel logo-card">
          <h2>CodeRisk</h2>
          <p>{isRegister ? "Secure Workspace Creation" : "Enterprise Security Portal"}</p>
        </div>
        
        <div className="glass-panel login-panel">
        <form onSubmit={handleSubmit} className="login-form">
          {isRegister && (
            <div className="name-row">
              <div className="form-group">
                <label htmlFor="firstName">First Name</label>
                <input
                  id="firstName"
                  type="text"
                  value={firstName}
                  onChange={e => setFirstName(e.target.value)}
                  required
                />
              </div>
              <div className="form-group">
                <label htmlFor="lastName">Last Name</label>
                <input
                  id="lastName"
                  type="text"
                  value={lastName}
                  onChange={e => setLastName(e.target.value)}
                  required
                />
              </div>
            </div>
          )}
          
          <div className="form-group">
            <label htmlFor="username">Username</label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={e => setUsername(e.target.value)} 
              required 
              minLength={3}
            />
          </div>

          {isRegister && (
            <div className="form-group">
              <label htmlFor="phone">Phone Number</label>
              <input id="phone" type="tel" value={phone} onChange={e => setPhone(e.target.value)} required />
            </div>
          )}
          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)} 
              required
              minLength={6}
            />
          </div>
          
          {error && <div className="error-msg">{error}</div>}
          
          <button type="submit" className="btn btn-primary login-btn" disabled={loading}>
            {loading ? "Please wait..." : (isRegister ? "Sign Up" : "Sign In")}
          </button>
        </form>
        <div className="toggle-mode">
          <button type="button" onClick={() => setIsRegister(!isRegister)}>
            {isRegister ? "Already have an account? Sign in" : "Don't have an account? Sign up"}
          </button>
        </div>
        </div>
      </div>
    </div>
  )
}

export default function App() {
  const [token, setToken] = useState(() => window.localStorage?.getItem("coderisk_token") || "")
  const [tab, setTab] = useState<Tab>("scan")
  
  const handleLogin = (newToken: string) => {
    setToken(newToken)
    window.localStorage?.setItem("coderisk_token", newToken)
  }

  const handleLogout = () => {
    setToken("")
    window.localStorage?.removeItem("coderisk_token")
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
  const [scanDiff, setScanDiff] = useState<ScanDiff | null>(null)

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


  // New States for Extensions
  const [users, setUsers] = useState<UserProfile[]>([])
  const [allFindings, setAllFindings] = useState<GlobalFinding[]>([])
  const [stats, setStats] = useState<DashboardStats | null>(null)

  const [integrations, setIntegrations] = useState<Integration[]>([])
  const [integrationName, setIntegrationName] = useState('')
  const [integrationType, setIntegrationType] = useState('github')
  const [integrationCreds, setIntegrationCreds] = useState('')
  
  const [policies, setPolicies] = useState<Policy[]>([])
  const [policyName, setPolicyName] = useState('')
  const [policyType, setPolicyType] = useState('threshold')
  const [policyValue, setPolicyValue] = useState('')

  useEffect(() => {
    if (tab === 'team') apiFetch<UserProfile[]>('/extensions/users').then(setUsers).catch(console.error)
    if (tab === 'vulnerabilities') apiFetch<GlobalFinding[]>('/extensions/findings/all').then(setAllFindings).catch(console.error)
    if (tab === 'dashboard') apiFetch<DashboardStats>('/extensions/stats').then(setStats).catch(console.error)
    if (tab === 'integrations') apiFetch<Integration[]>('/extensions/integrations').then(setIntegrations).catch(console.error)
    if (tab === 'policies') apiFetch<Policy[]>('/extensions/policies').then(setPolicies).catch(console.error)
  }, [tab])

  const handleAddIntegration = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      await apiFetch('/extensions/integrations', {
        method: 'POST',
        body: JSON.stringify({name: integrationName, integration_type: integrationType, credentials: integrationCreds})
      })
      setIntegrationName(''); setIntegrationCreds('')
      apiFetch<Integration[]>('/extensions/integrations').then(setIntegrations)
    } catch { alert('Failed to save integration') }
  }

  const handleAddPolicy = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      await apiFetch('/extensions/policies', {
        method: 'POST',
        body: JSON.stringify({name: policyName, rule_type: policyType, rule_value: policyValue})
      })
      setPolicyName(''); setPolicyValue('')
      apiFetch<Policy[]>('/extensions/policies').then(setPolicies)
    } catch { alert('Failed to save policy') }
  }

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
          const diff = await apiFetch<ScanDiff>(`/scans/${scan.id}/diff`)
          setScanDiff(diff)
        } catch {
          setFindings([])
          setScanDiff(null)
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

  // Download SBOM
  async function handleDownloadSBOM(scanId: string) {
    try {
      const data = await apiFetch<unknown>(`/scans/${scanId}/sbom`)
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" })
      const url = URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      a.download = `sbom-${scanId}.json`
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      alert("SBOM not available or failed to download.")
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

  if (!token) {
    return <LoginScreen onLogin={handleLogin} />
  }

  return (
    <div className="app-root">
      {/* ── Sidebar ── */}
      <nav className="sidebar glass-panel">
        <div style={{ padding: "0 8px 16px", borderBottom: "1px solid var(--border)", marginBottom: 8, display: "flex", flexDirection: "column" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <Zap className="brand-icon" size={24} style={{ color: "#6366f1" }} />
            <span className="brand-name">CodeRisk</span>
          </div>
          <span style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2, paddingLeft: 34 }}>developed by Bor-Code</span>
        </div>

        <ul className="nav-list">
          {([
            { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
            { id: "scan", label: "Scan", icon: Search },
            { id: "vulnerabilities", label: "Vulnerabilities", icon: Shield },
            { id: "reports", label: "Reports", icon: FileText },
            { id: "integrations", label: "Integrations", icon: Blocks },
            { id: "policies", label: "Policies", icon: FileCheck },
            { id: "team", label: "Team", icon: Users },
            { id: "history", label: "History", icon: History },
            { id: "settings", label: "Settings", icon: Settings }
          ] as const).map((item) => {
            const Icon = item.icon
            return (
              <li key={item.id}>
                <button
                  className={`nav-item ${tab === item.id ? "active" : ""}`}
                  onClick={() => setTab(item.id as Tab)}
                >
                  <Icon className="nav-icon" size={18} />
                  {item.label}
                </button>
              </li>
            )
          })}
        </ul>

        <EngineStatusBar engines={engines} />
      </nav>

      {/* ── Main content ── */}
      <main className="main-content">
        
        {tab === "dashboard" && (
          <div className="tab-content">
            <header className="page-header"><div><h1>Dashboard</h1><p className="page-sub">System-wide security overview</p></div></header>
            {stats && (
              <>
                <div style={{ display: 'flex', gap: '20px', flexWrap: 'wrap', marginBottom: '20px' }}>
                  <div className="glass-panel flex-1 hover-scale" style={{ textAlign: 'center', padding: '30px', borderTop: '2px solid var(--blue)' }}>
                    <h3 style={{ color: 'var(--text-secondary)', marginBottom: '10px' }}>Total Scans</h3>
                    <div style={{ fontSize: '42px', fontWeight: '800', color: '#fff' }}>{stats.total_scans}</div>
                  </div>
                  <div className="glass-panel flex-1 hover-scale" style={{ textAlign: 'center', padding: '30px', borderTop: '2px solid var(--accent)' }}>
                    <h3 style={{ color: 'var(--text-secondary)', marginBottom: '10px' }}>Total Findings</h3>
                    <div style={{ fontSize: '42px', fontWeight: '800', color: '#fff' }}>{stats.total_findings}</div>
                  </div>
                  <div className="glass-panel flex-1 hover-scale" style={{ textAlign: 'center', padding: '30px', borderTop: '2px solid var(--red)' }}>
                    <h3 style={{ color: 'var(--text-secondary)', marginBottom: '10px' }}>High Risk Findings</h3>
                    <div style={{ fontSize: '42px', fontWeight: '800', color: '#fff' }}>{stats.high_findings}</div>
                  </div>
                </div>
                
                <div style={{ display: 'flex', gap: '20px' }}>
                  <div className="glass-panel" style={{ flex: 1, padding: '20px' }}>
                    <h3 style={{ marginBottom: '20px', color: 'var(--text-primary)' }}>Scan History (Last 7 Days)</h3>
                    <ResponsiveContainer width="100%" height={300}>
                      <LineChart data={stats.history || []}>
                        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                        <XAxis dataKey="date" stroke="var(--text-secondary)" />
                        <YAxis stroke="var(--text-secondary)" />
                        <Tooltip contentStyle={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '8px' }} />
                        <Line type="monotone" dataKey="scans" stroke="var(--accent)" strokeWidth={3} activeDot={{ r: 8 }} />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              </>
            )}
          </div>
        )}

        {tab === "team" && (
          <div className="tab-content">
            <header className="page-header"><div><h1>Team</h1><p className="page-sub">Manage registered users</p></div></header>
            <div className="glass-panel table-scroll">
              <table className="history-table">
                <thead><tr><th>Username</th><th>First Name</th><th>Last Name</th><th>Phone</th><th>Joined</th></tr></thead>
                <tbody>
                  {users.map((u, i) => (
                    <tr key={i}><td>{u.username}</td><td>{u.first_name}</td><td>{u.last_name}</td><td>{u.phone_number}</td><td className="mono">{new Date(u.created_at).toLocaleDateString()}</td></tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {tab === "vulnerabilities" && (
          <div className="tab-content">
            <header className="page-header"><div><h1>Global Vulnerabilities</h1><p className="page-sub">All findings across all projects</p></div></header>
            <div className="glass-panel table-scroll">
              <table className="findings-table">
                <thead><tr><th>Severity</th><th>Title</th><th>Category</th><th>File Path</th><th>Date</th></tr></thead>
                <tbody>
                  {allFindings.map((f, i) => (
                    <tr key={i}>
                      <td><span className={`badge sev-${f.severity}`}>{f.severity}</span></td>
                      <td><strong>{f.title}</strong></td>
                      <td>{f.category}</td>
                      <td><code className="evidence">{f.file_path}</code></td>
                      <td className="mono">{new Date(f.created_at).toLocaleDateString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {tab === "integrations" && (
          <div className="tab-content">
            <header className="page-header"><div><h1>Integrations</h1><p className="page-sub">Connect external services</p></div></header>
            <form className="glass-panel" onSubmit={handleAddIntegration} style={{ display: 'flex', gap: '15px', alignItems: 'flex-end', marginBottom: '30px', padding: '24px' }}>
              <div className="form-group">
                <label htmlFor="integrationName">Name</label>
                <input
                  id="integrationName"
                  required
                  value={integrationName}
                  onChange={e => setIntegrationName(e.target.value)}
                  placeholder="My GitHub"
                />
              </div>
              <div className="form-group">
                <label htmlFor="integrationType">Type</label>
                <select
                  id="integrationType"
                  className="type-select"
                  style={{ height: '44px', borderRadius: '6px' }}
                  value={integrationType}
                  onChange={e => setIntegrationType(e.target.value)}
                >
                  <option value="github">GitHub</option>
                  <option value="slack">Slack</option>
                </select>
              </div>
              <div className="form-group flex-1">
                <label htmlFor="integrationCreds">Token / Webhook URL</label>
                <input
                  id="integrationCreds"
                  required
                  type="password"
                  value={integrationCreds}
                  onChange={e => setIntegrationCreds(e.target.value)}
                  placeholder="ghp_..."
                />
              </div>
              <button className="btn-primary" type="submit">Save</button>
            </form>
            <div className="glass-panel table-scroll">
              <table className="history-table">
                <thead><tr><th>Name</th><th>Type</th></tr></thead>
                <tbody>
                  {integrations.map((i, idx) => (
                    <tr key={idx}><td>{i.name}</td><td>{i.type}</td></tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {tab === "policies" && (
          <div className="tab-content">
            <header className="page-header"><div><h1>Security Policies</h1><p className="page-sub">Define global security rules</p></div></header>
            <form className="glass-panel" onSubmit={handleAddPolicy} style={{ display: 'flex', gap: '15px', alignItems: 'flex-end', marginBottom: '30px', padding: '24px' }}>
              <div className="form-group">
                <label htmlFor="policyName">Policy Name</label>
                <input
                  id="policyName"
                  required
                  value={policyName}
                  onChange={e => setPolicyName(e.target.value)}
                  placeholder="Fail on Critical"
                />
              </div>
              <div className="form-group">
                <label htmlFor="policyType">Rule Type</label>
                <select
                  id="policyType"
                  className="type-select"
                  style={{ height: '44px', borderRadius: '6px' }}
                  value={policyType}
                  onChange={e => setPolicyType(e.target.value)}
                >
                  <option value="max_severity">Max Severity</option>
                  <option value="min_score">Min Score</option>
                </select>
              </div>
              <div className="form-group flex-1">
                <label htmlFor="policyValue">Value</label>
                <input
                  id="policyValue"
                  required
                  value={policyValue}
                  onChange={e => setPolicyValue(e.target.value)}
                  placeholder="high"
                />
              </div>
              <button className="btn-primary" type="submit">Add Policy</button>
            </form>
            <div className="glass-panel table-scroll">
              <table className="history-table">
                <thead><tr><th>Policy Name</th><th>Rule</th><th>Value</th></tr></thead>
                <tbody>
                  {policies.map((p, idx) => (
                    <tr key={idx}><td>{p.name}</td><td>{p.rule_type}</td><td>{p.rule_value}</td></tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {tab === "reports" && (
          <div className="tab-content">
            <header className="page-header"><div><h1>Reports</h1><p className="page-sub">Generate compliance and security reports</p></div></header>
            <div className="empty-state glass-panel">
              <FileText size={64} style={{ margin: "0 auto 16px", color: "var(--text-muted)" }} />
              <h2>Export Options</h2>
              <p>Download full system reports for auditing and compliance.</p>
              <div style={{ marginTop: '20px', display: 'flex', gap: '10px', justifyContent: 'center' }}>
                <button type="button" className="btn-secondary" onClick={() => alert('PDF export initialized.')}><Download size={14} style={{marginRight: 4}}/> PDF Report</button>
                <button type="button" className="btn-secondary" onClick={() => alert('CSV export initialized.')}><Download size={14} style={{marginRight: 4}}/> CSV Export</button>
              </div>
            </div>
          </div>
        )}

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
                  
                  {activeScan.status === "completed" && (
                    <button 
                      className="btn-outline" 
                      style={{marginLeft: "auto", fontSize: "0.85rem", padding: "0.3rem 0.6rem"}}
                      onClick={() => handleDownloadSBOM(activeScan.id)}
                    >
                      <Download size={14} style={{marginRight: 4, verticalAlign: 'middle'}}/> Download SBOM
                    </button>
                  )}
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

                {scanDiff && (
                  <div className="diff-badges" style={{ marginTop: "1rem", display: "flex", gap: "0.75rem", fontSize: "0.9rem" }}>
                    <span style={{ padding: "0.25rem 0.75rem", borderRadius: "12px", backgroundColor: "rgba(255,71,87,0.15)", color: "#ff4757", border: "1px solid rgba(255,71,87,0.3)" }}>
                      +{scanDiff.new?.length ?? 0} New
                    </span>
                    <span style={{ padding: "0.25rem 0.75rem", borderRadius: "12px", backgroundColor: "rgba(46,213,115,0.15)", color: "#2ed573", border: "1px solid rgba(46,213,115,0.3)" }}>
                      -{scanDiff.resolved?.length ?? 0} Resolved
                    </span>
                    <span style={{ padding: "0.25rem 0.75rem", borderRadius: "12px", backgroundColor: "rgba(255,255,255,0.1)", color: "#ccc", border: "1px solid rgba(255,255,255,0.2)" }}>
                      {scanDiff.persistent?.length ?? 0} Persistent
                    </span>
                  </div>
                )}

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
                    <span><Shield size={32} style={{color:'var(--text-muted)'}}/></span>
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
                          <th>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredFindings.map((f) => (
                          <tr key={f.id} style={{ opacity: f.is_ignored ? 0.5 : 1 }}>
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
                            <td>
                              <button
                                type="button"
                                className="btn-secondary"
                                style={{ padding: "0.25rem 0.5rem", fontSize: "0.8rem", opacity: f.is_ignored ? 0.5 : 1 }}
                                onClick={async () => {
                                  if (!activeScan) return;
                                  try {
                                    if (f.is_ignored) {
                                      await apiFetch(`/repositories/${activeScan.repository_id}/ignored-findings/${f.source_finding_id}`, { method: "DELETE" });
                                      setFindings(findings.map(item => item.id === f.id ? { ...item, is_ignored: false } : item));
                                    } else {
                                      await apiFetch(`/repositories/${activeScan.repository_id}/ignored-findings`, {
                                        method: "POST",
                                        body: JSON.stringify({ source_finding_id: f.source_finding_id, reason: "False positive" }),
                                      });
                                      setFindings(findings.map(item => item.id === f.id ? { ...item, is_ignored: true } : item));
                                    }
                                  } catch (e) {
                                    alert(e instanceof Error ? e.message : "Failed to ignore finding");
                                  }
                                }}
                              >
                                {f.is_ignored ? "Restore" : "Ignore"}
                              </button>
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
                <div className="empty-icon"><History size={48} style={{margin:'0 auto 16px', color:'var(--text-muted)'}}/></div>
                <h2>No scans yet</h2>
                <p>Run your first scan from the Scan tab.</p>
              </div>
            ) : (
              <>
                <div className="glass-panel" style={{ marginBottom: "2rem", height: "300px", padding: "1rem" }}>
                  <h2 style={{ marginBottom: "1rem", marginTop: 0 }}>Score Trend</h2>
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={[...scanHistory].reverse()}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                      <XAxis 
                        dataKey="created_at" 
                        tickFormatter={(val: string) => new Date(val).toLocaleDateString()} 
                        stroke="#888" 
                      />
                      <YAxis stroke="#888" domain={[0, 100]} />
                      <Tooltip 
                        labelFormatter={(val: string) => new Date(val).toLocaleString()}
                        contentStyle={{ backgroundColor: "#1a1a2e", border: "1px solid #4a4e69", borderRadius: "8px" }}
                      />
                      <Line 
                        type="monotone" 
                        dataKey="score" 
                        stroke="#00f2fe" 
                        strokeWidth={3} 
                        dot={{ r: 4, fill: "#4facfe" }} 
                        activeDot={{ r: 6 }} 
                        animationDuration={1500}
                      />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
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
                      <th>Actions</th>
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
                        <td>
                          {s.status === "completed" && (
                            <button
                              className="btn-outline"
                              style={{ padding: "0.2rem 0.5rem", fontSize: "0.8rem" }}
                              onClick={() => handleDownloadSBOM(s.id)}
                              title="Download SBOM"
                            >
                              <Download size={14} style={{marginRight: 4, verticalAlign: 'middle'}}/> SBOM
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              </>
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
                <h2>User Account</h2>
                <p className="settings-desc">
                  You are logged in to the dashboard.
                </p>
                <div style={{ marginTop: "1rem" }}>
                  <button onClick={handleLogout} className="btn btn-secondary">
                    Logout
                  </button>
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
