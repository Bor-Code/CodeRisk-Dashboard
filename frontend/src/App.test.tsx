import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App'

const fetchMock = vi.fn()
let storedToken = 'mock-token'

const mockRepo = { id: 'repo-123' }
const mockScan = {
  id: 'scan-123',
  repository_id: 'repo-123',
  status: 'completed',
  score: 90,
  severity_counts: { high: 1, medium: 0, low: 0, info: 0 },
  total_files: 10,
  scanned_at_utc: '2026-08-22T00:00:00Z',
  created_at: '2026-08-22T00:00:00Z',
  started_at: '2026-08-22T00:00:00Z',
  completed_at: '2026-08-22T00:00:01Z',
  error_message: null,
  attempt_count: 1,
  cancellation_requested_at: null,
}
const mockFindingsPage = {
  items: [
    {
      id: 'f-1',
      scan_id: 'scan-123',
      source_finding_id: 'secret-test-rule-src-app-py-1',
      severity: 'high',
      category: 'secret',
      title: 'Test finding',
      engine_id: 'built-in',
      rule_id: 'test-rule',
      file_path: 'src/app.py',
      line: 1,
      evidence: 'test',
      remediation: 'fix',
      created_at: '2026-08-22T00:00:00Z',
      is_ignored: false,
    }
  ],
  total: 1,
  offset: 0,
  limit: 100,
}
const emptyDiff = { new: [], resolved: [], persistent: [] }

function jsonResponse(payload: unknown, ok = true): Response {
  return {
    ok,
    json: vi.fn().mockResolvedValue(payload),
  } as unknown as Response
}

function mockAuthenticatedApi() {
  fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
    if (url.includes('/engines')) return jsonResponse({ gitleaks: true, semgrep: false, 'osv-scanner': false })
    if (url.includes('/repositories/repo-123/scans')) return jsonResponse(mockScan)
    if (url.includes('/repositories')) return jsonResponse(mockRepo)
    if (url.includes('/scans/scan-123/findings')) return jsonResponse(mockFindingsPage)
    if (url.includes('/scans/scan-123/diff')) return jsonResponse(emptyDiff)
    if (url.includes('/scans/scan-123/sbom')) return jsonResponse({ bomFormat: 'CycloneDX' })
    if (url.includes('/scans/scan-123/cancel') && init?.method === 'POST') return jsonResponse({ status: 'cancelling' })
    if (url.includes('/scans/scan-123')) return jsonResponse(mockScan)
    if (url.includes('/scans?limit=50')) return jsonResponse({ items: [mockScan], total: 1, offset: 0, limit: 50 })
    return jsonResponse({})
  })
}

describe('App', () => {
  beforeEach(() => {
    storedToken = 'mock-token'
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockResolvedValue(jsonResponse({}))
    Object.defineProperty(window, 'localStorage', {
      value: {
        getItem: vi.fn(() => storedToken),
        setItem: vi.fn((_key: string, value: string) => {
          storedToken = value
        }),
        removeItem: vi.fn(() => {
          storedToken = ''
        }),
      },
      writable: true
    })
  })

  afterEach(() => {
    fetchMock.mockReset()
    vi.unstubAllGlobals()
  })

  it('renders empty state and allows scan submission', async () => {
    const user = userEvent.setup()
    mockAuthenticatedApi()
    render(<App />)

    expect(screen.getByText('Ready to scan')).toBeInTheDocument()

    const input = screen.getByLabelText('Target')
    await user.type(input, '/tmp/repo')

    const scanBtn = screen.getByRole('button', { name: '▶ Scan' })
    await user.click(scanBtn)

    await waitFor(() => {
      expect(screen.getByText('Test finding')).toBeInTheDocument()
    })
  })

  it('logs in when no token exists', async () => {
    storedToken = ''
    const user = userEvent.setup()
    fetchMock.mockImplementation(async (url: string) => {
      if (url.includes('/auth/login')) return jsonResponse({ access_token: 'new-token', token_type: 'bearer' })
      if (url.includes('/engines')) return jsonResponse({})
      return jsonResponse({})
    })

    render(<App />)

    await user.type(screen.getByLabelText('Username'), 'alice')
    await user.type(screen.getByLabelText('Password'), 'password123')
    await user.click(screen.getByRole('button', { name: 'Sign In' }))

    await waitFor(() => {
      expect(window.localStorage.setItem).toHaveBeenCalledWith('coderisk_token', 'new-token')
    })
  })

  it('registers a new user and then logs in', async () => {
    storedToken = ''
    const user = userEvent.setup()
    fetchMock.mockImplementation(async (url: string) => {
      if (url.includes('/auth/register')) return jsonResponse({ id: 'u-1', username: 'alice' })
      if (url.includes('/auth/login')) return jsonResponse({ access_token: 'new-token', token_type: 'bearer' })
      if (url.includes('/engines')) return jsonResponse({})
      return jsonResponse({})
    })

    render(<App />)

    await user.click(screen.getByRole('button', { name: /sign up/i }))
    await user.type(screen.getByLabelText('First Name'), 'Alice')
    await user.type(screen.getByLabelText('Last Name'), 'Example')
    await user.type(screen.getByLabelText('Username'), 'alice')
    await user.type(screen.getByLabelText('Phone Number'), '+15555550100')
    await user.type(screen.getByLabelText('Password'), 'password123')
    await user.click(screen.getByRole('button', { name: 'Sign Up' }))

    await waitFor(() => {
      expect(window.localStorage.setItem).toHaveBeenCalledWith('coderisk_token', 'new-token')
    })
  })

  it('allows switching to history tab', async () => {
    const user = userEvent.setup()
    mockAuthenticatedApi()
    render(<App />)

    const historyBtn = screen.getByRole('button', { name: /history/i })
    await user.click(historyBtn)

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Scan History' })).toBeInTheDocument()
    })
    expect(screen.getByText('SBOM')).toBeInTheDocument()
  })

  it('allows switching to settings tab, shows engine status, and logs out', async () => {
    const user = userEvent.setup()
    mockAuthenticatedApi()
    render(<App />)

    const settingsBtn = screen.getByRole('button', { name: /settings/i })
    await user.click(settingsBtn)

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Settings' })).toBeInTheDocument()
    })

    await user.click(screen.getByRole('button', { name: 'Logout' }))
    expect(window.localStorage.removeItem).toHaveBeenCalledWith('coderisk_token')
    expect(screen.getByRole('button', { name: 'Sign In' })).toBeInTheDocument()
  })

  it('filters findings by severity and toggles ignore state', async () => {
    const user = userEvent.setup()
    mockAuthenticatedApi()
    render(<App />)

    await user.type(screen.getByLabelText('Target'), '/tmp/repo')
    await user.click(screen.getByRole('button', { name: '▶ Scan' }))

    await waitFor(() => {
      expect(screen.getByText('Test finding')).toBeInTheDocument()
    })

    await user.click(screen.getByRole('button', { name: 'Ignore' }))
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Restore' })).toBeInTheDocument()
    })

    const select = screen.getByLabelText('Filter by severity')
    await user.selectOptions(select, 'low')

    expect(screen.queryByText('Test finding')).not.toBeInTheDocument()
  })

  it('handles scan submission errors', async () => {
    const user = userEvent.setup()
    render(<App />)

    const input = screen.getByLabelText('Target')
    await user.type(input, '/tmp/error-repo')

    fetchMock.mockImplementation(async (url: string) => {
      if (url.includes('/repositories')) return jsonResponse({ detail: 'Repository not found' }, false)
      return jsonResponse({})
    })

    const scanBtn = screen.getByRole('button', { name: '▶ Scan' })
    await user.click(scanBtn)

    await waitFor(() => {
      expect(screen.getByText('Repository not found')).toBeInTheDocument()
    })
  })

  it('renders dashboard, team, vulnerabilities, integrations, policies, and reports tabs', async () => {
    const user = userEvent.setup()
    const alertMock = vi.fn()
    vi.stubGlobal('alert', alertMock)
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
      if (url.includes('/engines')) return jsonResponse({})
      if (url.includes('/extensions/stats')) {
        return jsonResponse({
          total_scans: 3,
          total_findings: 8,
          high_findings: 2,
          history: [{ date: '2026-08-22', scans: 3 }],
        })
      }
      if (url.includes('/extensions/users')) {
        return jsonResponse([
          {
            id: 'u-1',
            username: 'alice',
            first_name: 'Alice',
            last_name: 'Example',
            phone_number: '+15555550100',
            created_at: '2026-08-22T00:00:00Z',
          },
        ])
      }
      if (url.includes('/extensions/findings/all')) {
        return jsonResponse([
          {
            id: 'f-1',
            scan_id: 'scan-123',
            title: 'Global finding',
            severity: 'high',
            category: 'secret',
            file_path: 'src/app.py',
            created_at: '2026-08-22T00:00:00Z',
          },
        ])
      }
      if (url.includes('/extensions/integrations') && init?.method === 'POST') {
        return jsonResponse({ id: 'i-1', name: 'GitHub', type: 'github' })
      }
      if (url.includes('/extensions/integrations')) {
        return jsonResponse([{ id: 'i-1', name: 'GitHub', type: 'github' }])
      }
      if (url.includes('/extensions/policies') && init?.method === 'POST') {
        return jsonResponse({ id: 'p-1', name: 'Fail high', rule_type: 'max_severity', rule_value: 'high' })
      }
      if (url.includes('/extensions/policies')) {
        return jsonResponse([{ id: 'p-1', name: 'Fail high', rule_type: 'max_severity', rule_value: 'high' }])
      }
      return jsonResponse({})
    })

    render(<App />)

    await user.click(screen.getByRole('button', { name: /dashboard/i }))
    await waitFor(() => expect(screen.getByText('Total Scans')).toBeInTheDocument())
    expect(screen.getByText('3')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /team/i }))
    await waitFor(() => expect(screen.getByText('alice')).toBeInTheDocument())

    await user.click(screen.getByRole('button', { name: /vulnerabilities/i }))
    await waitFor(() => expect(screen.getByText('Global finding')).toBeInTheDocument())

    await user.click(screen.getByRole('button', { name: /integrations/i }))
    await waitFor(() => expect(screen.getAllByText('GitHub').length).toBeGreaterThan(0))
    await user.type(screen.getByLabelText('Name'), 'GitHub')
    await user.type(screen.getByLabelText('Token / Webhook URL'), 'token')
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/extensions/integrations'),
      expect.objectContaining({ method: 'POST' })
    ))

    await user.click(screen.getByRole('button', { name: /policies/i }))
    await waitFor(() => expect(screen.getByText('Fail high')).toBeInTheDocument())
    await user.type(screen.getByLabelText('Policy Name'), 'Fail high')
    await user.type(screen.getByLabelText('Value'), 'high')
    await user.click(screen.getByRole('button', { name: 'Add Policy' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/extensions/policies'),
      expect.objectContaining({ method: 'POST' })
    ))

    await user.click(screen.getByRole('button', { name: /reports/i }))
    await user.click(screen.getByRole('button', { name: /PDF Report/i }))
    await user.click(screen.getByRole('button', { name: /CSV Export/i }))
    expect(alertMock).toHaveBeenCalledTimes(2)
  })
})
