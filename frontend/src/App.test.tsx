import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App'

const fetchMock = vi.fn()

const mockRepo = { id: 'repo-123' }
const mockScan = {
  id: 'scan-123',
  status: 'completed',
  score: 90,
  severity_counts: { high: 1, medium: 0, low: 0, info: 0 },
  total_files: 10,
  created_at: '2026-08-22T00:00:00Z',
}
const mockFindingsPage = {
  items: [
    {
      id: 'f-1',
      severity: 'high',
      title: 'Test finding',
      engine_id: 'built-in',
      rule_id: 'test-rule',
      file_path: 'src/app.py',
      evidence: 'test',
      remediation: 'fix',
    }
  ]
}

function jsonResponse(payload: unknown, ok = true): Response {
  return {
    ok,
    json: vi.fn().mockResolvedValue(payload),
  } as unknown as Response
}

describe('App', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockResolvedValue(jsonResponse({}))
    Object.defineProperty(window, 'localStorage', {
      value: {
        getItem: vi.fn(() => 'mock-token'),
        setItem: vi.fn(),
        removeItem: vi.fn(),
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
    render(<App />)

    expect(screen.getByText('Ready to scan')).toBeInTheDocument()

    const input = screen.getByLabelText('Target')
    await user.type(input, '/tmp/repo')

    // Mock API sequence:
    // 1. /engines (on mount)
    // 2. /repositories (POST)
    // 3. /repositories/repo-123/scans (POST)
    // 4. /scans/scan-123 (GET polling)
    // 5. /scans/scan-123/findings (GET)
    fetchMock.mockImplementation(async (url: string) => {
      if (url.includes('/engines')) return jsonResponse({ gitleaks: true })
      if (url.includes('/repositories/repo-123/scans')) return jsonResponse(mockScan)
      if (url.includes('/repositories')) return jsonResponse(mockRepo)
      if (url.includes('/scans/scan-123/findings')) return jsonResponse(mockFindingsPage)
      if (url.includes('/scans/scan-123')) return jsonResponse(mockScan)
      return jsonResponse({})
    })

    const scanBtn = screen.getByRole('button', { name: '▶ Scan' })
    await user.click(scanBtn)

    await waitFor(() => {
      expect(screen.getByText('Test finding')).toBeInTheDocument()
    })
  })

  it('allows switching to history tab', async () => {
    const user = userEvent.setup()
    render(<App />)
    
    const historyBtn = screen.getByRole('button', { name: /history/i })
    
    fetchMock.mockImplementation(async (url: string) => {
      if (url.includes('/scans?limit=50')) return jsonResponse({ items: [mockScan] })
      return jsonResponse({})
    })

    await user.click(historyBtn)
    
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Scan History' })).toBeInTheDocument()
    })
  })

  it('allows switching to settings tab and shows engine status', async () => {
    const user = userEvent.setup()
    
    fetchMock.mockImplementation(async (url: string) => {
      if (url.includes('/engines')) return jsonResponse({ gitleaks: true, semgrep: false, 'osv-scanner': false })
      return jsonResponse({})
    })

    render(<App />)
    
    const settingsBtn = screen.getByRole('button', { name: /settings/i })
    await user.click(settingsBtn)
    
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Settings' })).toBeInTheDocument()
    })
  })

  it('filters findings by severity', async () => {
    const user = userEvent.setup()
    render(<App />)

    const input = screen.getByLabelText('Target')
    await user.type(input, '/tmp/repo')

    fetchMock.mockImplementation(async (url: string) => {
      if (url.includes('/engines')) return jsonResponse({})
      if (url.includes('/repositories/repo-123/scans')) return jsonResponse(mockScan)
      if (url.includes('/repositories')) return jsonResponse(mockRepo)
      if (url.includes('/scans/scan-123/findings')) return jsonResponse(mockFindingsPage)
      if (url.includes('/scans/scan-123')) return jsonResponse(mockScan)
      return jsonResponse({})
    })

    const scanBtn = screen.getByRole('button', { name: '▶ Scan' })
    await user.click(scanBtn)

    await waitFor(() => {
      expect(screen.getByText('Test finding')).toBeInTheDocument()
    })

    // Filter by low severity (should hide the high severity finding)
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
})
