import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App'

const fetchMock = vi.fn()

const scanReport = {
  metadata: {
    name: 'sample-repo',
    root_path: '/repos/sample-repo',
    scanned_at_utc: '2026-08-22T00:00:00+00:00',
    total_files: 12,
    dependency_files: ['package.json'],
  },
  findings: [
    {
      id: 'high-finding',
      category: 'sast',
      severity: 'high',
      title: 'Possible hardcoded password',
      file_path: 'src/app.py',
      line: 4,
      evidence: 'password=***',
      remediation: 'Move passwords to a secret manager.',
    },
    {
      id: 'low-finding',
      category: 'sast',
      severity: 'low',
      title: 'Insecure HTTP URL',
      file_path: 'src/client.ts',
      line: null,
      evidence: "const api = '[sanitized URL]'",
      remediation: 'Prefer HTTPS endpoints.',
    },
    {
      id: 'info-finding',
      category: 'dependency',
      severity: 'info',
      title: 'Dependency manifest files detected',
      file_path: 'package.json',
      line: null,
      evidence: '1 dependency file found.',
      remediation: 'Run a dependency vulnerability scanner.',
    },
  ],
  severity_counts: {
    high: 1,
    medium: 0,
    low: 1,
    info: 1,
  },
  score: 90,
  file_tree: ['package.json', 'src/app.py', 'src/client.ts'],
}

function jsonResponse(payload: unknown, ok = true): Response {
  return {
    ok,
    json: vi.fn().mockResolvedValue(payload),
  } as unknown as Response
}

async function submitScan() {
  const user = userEvent.setup()
  await user.type(screen.getByLabelText('Repository Path'), '/repos/sample-repo')
  await user.click(screen.getByRole('button', { name: 'Scan' }))
  return user
}

describe('App', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    fetchMock.mockReset()
    vi.unstubAllGlobals()
  })

  it('starts with an accessible empty scan form', async () => {
    const user = userEvent.setup()
    render(<App />)

    const scanButton = screen.getByRole('button', { name: 'Scan' })
    expect(screen.getByRole('heading', { name: 'Waiting for scan' })).toBeInTheDocument()
    expect(scanButton).toBeDisabled()

    await user.type(screen.getByLabelText('Repository Path'), '/repos/sample-repo')

    expect(scanButton).toBeEnabled()
  })

  it('submits a scan, renders results, filters findings, and links exports', async () => {
    fetchMock.mockResolvedValue(jsonResponse(scanReport))
    render(<App />)

    const user = await submitScan()

    expect(fetchMock).toHaveBeenCalledWith(
      'http://127.0.0.1:8000/scan',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          target: '/repos/sample-repo',
          target_type: 'local_path',
        }),
      }),
    )
    expect(await screen.findByRole('heading', { name: 'Findings' })).toBeInTheDocument()
    expect(screen.getByText('Possible hardcoded password')).toBeInTheDocument()
    expect(screen.getByText('Insecure HTTP URL')).toBeInTheDocument()
    expect(screen.getByText('src/app.py:4')).toBeInTheDocument()
    expect(screen.getByText('src/client.ts')).toBeInTheDocument()
    expect(screen.getByText('90/100')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'JSON' })).toHaveAttribute(
      'href',
      'http://127.0.0.1:8000/reports/latest.json',
    )
    expect(screen.getByRole('link', { name: 'Markdown' })).toHaveAttribute(
      'href',
      'http://127.0.0.1:8000/reports/latest.md',
    )

    await user.selectOptions(screen.getByLabelText('Severity filter'), 'high')

    expect(screen.getByText('Possible hardcoded password')).toBeInTheDocument()
    expect(screen.queryByText('Insecure HTTP URL')).not.toBeInTheDocument()
  })

  it('shows API error details and leaves the empty state available', async () => {
    fetchMock.mockResolvedValue(jsonResponse({ detail: 'Repository is not readable.' }, false))
    render(<App />)

    await submitScan()

    expect(await screen.findByText('Repository is not readable.')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Waiting for scan' })).toBeInTheDocument()
  })

  it('uses a safe fallback for non-error failures', async () => {
    fetchMock.mockRejectedValue('offline')
    render(<App />)

    await submitScan()

    expect(await screen.findByText('Scan failed')).toBeInTheDocument()
  })

  it.each([
    [60, 'warn'],
    [40, 'bad'],
  ])('applies the %s score state', async (score, expectedClass) => {
    fetchMock.mockResolvedValue(jsonResponse({ ...scanReport, score }))
    render(<App />)

    await submitScan()

    expect(await screen.findByText(`${score}/100`)).toBeInTheDocument()
    expect(screen.getByText('Security Score').closest('article')).toHaveClass(expectedClass)
  })
})
