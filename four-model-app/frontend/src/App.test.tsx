import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import '@testing-library/jest-dom'
import { vi } from 'vitest'
import App from './App'

// Mock global fetch (Vitest uses `vi`, not `jest`)
;(globalThis as any).fetch = vi.fn(async () => ({
  ok: true,
  json: async () => ({
    input: { text: 't', url: null },
    outputs: { email_classifier: { label: 'Legitimate' } },
    verdict: { verdict: 'Low Risk' }
  })
})) as unknown as typeof fetch

test('renders fields and runs', async () => {
  render(<App />)
  expect(screen.getByLabelText(/email text/i)).toBeInTheDocument()
  expect(screen.getByRole('button', { name: /run/i })).toBeInTheDocument()
  fireEvent.change(screen.getByLabelText(/email text/i), { target: { value: 'hello' } })
  fireEvent.click(screen.getByRole('button', { name: /run/i }))
  await waitFor(() => expect(screen.getByText(/\"email_classifier\"/)).toBeInTheDocument())
})
