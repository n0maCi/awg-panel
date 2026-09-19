// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { App } from '../../src/web/App';

afterEach(() => vi.unstubAllGlobals());

describe('login screen', () => {
  it('logs in with a password', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ authenticated: false }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        interface: { name: 'awg0', endpoint: 'vpn.example.com:51820', address: '10.8.0.1/24', version: '3.1', publicKey: 'public-key', status: 'unknown' },
        peers: [],
        cluster: { role: 'standalone', nodeId: 'vpn.example.com', peerCount: 0, readOnly: false, lastSyncAt: null, lastSource: null, lastError: null },
      }), { status: 200, headers: { 'Content-Type': 'application/json' } }));
    vi.stubGlobal('fetch', fetchMock);

    render(<App />);
    const password = await screen.findByLabelText('Пароль');
    fireEvent.change(password, { target: { value: 'secret' } });
    fireEvent.click(screen.getByRole('button', { name: 'Войти' }));

    await waitFor(() => expect(screen.getByRole('heading', { name: 'Клиенты' })).toBeInTheDocument());
    expect(fetchMock).toHaveBeenCalledWith('/api/auth/login', expect.objectContaining({ method: 'POST' }));
  });
});
