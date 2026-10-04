import { afterEach, expect, it, vi } from 'vitest';
import { CredentialManager } from '../../source/core/jev/CredentialManager';

const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; vi.restoreAllMocks(); });

it('loads an organization key, keeps it on fetch failure, and drops it on 404', async () => {
  const manager = new CredentialManager('http://dashboard.local/', 'deployment-key', () => ({
    get: async () => null,
    set: async () => undefined,
  }));
  globalThis.fetch = vi.fn(async () => new Response(JSON.stringify({
    schemaVersion: 'tessera.jev-credential/v1',
    apiKey: 'test-key', version: 1, updatedAt: '2026-10-04T00:00:00.000Z',
  }), { status: 200 }));
  await manager.refresh();
  expect(manager.available).toBe(true);
  globalThis.fetch = vi.fn(async () => { throw new Error('offline'); });
  await manager.refresh();
  expect(manager.available).toBe(true);
  globalThis.fetch = vi.fn(async () => new Response(null, { status: 404 }));
  await manager.refresh();
  expect(manager.available).toBe(false);
});
