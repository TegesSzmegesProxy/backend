import { afterEach, expect, it, vi } from 'vitest';
import { ProxyReporter } from '../../source/shared/telemetry/ProxyReporter';
import type { PolicyStatusSource } from '../../source/core/policy/ActivePolicy';

const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; vi.useRealTimers(); vi.restoreAllMocks(); });

it('sends only policy endpoint counters and the loaded bundle version', async () => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date('2026-10-04T12:34:00.000Z'));
  const posted: { path: string; body: Record<string, unknown> }[] = [];
  globalThis.fetch = vi.fn(async (url, options) => {
    posted.push({ path: new URL(String(url)).pathname, body: JSON.parse(String(options?.body)) });
    return new Response(null, { status: 204 });
  });
  const bundles = {
    snapshot: { version: 'a'.repeat(64) },
    status: { source: 'remote', restartRequired: false, dashboardReachable: true, pullFailures: 0, verificationFailures: 0 },
    checkForUpdate: async () => undefined,
  } as unknown as PolicyStatusSource;
  const reporter = new ProxyReporter({ tenantId: '3f2b8c1e4a5d4e6f8a7b9c0d', apiBaseUrl: 'http://dashboard.local/', deploymentKey: 'secret', proxyVersion: '1.0.0' }, bundles);
  reporter.record('POST /users/:id', {
    action: 'ALLOW', reason: 'static analysis safe, not sampled',
    staticVerdict: { verdict: 'SAFE', results: [], evidence: undefined }, sampled: false,
  });
  reporter.start();
  await vi.advanceTimersByTimeAsync(60_000);
  const heartbeat = posted.find((entry) => entry.path.endsWith('/heartbeats'))?.body;
  const telemetry = posted.find((entry) => entry.path.endsWith('/telemetry'))?.body;
  expect(heartbeat?.['tenants']).toEqual([{ tenantId: '3f2b8c1e4a5d4e6f8a7b9c0d', bundleSource: 'remote', loadedBundleVersion: 'a'.repeat(64) }]);
  const windows = telemetry?.['windows'] as Array<{ bundleVersion: string; endpoints: Array<{ endpoint: string; decisions: { allow: number; block: number } }> }>;
  expect(windows[0].bundleVersion).toBe('a'.repeat(64));
  expect(windows[0].endpoints).toEqual([{ endpoint: 'POST /users/:id', decisions: { allow: 1, block: 0 }, staticVerdicts: { safe: 1, suspicious: 0, policyViolation: 0, error: 0 }, jev: { sampledSafe: 0, attack: 0, benign: 0, unavailable: 0 }, failureBehaviorApplied: 0 }]);
  expect(JSON.stringify(telemetry)).not.toContain('/users/42');
  await reporter.stop();
});
