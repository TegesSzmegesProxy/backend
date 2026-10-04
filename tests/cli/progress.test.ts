import { PassThrough } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { createProgress, formatElapsed } from '../../cli/src/progress';

const expectedMs = { nmap: 10_000, nuclei: 30_000, trivy: 5_000, httpx: 5_000, lynis: 100_000 };

function capture() {
    const output = new PassThrough();
    let text = '';
    output.on('data', chunk => (text += chunk));
    return { output, text: () => text };
}

describe('createProgress', () => {
    it('announces the expected total and its slowest tool', () => {
        const { output, text } = capture();
        createProgress(['nmap', 'lynis'], output, { interactive: false, expectedMs, basis: 'typical timings' });
        expect(text()).toBe('Tessera: expected time about 1m40s (based on typical timings; tools run in parallel, lynis is the slowest)\n');
    });

    it('prints one plain line per event, with time left, when not interactive', () => {
        const { output, text } = capture();
        let clock = 0;
        const progress = createProgress(['nmap', 'lynis'], output, { interactive: false, expectedMs, basis: 'previous runs', now: () => clock });
        progress.update({ tool: 'nmap', phase: 'started' });
        progress.update({ tool: 'lynis', phase: 'started' });
        clock = 11_000;
        progress.update({ tool: 'nmap', phase: 'finished', status: 'ok', durationMs: 11_000 });
        progress.stop();
        expect(text()).toContain('Tessera: nmap started\n');
        expect(text()).toContain('Tessera: nmap ok after 11s (1/2, about 1m30s left)\n');
    });

    it('draws the bar with finished tools, running tools, elapsed and time left when interactive', () => {
        const { output, text } = capture();
        let clock = 0;
        const progress = createProgress(['nmap', 'lynis'], output, { interactive: true, now: () => clock, intervalMs: 1_000_000, expectedMs, basis: 'previous runs' });
        progress.update({ tool: 'nmap', phase: 'started' });
        progress.update({ tool: 'lynis', phase: 'started' });
        clock = 65_000;
        progress.update({ tool: 'nmap', phase: 'finished', status: 'ok', durationMs: 11_000 });
        progress.stop();
        const last = text().split('\r').pop() ?? '';
        expect(last).toContain('1/2');
        expect(last).toContain('done: nmap✓');
        expect(last).toContain('running: lynis');
        expect(last).toContain('1m05s elapsed, about 35s left');
    });

    it('says so when the slowest tool is past its estimate, and never shows a full bar early', () => {
        const { output, text } = capture();
        let clock = 0;
        const progress = createProgress(['nmap', 'lynis'], output, { interactive: true, now: () => clock, intervalMs: 1_000_000, expectedMs, basis: 'typical timings' });
        progress.update({ tool: 'lynis', phase: 'started' });
        clock = 500_000;
        progress.stop();
        const last = text().split('\r').pop() ?? '';
        expect(last).toContain('taking longer than expected');
        expect(last).not.toContain('█'.repeat(20));
    });

    it('shows a full bar once everything has finished', () => {
        const { output, text } = capture();
        const progress = createProgress(['trivy'], output, { interactive: true, intervalMs: 1_000_000, expectedMs, basis: 'typical timings' });
        progress.update({ tool: 'trivy', phase: 'finished', status: 'ok', durationMs: 2_000 });
        progress.stop();
        expect(text().split('\r').pop()).toContain('█'.repeat(20));
    });

    it('ignores tools that are not part of the run', () => {
        const { output, text } = capture();
        const progress = createProgress(['trivy'], output, { interactive: false, expectedMs, basis: 'typical timings' });
        progress.update({ tool: 'nmap', phase: 'finished', status: 'skipped', durationMs: 0 });
        progress.update({ tool: 'trivy', phase: 'finished', status: 'ok', durationMs: 2_000 });
        expect(text()).toContain('Tessera: trivy ok after 2s (1/1)\n');
        expect(text()).not.toContain('nmap');
    });

    it('does nothing for an empty run', () => {
        const { output, text } = capture();
        createProgress([], output, { interactive: true, expectedMs, basis: 'typical timings' }).stop();
        expect(text()).toBe('');
    });
});

describe('formatElapsed', () => {
    it.each([[0, '0s'], [42_900, '42s'], [60_000, '1m00s'], [134_250, '2m14s']])('%d ms -> %s', (ms, expected) => {
        expect(formatElapsed(ms)).toBe(expected);
    });
});
