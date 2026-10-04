import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { loadExpectedDurations, saveDurations, TYPICAL_DURATIONS_MS } from '../../cli/src/timings';

let dir: string;
let file: string;
beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'tessera-timings-'));
    file = join(dir, 'state', 'timings.json');
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe('timings history', () => {
    it('falls back to typical durations when there is no history', () => {
        const { expectedMs, learned } = loadExpectedDurations(file);
        expect(expectedMs).toEqual(TYPICAL_DURATIONS_MS);
        expect(learned.size).toBe(0);
    });

    it('uses the slowest of the last runs per tool and merges runs', () => {
        saveDurations({ nmap: 11_303, lynis: 134_250 }, file);
        saveDurations({ nmap: 9_000 }, file);
        const { expectedMs, learned } = loadExpectedDurations(file);
        expect(expectedMs.nmap).toBe(11_303);
        expect(expectedMs.lynis).toBe(134_250);
        expect(expectedMs.trivy).toBe(TYPICAL_DURATIONS_MS.trivy);
        expect([...learned].sort()).toEqual(['lynis', 'nmap']);
    });

    it('keeps only the last three runs, so an old slow run ages out', () => {
        for (const ms of [90_000, 10_000, 12_000, 11_000]) saveDurations({ nuclei: ms }, file);
        expect(loadExpectedDurations(file).expectedMs.nuclei).toBe(12_000);
    });

    it('does not let one fast run (e.g. a target that was down) collapse the estimate', () => {
        saveDurations({ nuclei: 40_000 }, file);
        saveDurations({ nuclei: 1_100 }, file);
        expect(loadExpectedDurations(file).expectedMs.nuclei).toBe(40_000);
    });

    it('keeps the history private to the user', () => {
        saveDurations({ nmap: 5_000 }, file);
        expect(statSync(file).mode & 0o077).toBe(0);
    });

    it.each([
        ['not json', 'oops{'],
        ['an array', '[1,2]'],
        ['null', 'null'],
        ['strings and negatives', '{"nmap":"fast","nuclei":[-5,"x",null],"trivy":0,"httpx":[1e99],"lynis":null}'],
        ['the old single-number format', '{"nmap":9000}'],
    ])('ignores a corrupt history (%s)', (_name, content) => {
        saveDurations({}, file); // creates the directory
        writeFileSync(file, content);
        expect(loadExpectedDurations(file).expectedMs).toEqual(TYPICAL_DURATIONS_MS);
    });

    it('does not store implausible durations', () => {
        saveDurations({ nmap: Number.NaN, nuclei: -1, trivy: 10 ** 12, httpx: 2_000 }, file);
        expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual({ httpx: [2_000] });
    });

    it('never throws when the location is not writable', () => {
        writeFileSync(join(dir, 'blocker'), 'x');
        expect(() => saveDurations({ nmap: 5_000 }, join(dir, 'blocker', 'timings.json'))).not.toThrow();
    });
});
