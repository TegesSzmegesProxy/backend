import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
    InputError,
    parseApiUrl,
    parseDirectory,
    parseOutputFile,
    parsePort,
    parseProjectId,
    parseRateLimit,
    parseTargetList,
    parseTenant,
} from '../../cli/src/inputs';

let dir: string;
beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'tessera-inputs-'));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe('parseTenant', () => {
    it.each(['acme', 'a_b-1', 'x'.repeat(40)])('accepts %s', value => expect(parseTenant(value)).toBe(value));
    it('trims surrounding whitespace', () => expect(parseTenant(' acme \n')).toBe('acme'));
    it.each(['', '   ', '../etc', 'a b', 'x'.repeat(41), 'ünï', 'a;b', 'a\nb'])('rejects %j', value => {
        expect(() => parseTenant(value)).toThrow(InputError);
    });
});

describe('parseProjectId', () => {
    it('accepts a 24 character hex id', () => expect(parseProjectId('507f1f77bcf86cd799439011')).toBe('507f1f77bcf86cd799439011'));
    it.each(['', 'abc', '507f1f77bcf86cd79943901z', '507f1f77bcf86cd7994390111', '../../x'])('rejects %j', value => {
        expect(() => parseProjectId(value)).toThrow(InputError);
    });
});

describe('parseRateLimit', () => {
    it.each([['1', 1], ['50', 50], [' 1000 ', 1000]])('accepts %j', (value, expected) => expect(parseRateLimit(value)).toBe(expected));
    it.each(['0', '-1', '1001', '2.5', '1e2', '0x10', 'abc', '', ' ', 'Infinity', 'NaN'])('rejects %j', value => {
        expect(() => parseRateLimit(value)).toThrow(InputError);
    });
});

describe('parsePort', () => {
    it.each([['80', '80'], ['62197', '62197'], ['65535', '65535'], [' 8080 ', '8080']])('accepts %j', (value, expected) => {
        expect(parsePort(value)).toBe(expected);
    });
    it.each(['0', '65536', '-1', '80.5', 'http', '', '8080/../x', '99999999'])('rejects %j', value => {
        expect(() => parsePort(value)).toThrow(InputError);
    });
});

describe('parseTargetList', () => {
    it('splits on commas and whitespace', () => {
        expect(parseTargetList('http://localhost:3000, 10.0.0.5  example.com')).toEqual(['http://localhost:3000', '10.0.0.5', 'example.com']);
    });
    it.each(['', ' , ', '-oX/tmp/x', 'http://user:pw@host/', 'ftp://host', 'host;ls', 'http://'])('rejects %j', value => {
        expect(() => parseTargetList(value)).toThrow(InputError);
    });
    it('rejects too many targets', () => {
        expect(() => parseTargetList(Array.from({ length: 51 }, (_, i) => `h${i}.example.com`).join(','))).toThrow(InputError);
    });
});

describe('parseDirectory', () => {
    it('accepts an existing directory and returns it absolute', () => expect(parseDirectory(dir)).toBe(dir));
    it('strips quotes and expands ~', () => {
        mkdirSync(join(dir, 'proj'));
        expect(parseDirectory(`"${join(dir, 'proj')}"`)).toBe(join(dir, 'proj'));
        expect(parseDirectory('~/proj', dir)).toBe(join(dir, 'proj'));
    });
    it('rejects a missing path, a file, an empty value and a NUL byte', () => {
        writeFileSync(join(dir, 'file.txt'), 'x');
        for (const value of [join(dir, 'missing'), join(dir, 'file.txt'), '', '   ', `${dir}\0`]) {
            expect(() => parseDirectory(value)).toThrow(InputError);
        }
    });
});

describe('parseOutputFile', () => {
    it('accepts a new file in an existing directory and an existing file', () => {
        expect(parseOutputFile(join(dir, 'report.json'))).toBe(join(dir, 'report.json'));
        writeFileSync(join(dir, 'old.json'), '{}');
        expect(parseOutputFile(join(dir, 'old.json'))).toBe(join(dir, 'old.json'));
    });
    it('rejects a directory, a missing parent directory and an empty value', () => {
        for (const value of [dir, join(dir, 'no', 'such', 'report.json'), '']) {
            expect(() => parseOutputFile(value)).toThrow(InputError);
        }
    });
});

describe('parseApiUrl', () => {
    it.each(['https://tessera.example.com', 'https://tessera.example.com/', 'http://localhost:3000', 'http://127.0.0.1:3000', 'http://[::1]:3000'])('accepts %s', value => {
        expect(parseApiUrl(value)).toBe(value);
    });
    it.each([
        'tessera.example.com',
        'ftp://x.example.com',
        'javascript:alert(1)',
        'http://tessera.example.com',
        'https://user:pw@tessera.example.com',
        'https://tessera.example.com/?a=1',
        'https://tessera.example.com/#x',
        '',
    ])('rejects %j', value => {
        expect(() => parseApiUrl(value)).toThrow(InputError);
    });
});
