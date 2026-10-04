import { PassThrough } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { createPrompter } from '../../cli/src/prompt';

function setup(lines: string[]) {
    const input = new PassThrough();
    const output = new PassThrough();
    let written = '';
    output.on('data', chunk => (written += chunk));
    const prompter = createPrompter(input, output);
    input.end(lines.map(line => `${line}\n`).join(''));
    return { prompter, written: () => written };
}

describe('createPrompter', () => {
    it('uses the default on an empty answer', async () => {
        const { prompter } = setup(['']);
        expect(await prompter.ask('Tenant', { default: 'acme' })).toBe('acme');
        prompter.close();
    });

    it('returns the typed answer over the default', async () => {
        const { prompter } = setup(['other']);
        expect(await prompter.ask('Tenant', { default: 'acme' })).toBe('other');
        prompter.close();
    });

    it('asks again after a validation error and shows the message', async () => {
        const { prompter, written } = setup(['bad id!', 'good_id']);
        const validate = (v: string) => {
            if (!/^[\w-]+$/.test(v)) throw new Error('invalid tenant');
            return v;
        };
        expect(await prompter.ask('Tenant', { validate })).toBe('good_id');
        expect(written()).toContain('invalid tenant');
        prompter.close();
    });
});
