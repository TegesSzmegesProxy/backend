import { z } from 'zod';
import type { HttpTarget, HttpxResult } from '../types';

const lineSchema = z.object({
    url: z.string(),
    scheme: z.string().optional(),
    status_code: z.number().optional(),
    title: z.string().optional(),
    webserver: z.string().optional(),
    tech: z.array(z.string()).optional(),
    header: z.record(z.string(), z.string()).optional(),
    tls: z.object({ tls_version: z.string().optional() }).optional(),
    failed: z.boolean().optional(),
});

// Cookies and anything credential-shaped must never reach the AI or the control plane.
const SENSITIVE_HEADER = /cookie|auth|token|secret|api[-_]?key|session/i;

export const httpxArgs = (urls: string[]): string[] => [
    ...urls.flatMap(url => ['-u', url]),
    '-json',
    '-silent',
    '-duc',
    '-title',
    '-status-code',
    '-web-server',
    '-tech-detect',
    '-tls-grab',
    '-irh',
];

export function parseHttpx(output: string): HttpxResult {
    const targets = jsonLines(output)
        .map(line => lineSchema.parse(line))
        // httpx also prints a line for probes that never connected; those are not reachable targets.
        .filter(line => line.failed !== true)
        .map(toTarget);
    return { targets };
}

function toTarget(line: z.infer<typeof lineSchema>): HttpTarget {
    const headers = Object.fromEntries(
        Object.entries(line.header ?? {})
            .map(([name, value]) => [name.replace(/_/g, '-').toLowerCase(), value] as const)
            .filter(([name]) => !SENSITIVE_HEADER.test(name))
    );
    const tlsEnabled = line.scheme === 'https' || line.tls !== undefined;
    return {
        url: line.url,
        ...(line.status_code !== undefined && { statusCode: line.status_code }),
        ...(line.title !== undefined && { title: line.title }),
        ...(line.webserver !== undefined && { server: line.webserver }),
        technologies: line.tech ?? [],
        headers,
        tls: {
            enabled: tlsEnabled,
            ...(line.tls?.tls_version !== undefined && { version: line.tls.tls_version }),
        },
    };
}

export function jsonLines(output: string): unknown[] {
    return output
        .split('\n')
        .map(line => line.trim())
        .filter(line => line !== '')
        .map(line => JSON.parse(line) as unknown);
}
