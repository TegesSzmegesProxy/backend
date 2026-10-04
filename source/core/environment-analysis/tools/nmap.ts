import { XMLParser } from 'fast-xml-parser';
import { z } from 'zod';
import type { NmapHost, NmapPort, NmapResult } from '../types';

const PORT_STATES = [
    'open',
    'closed',
    'filtered',
    'unfiltered',
    'open|filtered',
    'closed|filtered',
] as const;

const portSchema = z.object({
    '@_protocol': z.string(),
    '@_portid': z.coerce.number().int(),
    state: z.object({ '@_state': z.enum(PORT_STATES) }),
    service: z
        .object({
            '@_name': z.string().optional(),
            '@_product': z.string().optional(),
            '@_version': z.string().optional(),
        })
        .optional(),
});

const hostSchema = z.object({
    address: z.array(z.object({ '@_addr': z.string(), '@_addrtype': z.string().optional() })).min(1),
    // An empty <hostnames> element is parsed as an empty string.
    hostnames: z.union([z.string(), z.object({ hostname: z.array(z.object({ '@_name': z.string() })) })]).optional(),
    ports: z.union([z.string(), z.object({ port: z.array(portSchema).optional() })]).optional(),
});

const documentSchema = z.object({
    nmaprun: z.object({ host: z.array(hostSchema).optional() }),
});

const xml = new XMLParser({
    ignoreAttributes: false,
    isArray: name => ['host', 'address', 'hostname', 'port'].includes(name),
});

export const nmapArgs = (hosts: string[]): string[] => ['-sV', '-oX', '-', ...hosts];

export function parseNmap(output: string): NmapResult {
    const { nmaprun } = documentSchema.parse(xml.parse(output));
    // <hosthint> elements are skipped on purpose: only <host> carries scan results.
    return { hosts: (nmaprun.host ?? []).map(toHost) };
}

function toHost(host: z.infer<typeof hostSchema>): NmapHost {
    const address = host.address.find(a => a['@_addrtype'] !== 'mac') ?? host.address[0];
    const hostname = typeof host.hostnames === 'object' ? host.hostnames.hostname[0]?.['@_name'] : undefined;
    const ports = typeof host.ports === 'object' ? (host.ports.port ?? []) : [];
    return {
        address: address!['@_addr'],
        ...(hostname !== undefined && { hostname }),
        ports: ports.flatMap(toPort),
    };
}

function toPort(port: z.infer<typeof portSchema>): NmapPort[] {
    const protocol = port['@_protocol'];
    if (protocol !== 'tcp' && protocol !== 'udp') return [];
    const service = port.service;
    const version = [service?.['@_product'], service?.['@_version']].filter(Boolean).join(' ');
    return [
        {
            port: port['@_portid'],
            protocol,
            state: port.state['@_state'],
            ...(service?.['@_name'] !== undefined && { service: service['@_name'] }),
            ...(version !== '' && { version }),
        },
    ];
}
