import { RequestFile } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, failure, safe, violation } from '@tessera/core/static-analysis/shared';

interface SvgRule {
    name: string;
    pattern: RegExp;
}

const MAX_SCAN = 1024 * 1024;

// No g flags, so RegExp.test has no lastIndex state on these shared constants.
const RULES: SvgRule[] = [
    { name: 'script_element', pattern: /<\s*(?:\w+:)?script\b/i },
    { name: 'event_handler', pattern: /<[^>]+\son[a-z]+\s*=/i },
    { name: 'foreign_object', pattern: /<\s*(?:\w+:)?foreignObject\b/i },
    { name: 'javascript_uri', pattern: /(?:xlink:)?href\s*=\s*["']?\s*(?:javascript|vbscript|data:text\/html)\s*:?/i },
    { name: 'embedded_document', pattern: /<\s*(?:iframe|embed|object|html|body)\b/i },
    { name: 'external_reference', pattern: /<\s*(?:\w+:)?(?:use|image|feImage)\b[^>]+href\s*=\s*["']?\s*(?:https?:|\/\/)/i },
    { name: 'entity_declaration', pattern: /<!ENTITY\b/i },
    { name: 'animate_href', pattern: /<\s*(?:animate|set)\b[^>]+attributeName\s*=\s*["']?(?:xlink:)?href/i },
];

export default class SvgScript extends Tool<ToolContextType.File> {
    constructor() {
        super({
            id: 'svg_script',
            displayName: 'Script in SVG',
            category: ToolCategory.Injection,
            contextType: ToolContextType.File,
        });
    }

    override run(context: RequestFile): ToolResult {
        const metadata = (context.metadata ?? {}) as Record<string, unknown>;
        const content = typeof metadata['content'] === 'string'
            ? metadata['content']
            : typeof metadata['contentBase64'] === 'string' ? Buffer.from(metadata['contentBase64'], 'base64').toString('utf8') : undefined;

        if (!SvgScript.isSvg(context, content)) {
            return safe(this.tool);
        }
        if (content === undefined) {
            // an SVG we can't read can't be evaluated, which is different from "safe".
            // Adjust the key names to whatever your normalizer writes into RequestFile.metadata.
            return failure(this.tool, { filename: clip(context.filename), reason: 'missing_content' });
        }

        const text = content.slice(0, MAX_SCAN);
        const matched = RULES.filter(rule => rule.pattern.test(text)).map(rule => rule.name);

        // an uploaded image with active content is served back from our origin: stored XSS, so a violation
        return matched.length > 0
            ? violation(this.tool, { filename: clip(context.filename), rules: matched })
            : safe(this.tool);
    }

    private static isSvg(file: RequestFile, content: string | undefined): boolean {
        const type = String(file.contentType ?? '').split(';')[0].trim().toLowerCase();
        return type === 'image/svg+xml'
            || /\.svgz?$/i.test(String(file.filename ?? ''))
            || (content !== undefined && /^\s*(?:<\?xml[^>]*>\s*)?(?:<!--[\s\S]*?-->\s*)*(?:<!DOCTYPE[^>]*>\s*)?<svg\b/i.test(content.slice(0, 4096)));
    }
}
