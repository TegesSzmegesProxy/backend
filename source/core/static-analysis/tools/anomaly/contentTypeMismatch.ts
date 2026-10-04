import { NormalizedRequest } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, header, metadataOf, safe, suspicious } from '@tessera/core/static-analysis/shared';

type Kind = 'json' | 'xml' | 'form' | 'multipart' | 'text' | 'other';

export default class ContentTypeMismatch extends Tool<ToolContextType.Full> {
    constructor() {
        super({
            id: 'content_type_mismatch',
            displayName: 'Content-Type mismatch',
            category: ToolCategory.Anomaly,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const raw = ContentTypeMismatch.rawBody(context);
        if (raw === undefined || raw.trim() === '') {
            return safe(this.tool); // no body, or a body the parser already accepted for its declared type
        }

        const contentType = header(context, 'content-type');
        const declared = ContentTypeMismatch.declaredKind(contentType);
        const actual = ContentTypeMismatch.sniff(raw);

        if (contentType === undefined) {
            return suspicious(this.tool, { reason: 'body_without_content_type', detected: actual });
        }
        if (actual === 'other' || actual === declared) {
            return safe(this.tool);
        }
        // text/plain may carry anything; only structured declarations are held to their format
        if (declared === 'text' || declared === 'other') {
            return actual === 'xml' || actual === 'json'
                ? suspicious(this.tool, { reason: 'structured_body_as_text', declared: contentType.slice(0, 100), detected: actual })
                : safe(this.tool);
        }

        return suspicious(this.tool, { reason: 'body_does_not_match_declared_type', declared: contentType.slice(0, 100), detected: actual });
    }

    // The unparsed body: captured raw text, or the body itself when the parser left it as a string.
    private static rawBody(request: NormalizedRequest): string | undefined {
        const raw = metadataOf(request).rawBody;
        if (typeof raw === 'string') return raw;
        if (typeof request.body === 'string') return request.body;
        if (Buffer.isBuffer(request.body)) return request.body.subarray(0, 4096).toString('utf8');
        return undefined;
    }

    private static declaredKind(contentType: string | undefined): Kind {
        const type = (contentType ?? '').split(';')[0].trim().toLowerCase();
        if (type === 'application/json' || type.endsWith('+json')) return 'json';
        if (type === 'application/xml' || type === 'text/xml' || type.endsWith('+xml')) return 'xml';
        if (type === 'application/x-www-form-urlencoded') return 'form';
        if (type.startsWith('multipart/')) return 'multipart';
        if (type === 'text/plain') return 'text';
        return 'other';
    }

    private static sniff(raw: string): Kind {
        const text = raw.replace(/^﻿/, '').trimStart();
        if (/^(?:<\?xml|<!DOCTYPE|<[A-Za-z_][\w:.-]*[\s>/])/i.test(text)) return 'xml';
        if (/^[{[]/.test(text)) {
            try {
                JSON.parse(text);
                return 'json';
            } catch {
                return 'other';
            }
        }
        if (/^--[^\r\n]{1,70}\r?\n/.test(text)) return 'multipart';
        if (/^[\w.%[\]-]+=[^&]*(?:&[\w.%[\]-]+=[^&]*)*$/.test(text.trim())) return 'form';
        return 'other';
    }
}
