import { NormalizedRequest } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, failure, header, metadataOf, safe, violation } from '@tessera/core/static-analysis/shared';

const MAX_SCAN = 1024 * 1024;
const MAX_REPORTED = 10;

export default class DuplicateJsonKeys extends Tool<ToolContextType.Full> {
    constructor() {
        super({
            id: 'duplicate_json_keys',
            displayName: 'Duplicate JSON keys',
            category: ToolCategory.Schema,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const contentType = (header(context, 'content-type') ?? '').split(';')[0].trim().toLowerCase();
        const isJson = contentType === 'application/json' || contentType.endsWith('+json');
        if (!isJson) {
            return safe(this.tool);
        }

        // JSON.parse keeps the last duplicate, so the parsed body can't show them: the raw text is needed.
        const raw = metadataOf(context).rawBody ?? (typeof context.body === 'string' ? context.body : undefined);
        if (typeof raw !== 'string') {
            return failure(this.tool, { reason: 'raw_body_unavailable' });
        }

        const duplicates = DuplicateJsonKeys.findDuplicates(raw.slice(0, MAX_SCAN));
        // one parser takes the first value, another the last: that's the bypass, so any duplicate is rejected
        return duplicates.length > 0 ? violation(this.tool, { duplicates }) : safe(this.tool);
    }

    // A single pass over the text that tracks the keys of every open object. Keys are compared after
    // decoding escapes, so "role" and "role" count as the same key.
    private static findDuplicates(raw: string): string[] {
        const duplicates: string[] = [];
        // one entry per open container: a Set of keys for objects, undefined for arrays
        const stack: (Set<string> | undefined)[] = [];
        let expectingKey = false;

        for (let index = 0; index < raw.length; index++) {
            const char = raw[index];
            if (char === '{') {
                stack.push(new Set());
                expectingKey = true;
            } else if (char === '[') {
                stack.push(undefined);
                expectingKey = false;
            } else if (char === '}' || char === ']') {
                stack.pop();
                expectingKey = false;
            } else if (char === ',') {
                expectingKey = stack[stack.length - 1] !== undefined;
            } else if (char === '"') {
                let end = index + 1;
                while (end < raw.length && raw[end] !== '"') {
                    end += raw[end] === '\\' ? 2 : 1;
                }
                const token = raw.slice(index, end + 1);
                const keys = stack[stack.length - 1];
                if (expectingKey && keys) {
                    let key: string;
                    try {
                        key = JSON.parse(token);
                    } catch {
                        key = token;
                    }
                    if (keys.has(key)) {
                        if (duplicates.length < MAX_REPORTED) duplicates.push(clip(key, 50));
                    } else {
                        keys.add(key);
                    }
                    expectingKey = false;
                }
                index = end;
            }
        }

        return duplicates;
    }
}
