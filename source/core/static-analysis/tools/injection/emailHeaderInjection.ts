import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, safe, suspicious } from '@tessera/core/static-analysis/shared';

interface EmailHeaderRule {
    name: string;
    pattern: RegExp;
}

// A line break, raw or encoded, as it would reach the mail library.
const BREAK = '(?:\\r\\n|\\r|\\n|%0d%0a|%0d|%0a|\\\\r\\\\n|\\\\n)';

// No g flags, so RegExp.test has no lastIndex state on these shared constants.
const RULES: EmailHeaderRule[] = [
    {
        // victim@example.com\r\nBcc: spam-list@example.net
        name: 'recipient_header',
        pattern: new RegExp(`${BREAK}\\s*(?:bcc|cc|to)\\s*:`, 'i'),
    },
    {
        // \r\nFrom: ceo@example.com   \r\nReply-To:   \r\nSubject:
        name: 'sender_or_subject_header',
        pattern: new RegExp(`${BREAK}\\s*(?:from|reply-to|sender|return-path|subject)\\s*:`, 'i'),
    },
    {
        // \r\nContent-Type: multipart/mixed; boundary=...  -- replaces the whole message body
        name: 'mime_header',
        pattern: new RegExp(`${BREAK}\\s*(?:content-type|content-transfer-encoding|mime-version)\\s*:`, 'i'),
    },
    {
        // an empty line ends the headers, so whatever follows becomes the message body
        name: 'header_body_separator',
        pattern: new RegExp(`${BREAK}\\s*${BREAK}`, 'i'),
    },
];

// Contact-form fields that become headers, where a line break never belongs. A free-text message body
// legitimately has blank lines, so header_body_separator only counts in these.
const HEADER_FIELDS = /(?:^|[._[-])(?:e?mail|from|to|cc|bcc|subject|name|sender|replyto|reply_to|reply-to)\]?$/i;

export default class EmailHeaderInjection extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'email_header_injection',
            displayName: 'Email header injection',
            category: ToolCategory.Injection,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        if (typeof context.value !== 'string') {
            return safe(this.tool);
        }

        const value = context.value;
        const headerField = HEADER_FIELDS.test(String(context.name));
        const matched = RULES
            .filter(rule => rule.name !== 'header_body_separator' || headerField)
            .filter(rule => rule.pattern.test(value))
            .map(rule => rule.name);

        return matched.length > 0
            ? suspicious(this.tool, { name: clip(context.name), location: context.location, rules: matched })
            : safe(this.tool);
    }
}
