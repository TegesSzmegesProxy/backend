import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, safe, suspicious } from '@tessera/core/static-analysis/shared';
import CommandInjection from '../injection/commandinjection';
import PathTraversal from '../injection/pathTraversal';
import SqlInjection from '../injection/sqlinjection';
import Xss from '../injection/xss';

interface Decoded {
    encoding: 'base64' | 'hex' | 'percent';
    text: string;
}

const MIN_BLOB = 16;
const MAX_LENGTH = 16_384;
const MAX_BLOBS = 10;

// matchAll clones the regex, so the g flag is safe on these shared constants.
const BASE64_BLOB = /(?:^|[^A-Za-z0-9+/=_-])([A-Za-z0-9+/_-]{16,}={0,2})(?![A-Za-z0-9+/=_-])/g;
const HEX_BLOB = /(?:^|[^0-9a-fA-Fx])(?:0x)?((?:[0-9a-fA-F]{2}){8,})(?![0-9a-fA-F])/g;
// three or more escapes of printable ASCII close together, e.g. %3Cscript%3E
const PERCENT_RUN = /(?:%[2-7][0-9a-fA-F][^%]{0,8}){3,}/;

// Characters that make decoded text look like code or markup rather than data.
const ACTIVE_CHARACTERS = /[<>'"`;$(){}|]/;

// The existing detectors decoded text is re-scanned with.
const RESCANNERS = [new SqlInjection(), new Xss(), new CommandInjection(), new PathTraversal()];

export default class EncodedPayload extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'encoded_payload',
            displayName: 'Encoded payload',
            category: ToolCategory.Anomaly,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        if (typeof context.value !== 'string') {
            return safe(this.tool);
        }

        const whole = context.value.trim();
        const findings: { encoding: string; tools: string[]; preview: string }[] = [];

        for (const decoded of EncodedPayload.decode(context.value.slice(0, MAX_LENGTH))) {
            const tools = RESCANNERS
                .map(scanner => scanner.run({ ...context, value: decoded.text }))
                .filter(result => result.verdict === 'SUSPICIOUS' || result.verdict === 'POLICY_VIOLATION')
                .map(result => result.tool);

            // a value that is entirely a base64/hex blob decoding to code-looking text is odd even when
            // no detector names it
            const blobOnly = decoded.encoding !== 'percent' && whole.length >= MIN_BLOB && /^(?:0x)?[A-Za-z0-9+/=_-]+$/.test(whole);
            if (tools.length > 0 || (blobOnly && ACTIVE_CHARACTERS.test(decoded.text))) {
                findings.push({ encoding: decoded.encoding, tools, preview: decoded.text.slice(0, 80) });
            }
        }

        if (findings.length > 0) {
            return suspicious(this.tool, { name: clip(context.name), location: context.location, findings: findings.slice(0, 5) });
        }
        return safe(this.tool);
    }

    private static decode(value: string): Decoded[] {
        const results: Decoded[] = [];

        for (const match of [...value.matchAll(BASE64_BLOB)].slice(0, MAX_BLOBS)) {
            const blob = match[1];
            // pure hex also matches the base64 alphabet and is handled below
            if (/^[0-9a-f]+$/i.test(blob)) continue;
            const text = EncodedPayload.printable(Buffer.from(blob.replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
            if (text) results.push({ encoding: 'base64', text });
        }

        for (const match of [...value.matchAll(HEX_BLOB)].slice(0, MAX_BLOBS)) {
            const text = EncodedPayload.printable(Buffer.from(match[1], 'hex'));
            if (text) results.push({ encoding: 'hex', text });
        }

        if (PERCENT_RUN.test(value)) {
            try {
                results.push({ encoding: 'percent', text: decodeURIComponent(value) });
            } catch {
                // malformed escape: the other encodings are still checked
            }
        }

        return results;
    }

    // Decoded bytes only count when they are mostly printable text; random bytes are just binary data.
    private static printable(bytes: Buffer): string | undefined {
        if (bytes.length < 6) return undefined;
        const chars = [...bytes.toString('utf8')];
        const printable = chars.filter(char => /[\x20-\x7e\t\r\n]/.test(char)).length;
        return printable / chars.length >= 0.9 ? chars.join('') : undefined;
    }
}
