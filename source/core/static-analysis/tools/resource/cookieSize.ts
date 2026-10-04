import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, cookiesOf, headerValues, safe, violation } from '@tessera/core/static-analysis/shared';

export default class CookieSize extends Tool<ToolContextType.Full> {
    constructor(private readonly config: ToolConfig<'cookie_size'>) {
        super({
            id: 'cookie_size',
            displayName: 'Cookie count and size',
            category: ToolCategory.Resource,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const cookies = cookiesOf(context);
        if (cookies.length === 0) {
            return safe(this.tool);
        }

        const { maxCookies, maxCookieBytes, maxTotalBytes } = this.config;
        const totalBytes = headerValues(context, 'cookie').reduce((sum, value) => sum + Buffer.byteLength(value), 0);
        const oversized = cookies
            .filter(([name, value]) => Buffer.byteLength(name) + Buffer.byteLength(value) + 1 > maxCookieBytes)
            .map(([name, value]) => ({ name: clip(name, 50), bytes: Buffer.byteLength(name) + Buffer.byteLength(value) + 1 }));

        const reasons: string[] = [];
        if (cookies.length > maxCookies) reasons.push('too_many_cookies');
        if (oversized.length > 0) reasons.push('cookie_too_large');
        if (totalBytes > maxTotalBytes) reasons.push('cookies_too_large_in_total');

        return reasons.length > 0
            ? violation(this.tool, { reasons, count: cookies.length, totalBytes, oversized: oversized.slice(0, 5) })
            : safe(this.tool);
    }
}
