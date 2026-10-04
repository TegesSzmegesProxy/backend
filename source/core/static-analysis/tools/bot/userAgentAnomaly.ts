import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, browserFamily, clip, header, safe, suspicious } from '@tessera/core/static-analysis/shared';

export default class UserAgentAnomaly extends Tool<ToolContextType.Full> {
    constructor(private readonly config: ToolConfig<'user_agent_anomaly'>) {
        super({
            id: 'user_agent_anomaly',
            displayName: 'User-Agent anomaly',
            category: ToolCategory.Bot,
            contextType: ToolContextType.Full,
        });
    }

    override run(context: NormalizedRequest): ToolResult {
        const userAgent = header(context, 'user-agent');
        if (userAgent === undefined) {
            return suspicious(this.tool, { findings: ['missing_user_agent'] });
        }

        const findings: string[] = [];
        const trimmed = userAgent.trim();

        if (trimmed.length < this.config.minLength) findings.push('too_short');
        if (trimmed.length > this.config.maxLength) findings.push('too_long');
        // "product/version" is the minimum shape (RFC 9110); "test", "-" or "${jndi:...}" are not
        if (!/^[\w.!#$%&'*+^`|~-]+\/[\w.+-]+/.test(trimmed)) findings.push('malformed');
        if (/[\u0000-\u001f\u007f]/.test(userAgent)) findings.push('control_characters');
        if (/\bMSIE \d|\bTrident\//.test(userAgent)) findings.push('internet_explorer');

        const browser = browserFamily(userAgent);
        // majors older than config.minMajor are years out of date; real users auto-update, old bot kits don't
        if (browser && browser.major < this.config.minMajor[browser.family]) {
            findings.push('outdated_browser_version');
        }

        // Client hints must agree with the User-Agent they accompany.
        const hintBrands = header(context, 'sec-ch-ua');
        const hintPlatform = header(context, 'sec-ch-ua-platform')?.replace(/"/g, '').toLowerCase();
        const hintMobile = header(context, 'sec-ch-ua-mobile');
        if (hintBrands !== undefined && (browser?.family === 'firefox' || browser?.family === 'safari')) {
            findings.push('client_hints_from_browser_without_them'); // only Chromium sends sec-ch-ua
        }
        if (hintPlatform) {
            const uaPlatform = /Windows NT/.test(userAgent) ? 'windows' : /Android/.test(userAgent) ? 'android'
                : /iPhone|iPad/.test(userAgent) ? 'ios' : /Mac OS X/.test(userAgent) ? 'macos' : /CrOS/.test(userAgent) ? 'chrome os'
                    : /Linux/.test(userAgent) ? 'linux' : undefined;
            if (uaPlatform && uaPlatform !== hintPlatform) findings.push('platform_mismatch');
        }
        if (hintMobile !== undefined && (hintMobile.trim() === '?1') !== /Mobile|Android/.test(userAgent)) {
            findings.push('mobile_flag_mismatch');
        }

        return findings.length > 0 ? suspicious(this.tool, { findings, userAgent: clip(userAgent, 150) }) : safe(this.tool);
    }
}
