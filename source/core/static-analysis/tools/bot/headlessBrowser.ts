import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, browserFamily, clip, fieldLeaf, header, safe, suspicious } from '@tessera/core/static-analysis/shared';

// Automation markers in the User-Agent or client hints.
const AUTOMATION_AGENTS = /HeadlessChrome|PhantomJS|SlimerJS|Puppeteer|Playwright|Selenium|WebDriver|Electron\/|jsdom|HtmlUnit|Splash/i;
// Headers automation frameworks or their proxies add.
const AUTOMATION_HEADERS = ['x-puppeteer-request', 'x-devtools-emulate-network-conditions-client-id', 'x-playwright', 'x-selenium'];
export default class HeadlessBrowser extends Tool<ToolContextType.Full> {
    // signals reported by the application's own client-side script (navigator.webdriver, missing plugins, ...)
    private readonly clientSignalFields: ReadonlySet<string>;

    constructor(config: ToolConfig<'headless_browser'>) {
        super({
            id: 'headless_browser',
            displayName: 'Headless browser',
            category: ToolCategory.Bot,
            contextType: ToolContextType.Full,
        });
        this.clientSignalFields = new Set(config.clientSignalFields);
    }

    override run(context: NormalizedRequest): ToolResult {
        const userAgent = header(context, 'user-agent') ?? '';
        const findings: { rule: string; detail?: string }[] = [];

        const agent = userAgent.match(AUTOMATION_AGENTS);
        if (agent) findings.push({ rule: 'automation_user_agent', detail: agent[0] });

        const brands = header(context, 'sec-ch-ua') ?? '';
        if (/HeadlessChrome/i.test(brands)) findings.push({ rule: 'headless_client_hint' });

        for (const name of AUTOMATION_HEADERS) {
            if (header(context, name) !== undefined) findings.push({ rule: 'automation_header', detail: name });
        }

        // headless Chrome's defaults: no Accept-Language, and "en-US" without q-values when it is set
        const browser = browserFamily(userAgent);
        if (browser?.family === 'chrome' && header(context, 'accept-language') === undefined) {
            findings.push({ rule: 'chrome_without_accept_language' });
        }

        const signal = context.fields.find(field => this.clientSignalFields.has(fieldLeaf(field.name)) && (field.value === true || field.value === 'true' || field.value === 1));
        if (signal) findings.push({ rule: 'client_reported_automation', detail: clip(signal.name, 50) });

        // suspicious, not blocked: monitoring, link previews and test suites run headless legitimately
        return findings.length > 0 ? suspicious(this.tool, { findings }) : safe(this.tool);
    }
}
