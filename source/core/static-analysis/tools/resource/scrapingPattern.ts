import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import {
    SlidingWindow, Tool, ToolCategory, ToolContextType, ToolResult, ToolState, distinct, failure, fieldLeaf, header, inRouteFilter, methodOf,
    pathOf, routeKey, safe, suspicious,
} from '@tessera/core/static-analysis/shared';

interface View {
    resource: string;
    page?: number;
    withReferer: boolean;
}

export default class ScrapingPattern extends Tool<ToolContextType.Full> {
    // (Redis, per tenant) client -> catalog views.
    private readonly views: SlidingWindow<View>;

    constructor(private readonly config: ToolConfig<'scraping_pattern'>, state: ToolState) {
        super({
            id: 'scraping_pattern',
            displayName: 'Scraping pattern',
            category: ToolCategory.Resource,
            contextType: ToolContextType.Full,
        });
        this.views = state.window<View>('views', config.windowMs, config.maxDistinctResources * 3);
    }

    override async run(context: NormalizedRequest): Promise<ToolResult> {
        const path = pathOf(context);
        if (methodOf(context) !== 'GET' || !inRouteFilter(path, this.config.routes)) {
            return safe(this.tool);
        }
        if (!context.clientIp) {
            return failure(this.tool, { reason: 'missing_client_identity' });
        }

        const pageField = context.fields.find(field => fieldLeaf(field.name) === 'page');
        const page = pageField !== undefined && /^\d{1,6}$/.test(String(pageField.value)) ? Number(pageField.value) : undefined;
        // a listing page is identified by its path and query, a product page by its path
        const query = context.fields.filter(field => field.location === 'query').map(field => `${field.name}=${String(field.value)}`).sort().join('&');
        const view: View = { resource: `${routeKey(path)}?${query}`, page, withReferer: header(context, 'referer') !== undefined };

        const now = typeof context.timestamp === 'number' ? context.timestamp : Date.now();
        const recent = await this.views.record(context.tenantId, context.clientIp, view, now);

        const findings: string[] = [];
        const resources = distinct(recent, value => value.resource).size;
        if (resources > this.config.maxDistinctResources) findings.push('high_catalog_coverage');

        const pages = [...new Set(recent.map(event => event.value.page).filter((value): value is number => value !== undefined))].sort((a, b) => a - b);
        let run = pages.length > 0 ? 1 : 0;
        let longest = run;
        for (let index = 1; index < pages.length; index++) {
            run = pages[index] === pages[index - 1] + 1 ? run + 1 : 1;
            longest = Math.max(longest, run);
        }
        if (longest >= this.config.minSequentialPages) findings.push('sequential_page_walk');

        if (findings.length === 0) {
            return safe(this.tool);
        }
        return suspicious(this.tool, {
            findings,
            distinctResources: resources,
            longestPageRun: longest,
            refererRatio: Math.round((recent.filter(event => event.value.withReferer).length / recent.length) * 100) / 100,
            windowMs: this.config.windowMs,
        });
    }
}
