import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { FastifyRequest } from 'fastify';
import { Normalizer } from '../../source/edge/normalizer';
import { Runner, type ExecutionPlan, type ToolStep } from '../../source/core/static-analysis/runner';
import { Aggregator, type StaticVerdict } from '../../source/core/static-analysis/aggregator';
import { Tool, ToolContextType } from '../../source/core/static-analysis/shared';
import type { NormalizedRequest, RequestFile } from '../../source/shared/contracts';
import SqlInjection from '../../source/core/static-analysis/tools/injection/sqlinjection';
import Xss from '../../source/core/static-analysis/tools/injection/xss';
import CommandInjection from '../../source/core/static-analysis/tools/injection/commandinjection';
import NullByte from '../../source/core/static-analysis/tools/injection/nullByte';
import ControlCharacter from '../../source/core/static-analysis/tools/injection/controlCharacter';
import Ssrf from '../../source/core/static-analysis/tools/url/ssrf';
import UrlValidator from '../../source/core/static-analysis/tools/url/urlValidator';
import TypeCheck from '../../source/core/static-analysis/tools/schema/typeCheck';
import IntegerRange from '../../source/core/static-analysis/tools/schema/integerRange';
import StringLength from '../../source/core/static-analysis/tools/schema/stringLength';
import MimeType from '../../source/core/static-analysis/tools/schema/mimeType';
import FileSize from '../../source/core/static-analysis/tools/resource/fileSize';
import ArchiveExpansionRatio from '../../source/core/static-analysis/tools/resource/archiveExpantionRatio';
import RequestSize from '../../source/core/static-analysis/tools/resource/requestSize';
import RateLimit from '../../source/core/static-analysis/tools/resource/rateLimit';
import PrivateIp from '../../source/core/static-analysis/tools/anomaly/privateIP';
import DuplicateRequest from '../../source/core/static-analysis/tools/anomaly/duplicateRequest';

export const EVAL_TENANT = '3f2b8c1e-4a5d-4e6f-8a7b-9c0d1e2f3a4b';

export interface EndpointPolicy {
    /** Declared type per flattened field name, as a compiled policy would supply. Overrides `typeof`. */
    declared: Record<string, string>;
    /** Extra field tools by field name, on top of the tools every field gets. */
    extraTools?: Record<string, string[]>;
    /** Tools run on every file the request carries. */
    fileTools?: string[];
}

export interface EvalFile {
    field: string;
    filename: string;
    contentType?: string;
    size: number;
    magicBytes?: string;
    metadata?: object;
}

export interface EvalCase {
    name: string;
    /** `attack` should end in BLOCK, `benign` in ALLOW. */
    label: 'attack' | 'benign';
    category: string;
    /** Why the label is right; the reason a case is hard. */
    why: string;
    /** `METHOD /path`, a key of the fixture's endpoints. */
    endpoint: string;
    body?: unknown;
    query?: Record<string, string>;
    files?: EvalFile[];
    clientIp?: string;
    /** Sends the request this many times; the last one is the case. */
    repeat?: number;
}

export interface Fixture {
    endpoints: Record<string, EndpointPolicy>;
    cases: EvalCase[];
}

type FieldTool = Tool<ToolContextType.Field>;
type FileTool = Tool<ToolContextType.File>;
type FullTool = Tool<ToolContextType.Full>;

/** Run on every field of every request. */
const DEFAULT_FIELD_TOOLS: (new () => FieldTool)[] = [SqlInjection, Xss, CommandInjection, Ssrf, NullByte, ControlCharacter, TypeCheck];
const EXTRA_FIELD_TOOLS: Record<string, new () => FieldTool> = {
    url_validator: UrlValidator,
    integer_range: IntegerRange,
    string_length: StringLength,
};
const FILE_TOOLS: Record<string, new () => FileTool> = {
    file_size: FileSize,
    mime_type: MimeType,
    archive_expansion_ratio: ArchiveExpansionRatio,
};
/** Run on every request. */
const REQUEST_TOOLS: (new () => FullTool)[] = [PrivateIp, DuplicateRequest, RateLimit, RequestSize];

/** Ids of every tool the fixture can exercise. */
export const ALL_TOOL_IDS: string[] = [
    ...DEFAULT_FIELD_TOOLS,
    ...Object.values(EXTRA_FIELD_TOOLS),
    ...Object.values(FILE_TOOLS),
    ...REQUEST_TOOLS,
].map((Tool) => new Tool().tool);

export function loadFixture(): Fixture {
    return JSON.parse(readFileSync(resolve(__dirname, 'jev-cases.json'), 'utf8'));
}

/** A case's own address, so rate-limit and duplicate state never leaks between cases. */
export function defaultClientIp(index: number): string {
    return `203.0.113.${(index % 250) + 1}`;
}

/** `{ "$repeat": ["A", 3] }` stands for "AAA", so the fixture can hold large values compactly. */
export function expandValue(value: unknown): unknown {
    if (Array.isArray(value)) return value.map(expandValue);
    if (value !== null && typeof value === 'object') {
        const repeat = (value as { $repeat?: [string, number] }).$repeat;
        if (repeat) return repeat[0].repeat(repeat[1]);
        return Object.fromEntries(Object.entries(value).map(([key, inner]) => [key, expandValue(inner)]));
    }
    return value;
}

export function splitEndpoint(endpoint: string): { method: string; path: string } {
    const space = endpoint.indexOf(' ');
    return { method: endpoint.slice(0, space), path: endpoint.slice(space + 1) };
}

/** Sets the declared field types and files that the normalizer cannot know, as a compiled policy would. */
export function applyPolicy(request: NormalizedRequest, policy: EndpointPolicy, files: EvalFile[] = []): NormalizedRequest {
    return {
        ...request,
        fields: request.fields.map((field) => ({ ...field, type: policy.declared[field.name] ?? field.type })),
        files: files.map((file): RequestFile => ({ ...file })),
    };
}

/** The execution plan a compiled policy would give this request. */
export function planFor(request: NormalizedRequest, policy: EndpointPolicy): ExecutionPlan {
    const plan: ToolStep[] = [];
    const names = [...new Set(request.fields.map((field) => field.name))];

    for (const name of names) {
        // zod_type_check only knows JSON types, so a policy type such as "url" is checked by its own tool instead.
        const zodKnowsType = policy.declared[name] !== 'url';
        for (const Tool of DEFAULT_FIELD_TOOLS) {
            if (Tool === TypeCheck && !zodKnowsType) continue;
            plan.push({ tool: new Tool(), target: name });
        }
        for (const id of policy.extraTools?.[name] ?? []) plan.push({ tool: new EXTRA_FIELD_TOOLS[id](), target: name });
    }
    for (const field of [...new Set(request.files.map((file) => file.field))]) {
        for (const id of policy.fileTools ?? []) plan.push({ tool: new FILE_TOOLS[id](), target: field });
    }
    for (const Tool of REQUEST_TOOLS) plan.push({ tool: new Tool() });
    return plan;
}

/** Builds the request the proxy would see for attempt `attempt` of a case, through the real normalizer. */
export function buildRequest(testCase: EvalCase, index: number, fixture: Fixture, attempt = 0): NormalizedRequest {
    const policy = fixture.endpoints[testCase.endpoint];
    if (!policy) throw new Error(`Case "${testCase.name}" uses undeclared endpoint ${testCase.endpoint}`);
    const { method, path } = splitEndpoint(testCase.endpoint);

    const fake = {
        id: `${testCase.name}#${attempt}`,
        method,
        url: path,
        ip: testCase.clientIp ?? defaultClientIp(index),
        headers: {},
        query: testCase.query ?? {},
        body: expandValue(testCase.body),
    } as unknown as FastifyRequest;

    return applyPolicy(new Normalizer().normalize(fake, EVAL_TENANT), policy, testCase.files);
}

export interface StaticOutcome {
    request: NormalizedRequest;
    verdict: StaticVerdict;
    /** Tools that returned anything but SAFE, with the field they inspected. */
    hits: string[];
}

/** Sends the case through the real static pipeline; repeats run too, so rate and duplicate tools see them. */
export function runStatic(testCase: EvalCase, index: number, fixture: Fixture): StaticOutcome {
    const runner = new Runner();
    const aggregator = new Aggregator();
    const policy = fixture.endpoints[testCase.endpoint];

    let outcome!: StaticOutcome;
    for (let attempt = 0; attempt < (testCase.repeat ?? 1); attempt++) {
        const request = buildRequest(testCase, index, fixture, attempt);
        const results = runner.run(request, planFor(request, policy));
        outcome = {
            request,
            verdict: aggregator.aggregate(results),
            hits: results
                .filter((result) => result.verdict !== 'SAFE')
                .map((result) => (result.target ? `${result.tool}(${result.target})` : result.tool)),
        };
    }
    return outcome;
}

/** Tool ids that returned anything but SAFE for any attempt of the case. */
export function toolsFired(testCase: EvalCase, index: number, fixture: Fixture): Set<string> {
    const runner = new Runner();
    const policy = fixture.endpoints[testCase.endpoint];
    const fired = new Set<string>();
    for (let attempt = 0; attempt < (testCase.repeat ?? 1); attempt++) {
        const request = buildRequest(testCase, index, fixture, attempt);
        for (const result of runner.run(request, planFor(request, policy))) {
            if (result.verdict !== 'SAFE') fired.add(result.tool);
        }
    }
    return fired;
}
