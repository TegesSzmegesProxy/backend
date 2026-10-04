import { NormalizedRequest, RequestField, RequestFile } from '@tessera/shared/contracts';

export enum ToolCategory {
    Schema = 'schema',
    Auth = 'auth',
    Injection = 'injection',
    Url = 'url',
    Resource = 'resource',
    Anomaly = 'anomaly',
    Protocol = 'protocol',
    Bot = 'bot',
    DataLeakage = 'data_leakage',
}

export enum ToolContextType {
    Field = 'field',
    File = 'file',
    Full = 'full',
}

export interface ToolMetadata<C extends ToolContextType> {
    id: string;
    displayName: string;
    category: ToolCategory;
    contextType: C;
}

export interface ToolResult {
    tool: string;
    /** The field or file the tool inspected; absent for whole-request tools. Set by the Runner. */
    target?: string;
    status: 'SUCCESS' | 'ERROR';
    verdict: 'SAFE' | 'SUSPICIOUS' | 'POLICY_VIOLATION' | 'ERROR';
    evidence: unknown | undefined;
}

export interface ContextMap {
    [ToolContextType.Field]: RequestField;
    [ToolContextType.File]: RequestFile;
    [ToolContextType.Full]: NormalizedRequest;
}

export abstract class Tool<C extends ToolContextType> {
    constructor (public metadata: ToolMetadata<C>) {}

    /** Tools that keep state across requests (in Redis) are async; the others answer synchronously. */
    abstract run(context: ContextMap[C]): ToolResult | Promise<ToolResult>;

    get tool() {
        return this.metadata.id;
    }
}