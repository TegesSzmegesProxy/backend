import { NormalizedRequest, RequestField, RequestFile } from '@tessera/shared/contracts';

export enum ToolCategory {
    Schema = 'schema',
    Auth = 'auth',
    Injection = 'injection',
    Url = 'url',
    Resource = 'resource',
    Anomaly = 'anomaly',
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
    status: 'SUCCESS' | 'ERROR';
    verdict: 'SAFE' | 'SUSPICIOUS' | 'POLICY_VIOLATION' | 'ERROR';
    evidence: unknown | undefined;
}

interface ContextMap {
    [ToolContextType.Field]: RequestField;
    [ToolContextType.File]: RequestFile;
    [ToolContextType.Full]: NormalizedRequest;
}

export abstract class Tool<C extends ToolContextType> {
    constructor (public metadata: ToolMetadata<C>) {}

    abstract run(context: ContextMap[C]): ToolResult;

    get tool() {
        return this.metadata.id;
    }
}