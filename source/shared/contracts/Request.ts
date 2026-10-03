import { Endpoint } from './Endpoint';

export interface NormalizedRequest {
    requestId: string;
    tenantId: string;
    endpoint: Endpoint;
    clientIp: string;
    query: Record<string, string>;
    headers: Record<string, string>;
    body: unknown;
    fields: RequestField[];
    files: RequestFile[];
    timestamp: number;
}

export interface RequestField {
    name: string;
    value: unknown;
    type: string;
    location: string;
    metadata?: object;
}

export interface RequestFile {
    field: string;
    filename: string;
    contentType?: string;
    size: number;
    magicBytes?: string;
    metadata?: object;
}