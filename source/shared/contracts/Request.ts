
export interface NormalizedRequest {
    requestId: string;
    tenantId: string;
    endpoint: string;
    clientIp: string;
    query: Record<string, string>;
    headers: Record<string, string>;
    body: unknown;
    requestHash: string,
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