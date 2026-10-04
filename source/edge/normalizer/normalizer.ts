import { NormalizedRequest, RequestField } from "@tessera/shared/contracts"
import { FastifyRequest } from "fastify";
import { createHash } from "node:crypto";

type Location = "body" | "query";

class Normalizer {
    normalize(request: FastifyRequest, tenantId: string): NormalizedRequest {
        // A bodiless request yields no body fields, so one path serves every method.
        const fields = [
            ...Normalizer.extractFields(request.body, "body"),
            ...Normalizer.extractFields(request.query, "query"),
        ];
        return {
            requestId: request.id,
            tenantId,
            endpoint: this.endpoint(request),
            clientIp: request.ip,
            query: this.stringRecord(request.query),
            headers: this.stringRecord(request.headers),
            body: request.body,
            requestHash: Normalizer.hashFields(request.ip, fields),
            fields,
            files: [],
            timestamp: Date.now(),
        };
    }

    // `routeOptions.url` is the matched route pattern (e.g. `/*` on a catch-all), not the
    // requested path, so the path is taken from the raw URL.
    private endpoint(request: FastifyRequest): string {
        const path = request.url.split("?")[0] ?? "/";
        return `${request.method} ${path}`;
    }

    private static hashFields(ip: string, fields: RequestField[]): string {
        const names = fields.map((f) => f.name).join("");
        const values = fields.map((f) => String(f.value)).join("");
        return createHash("sha256").update(ip + names + values).digest("hex");
    }

    private static extractFields(payload: unknown, location: Location): RequestField[] {
        const fields: RequestField[] = [];
        this.flatten(payload, "", location, fields);
        return fields;
    }

    private static flatten(node: unknown, path: string, location: Location, out: RequestField[]) {
        if (node !== null && typeof node === "object") {
            const entries = Array.isArray(node)
                ? node.map((v, i) => [String(i), v] as const)
                : Object.entries(node).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
            for (const [key, value] of entries) {
                this.flatten(value, path ? `${path}.${key}` : key, location, out);
            }
            return;
        }
        if (node === undefined && path === "") return;
        out.push({ name: path, value: node, type: node === null ? "null" : typeof node, location });
    }

    private stringRecord(source: unknown): Record<string, string> {
        const result: Record<string, string> = {};
        if (source === null || typeof source !== "object") return result;
        for (const [key, value] of Object.entries(source)) {
            if (value === undefined) continue;
            result[key] = Array.isArray(value) ? value.join(",") : typeof value === "object" ? JSON.stringify(value) : String(value);
        }
        return result;
    }
}

export { Normalizer };
