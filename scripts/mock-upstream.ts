/**
 * A mock "protected application" for the JEV evaluation: it answers every endpoint in the fixture with a canned
 * response, so a request that reaches it is a request Tessera let through.
 *
 *   npm run mock:upstream            # listens on :9090
 */
import Fastify, { type FastifyInstance } from 'fastify';

const CANNED: Record<string, unknown> = {
    'POST /userLogin': { token: 'mock-session-token' },
    'POST /userRegister': { id: 1, created: true },
    'POST /comments': { id: 7, stored: true },
    'POST /search': { results: [{ id: 1, title: 'mock result' }] },
    'PATCH /profile': { updated: true },
    'POST /webhooks': { registered: true },
    'POST /diagnostics/ping': { output: '64 bytes from mock: icmp_seq=1 ttl=64 time=0.1 ms' },
    'POST /files/read': { contents: 'mock file contents' },
    'POST /snippets': { id: 3, stored: true },
    'POST /reports': { id: 9, received: true },
    'POST /cart': { items: 1 },
    'POST /upload': { stored: true },
    'PATCH /admin/users/42': { updated: true },
};

export async function startMockUpstream(port = 0): Promise<{ app: FastifyInstance; url: string }> {
    const app = Fastify({ bodyLimit: 8 * 1024 * 1024 });
    app.route({
        method: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
        url: '/*',
        handler: async (request, reply) => {
            const path = request.url.split('?')[0];
            reply.header('x-mock-upstream', '1');
            return { mock: true, route: `${request.method} ${path}`, ...(CANNED[`${request.method} ${path}`] as object | undefined) };
        },
    });
    const url = await app.listen({ port, host: '127.0.0.1' });
    return { app, url };
}

if (require.main === module) {
    startMockUpstream(Number(process.env['MOCK_UPSTREAM_PORT'] ?? 9090)).then(({ url }) => console.log(`mock upstream on ${url}`));
}
