import { defineConfig } from 'vitest/config';
import { resolve } from 'path';

export default defineConfig({
    test: {
        globals: true,
        environment: 'node',
        include: ['tests/**/*.test.ts'],
        coverage: {
            provider: 'v8',
            reporter: ['text', 'json', 'html'],
            include: ['source/**/*.ts'],
            exclude: ['**/*.test.ts', '**/index.ts'],
        },
    },
    resolve: {
        alias: [
            {
                find: /^@tessera\/(.+)$/,
                replacement: resolve(__dirname, './source/$1/index.ts'),
            },
        ],
    },
});