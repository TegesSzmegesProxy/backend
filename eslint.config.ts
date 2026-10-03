import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import prettier from 'eslint-config-prettier';

export default tseslint.config(
    js.configs.recommended,
    ...tseslint.configs.recommended,
    {
        files: ['**/*.ts'],
        languageOptions: {
            parserOptions: {
                project: ['./tsconfig.json', './tsconfig.test.json']
            }
        }
    },
    {
        ignores: ['dist/**', 'node_modules/**', '*.config.js', '*.config.ts', 'build.js']
    },
    prettier,
    {
        rules: {
            'no-unused-vars': 'off',
            '@typescript-eslint/no-unused-vars': [
                'error',
                {
                    argsIgnorePattern: '^_',
                    varsIgnorePattern: '^_',
                    caughtErrorsIgnorePattern: '^_'
                }
            ],
            '@typescript-eslint/no-empty-object-type': 'off',
            '@typescript-eslint/no-namespace': 'off',
        }
    }
)