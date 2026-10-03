import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

interface SqlInjectionRule {
    name: string;
    pattern: RegExp;
}

const RULES: SqlInjectionRule[] = [
    {
        name: 'union_select',
        pattern: /\bunion\b\s+(?:all\s+)?select\b/i,
    },
    {
        // ' OR '1'='1, " AND 1=1, ' or x like y
        name: 'quoted_tautology',
        pattern: /['"`]\s*(?:or|and)\s+['"`]?\w+['"`]?\s*(?:=|<>|!=|\blike\b)\s*['"`]?\w+/i,
    },
    {
        // 1 OR 1=1, 5 AND 5=5
        name: 'numeric_tautology',
        pattern: /\b(?:or|and)\s+(\d+)\s*=\s*\1\b/i,
    },
    {
        // '; DROP TABLE users
        name: 'stacked_query',
        pattern: /;\s*(?:drop|delete|insert|update|alter|create|truncate|exec|execute)\b/i,
    },
    {
        // admin'--  /  ' #  /  ' /*
        name: 'quote_then_comment',
        pattern: /['"`]\s*(?:--|#|\/\*)/,
    },
    {
        name: 'time_based',
        pattern: /\b(?:sleep|pg_sleep|benchmark)\s*\(|\bwaitfor\s+delay\b/i,
    },
    {
        name: 'schema_probe',
        pattern: /\b(?:information_schema|pg_catalog|sysobjects|sqlite_master)\b/i,
    },
    {
        name: 'dangerous_procedure',
        pattern: /\b(?:xp_cmdshell|load_file|into\s+(?:out|dump)file)\b/i,
    },
];

export default class SqlInjection extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'sql_injection',
            displayName: 'SQL injection',
            category: ToolCategory.Injection,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        if (typeof context.value !== 'string') {
            return {
                tool: this.tool,
                status: 'SUCCESS',
                verdict: 'SAFE',
                evidence: undefined,
            };
        }

        const value = context.value;
        const matched = RULES
            .filter(rule => rule.pattern.test(value))
            .map(rule => rule.name);

        if (matched.length > 0) {
            return {
                tool: this.tool,
                status: 'SUCCESS',
                verdict: 'SUSPICIOUS',
                evidence: matched,
            };
        }

        return {
            tool: this.tool,
            status: 'SUCCESS',
            verdict: 'SAFE',
            evidence: undefined,
        };
    }
}