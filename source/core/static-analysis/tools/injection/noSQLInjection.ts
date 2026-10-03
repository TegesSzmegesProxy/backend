import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

interface NoSqlInjectionRule {
    name: string;
    pattern: RegExp;
}

type Target = 'name' | 'key' | 'command' | 'value';

// Limits for walking nested values, so a huge or deeply nested body can't make this tool slow.
const MAX_DEPTH = 6;
const MAX_NODES = 1000;

// MongoDB-style query, update and aggregation operators and stages.
const OPERATORS = [
    'eq', 'ne', 'gt', 'gte', 'lt', 'lte', 'in', 'nin', 'exists', 'type', 'regex', 'options', 'where', 'expr',
    'jsonSchema', 'mod', 'text', 'all', 'elemMatch', 'size', 'and', 'or', 'nor', 'not', 'function',
    'accumulator', 'lookup', 'graphLookup', 'unionWith', 'out', 'merge', 'currentOp', 'listSessions',
    'listLocalSessions', 'collStats', 'indexStats', 'planCacheStats', 'set', 'unset', 'inc', 'push', 'pull',
    'pullAll', 'pop', 'addToSet', 'mul', 'setOnInsert', 'bit', 'rename',
].join('|');

// Collection methods in shell syntax: db.users.find(...), db["users"].remove(...), db.getCollection("x").drop()
const COLLECTION_METHODS = [
    'find', 'findOne', 'findOneAndDelete', 'findOneAndReplace', 'findOneAndUpdate', 'insert', 'insertOne',
    'insertMany', 'update', 'updateOne', 'updateMany', 'replaceOne', 'delete', 'deleteOne', 'deleteMany',
    'remove', 'drop', 'dropIndex', 'dropIndexes', 'createIndex', 'createIndexes', 'ensureIndex', 'reIndex',
    'aggregate', 'count', 'countDocuments', 'estimatedDocumentCount', 'distinct', 'mapReduce', 'bulkWrite',
    'renameCollection', 'save', 'explain', 'watch', 'stats', 'validate', 'getIndexes', 'totalSize',
    'storageSize', 'dataSize', 'initializeOrderedBulkOp', 'initializeUnorderedBulkOp',
].join('|');

// Database-level shell methods: db.dropDatabase(), db.getSiblingDB("admin"), db.runCommand(...)
const DB_METHODS = [
    'dropDatabase', 'getCollectionNames', 'getCollectionInfos', 'createCollection', 'createView', 'createUser',
    'dropUser', 'dropAllUsers', 'getUsers', 'getUser', 'updateUser', 'changeUserPassword', 'grantRolesToUser',
    'revokeRolesFromUser', 'createRole', 'dropRole', 'getRoles', 'auth', 'logout', 'getSiblingDB', 'getMongo',
    'runCommand', 'adminCommand', 'eval', 'currentOp', 'killOp', 'shutdownServer', 'serverStatus', 'stats',
    'hostInfo', 'version', 'fsyncLock', 'fsyncUnlock', 'copyDatabase', 'cloneDatabase', 'setProfilingLevel',
    'getProfilingStatus', 'getLogComponents', 'setLogLevel', 'getReplicationInfo', 'printReplicationInfo',
    'serverBuildInfo', 'serverCmdLineOpts', 'listCommands', 'loadServerScripts',
].join('|');

// Administrative commands as passed to runCommand/adminCommand, e.g. {"dropDatabase": 1}.
// A MongoDB command document always starts with the command name as its first key.
const ADMIN_COMMANDS = [
    'dropDatabase', 'dropAllUsersFromDatabase', 'dropAllRolesFromDatabase', 'dropUser', 'dropRole',
    'createUser', 'createRole', 'updateUser', 'updateRole', 'grantRolesToUser', 'revokeRolesFromUser',
    'grantPrivilegesToRole', 'usersInfo', 'rolesInfo', 'listDatabases', 'listCollections', 'listIndexes',
    'listCommands', 'dropIndexes', 'createIndexes', 'renameCollection', 'collMod', 'repairDatabase',
    'shutdown', 'fsync', 'fsyncUnlock', 'logRotate', 'killOp', 'killCursors', 'killAllSessions', 'currentOp',
    'serverStatus', 'hostInfo', 'buildInfo', 'connectionStatus', 'getParameter', 'setParameter',
    'getCmdLineOpts', 'getLog', 'replSetReconfig', 'replSetStepDown', 'replSetInitiate', 'addShard',
    'removeShard', 'enableSharding', 'shardCollection', 'eval', 'copydb', 'cloneCollection', 'mapReduce',
    'dbStats', 'collStats',
].join('|');

// No g flags, so RegExp.test has no lastIndex state on these shared constants.
// Applied to field names, object keys and string values.
const RULES: NoSqlInjectionRule[] = [
    {
        // {"$ne": null}   {'$gt': ''}   $regex: ".*"  -- the operator must be followed by a colon
        name: 'operator_json',
        pattern: new RegExp(`\\$(?:${OPERATORS})\\b["']?\\s*:`, 'i'),
    },
    {
        // user[$ne]=x   filter.$gt   -- query-string and dotted-path forms parsed into operators by some frameworks
        name: 'operator_path',
        pattern: new RegExp(`(?:\\[\\s*|\\.)\\$(?:${OPERATORS})\\b`, 'i'),
    },
    {
        // $where runs JavaScript on the server
        name: 'where_clause',
        pattern: /\$where\b/i,
    },
    {
        // this.password == "x"   function() { ... }   sleep(5000)
        name: 'js_expression',
        pattern: /\bthis\s*\.\s*\w+\s*(?:==|===|!=|!==|<|>)|\bfunction\s*\(|\bsleep\s*\(\s*\d+/i,
    },
    {
        // ' || '1'=='1   " && 1==1   ';return true;var x='
        name: 'js_tautology',
        pattern: /['"]\s*(?:\|\||&&)\s*['"]?\w*['"]?\s*={2,3}|;\s*return\s+(?:true|false|1|0)\b/i,
    },
    {
        // db.users.find(   db["users"].remove(   db.getCollection("users").drop(
        name: 'db_collection_method',
        pattern: new RegExp(
            `\\bdb\\s*(?:\\.\\s*\\w+|\\[\\s*["'][^"']+["']\\s*\\]|\\.\\s*getCollection\\s*\\(\\s*["'][^"']+["']\\s*\\))\\s*\\.\\s*(?:${COLLECTION_METHODS})\\s*\\(`,
            'i',
        ),
    },
    {
        // db.dropDatabase(   db.runCommand(   x.getSiblingDB(   x.adminCommand(
        name: 'db_method',
        pattern: new RegExp(`\\bdb\\s*\\.\\s*(?:${DB_METHODS})\\s*\\(|\\.\\s*(?:runCommand|adminCommand|getSiblingDB)\\s*\\(`, 'i'),
    },
    {
        // rs.initiate(   rs.reconfig(   sh.addShard(   sh.enableSharding(
        name: 'replica_or_shard_helper',
        pattern: /\b(?:rs|sh)\s*\.\s*(?:add|remove|initiate|reconfig|stepDown|freeze|syncFrom|addArb|conf|status|addShard|removeShard|enableSharding|shardCollection|moveChunk|splitAt|splitFind|startBalancer|stopBalancer)\s*\(/i,
    },
    {
        // "show dbs"   "show collections"   "use admin"  -- mongo shell helpers, only as a whole statement
        name: 'shell_helper',
        pattern: /(?:^|[;\r\n])\s*(?:show\s+(?:dbs|databases|collections|users|roles)|use\s+(?:admin|local|config))\s*(?:[;\r\n]|$)/i,
    },
    {
        // {"dropDatabase": 1}   {'shutdown': 1}   {eval: "..."}  -- command document passed to runCommand
        name: 'command_document',
        pattern: new RegExp(`\\{\\s*["']?(?:${ADMIN_COMMANDS})["']?\\s*:`, 'i'),
    },
    {
        // ObjectId("...")   ISODate("...")   NumberLong(...)  -- shell-only literals, not valid JSON
        name: 'shell_literal',
        pattern: /\b(?:ObjectId|ISODate|NumberLong|NumberInt|NumberDecimal|BinData)\s*\(/i,
    },
];

// Applied to field names and object keys only. In MongoDB a key that starts with $ is an operator.
const KEY_RULES: NoSqlInjectionRule[] = [
    {
        name: 'operator_key',
        pattern: /^\$[a-z]/i,
    },
];

// Applied to the first key of every object only: a command document starts with the command name,
// so {"dropDatabase": 1} is a command but {"user": "x", "dropDatabase": 1} is not.
const COMMAND_KEY_RULES: NoSqlInjectionRule[] = [
    {
        name: 'command_key',
        pattern: new RegExp(`^(?:${ADMIN_COMMANDS})$`, 'i'),
    },
];

export default class NoSqlInjection extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'nosql_injection',
            displayName: 'NoSQL injection',
            category: ToolCategory.Injection,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        const seen = new Set<string>();
        const findings: { target: Target; rule: string }[] = [];

        const check = (target: Target, text: string): void => {
            const rules = NoSqlInjection.rulesFor(target);
            for (const rule of rules) {
                const id = `${target}|${rule.name}`;
                if (!seen.has(id) && rule.pattern.test(text)) {
                    seen.add(id);
                    findings.push({ target, rule: rule.name });
                }
            }
        };

        // the field name is attacker-controlled too ("user[$ne]" arrives as a name, not as a value)
        if (typeof context.name === 'string') {
            check('name', context.name);
        }

        NoSqlInjection.walk(context.value, 0, { nodes: 0 }, check);

        if (findings.length > 0) {
            return {
                tool: this.tool,
                status: 'SUCCESS',
                verdict: 'SUSPICIOUS',
                evidence: { name: String(context.name).slice(0, 100), location: context.location, findings },
            };
        }

        return {
            tool: this.tool,
            status: 'SUCCESS',
            verdict: 'SAFE',
            evidence: undefined,
        };
    }

    private static rulesFor(target: Target): NoSqlInjectionRule[] {
        if (target === 'value') return RULES;
        if (target === 'command') return COMMAND_KEY_RULES;
        return [...KEY_RULES, ...RULES];
    }

    // Visits every string, every object key and every object's first key, down to MAX_DEPTH and up to MAX_NODES nodes.
    private static walk(
        value: unknown,
        depth: number,
        state: { nodes: number },
        visit: (target: Target, text: string) => void,
    ): void {
        if (depth > MAX_DEPTH || state.nodes++ >= MAX_NODES) {
            return;
        }

        if (typeof value === 'string') {
            visit('value', value);
            return;
        }

        if (Array.isArray(value)) {
            for (const item of value) {
                NoSqlInjection.walk(item, depth + 1, state, visit);
            }
            return;
        }

        if (typeof value === 'object' && value !== null) {
            const entries = Object.entries(value);
            if (entries.length > 0) {
                visit('command', entries[0][0]);
            }
            for (const [key, child] of entries) {
                visit('key', key);
                NoSqlInjection.walk(child, depth + 1, state, visit);
            }
        }
    }
}