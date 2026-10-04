// Writes docs/tool-registry.json from the tool contracts in source/shared/contracts/tools: every tool the proxy
// can execute, its metadata and the JSON Schema of its configuration. Run after changing a contract:
//   npm run tools:registry
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { toolRegistryDocument } from '../source/shared/contracts/tools';

const target = resolve(__dirname, '../docs/tool-registry.json');
const document = toolRegistryDocument();
writeFileSync(target, `${JSON.stringify(document, null, 2)}\n`);
console.log(`Wrote ${document.tools.length} tools (${document.registryVersion}) to ${target}`);
