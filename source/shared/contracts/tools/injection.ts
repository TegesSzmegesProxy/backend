import { z } from "zod";
import { defineTool, noConfig, positiveCount, type ToolContextTypeName } from "./common";

// Injection detectors are fixed, versioned signature sets: the registry version pins their rules, and a policy
// only chooses where they run. The exception is GraphQL injection, whose abuse thresholds depend on the schema.

const detector = <const Id extends string, const Context extends ToolContextTypeName>(id: Id, displayName: string, contextType: Context, description: string) =>
  defineTool({ id, displayName, category: "injection", contextType, description, config: noConfig() });

export const injectionTools = {
  code_injection: detector("code_injection", "Code injection", "field", "Detects server-side code execution payloads (eval, constructor chains, process access)."),
  command_injection: detector("command_injection", "Command injection", "field", "Detects shell metacharacters chaining or substituting OS commands."),
  control_character: detector("control_character", "Control character", "field", "Detects control, bidi and zero-width characters, and line breaks in single-line locations."),
  css_injection: detector("css_injection", "CSS injection", "field", "Detects CSS that runs script, loads remote resources or exfiltrates through selectors."),
  csv_injection: detector("csv_injection", "CSV / formula injection", "field", "Detects spreadsheet formulas that execute or exfiltrate when an export is opened."),
  email_header_injection: detector("email_header_injection", "Email header injection", "field", "Detects line breaks that add mail headers (Bcc, Subject) through form fields."),
  expression_language_injection: detector("expression_language_injection", "Expression language injection", "field", "Detects Java EL, SpEL and OGNL expressions."),
  graphql_injection: defineTool({
    id: "graphql_injection",
    displayName: "GraphQL injection",
    category: "injection",
    contextType: "full",
    description: "Flags alias batching, directive overloading, field duplication, fragment abuse and GraphQL syntax smuggled into variables.",
    config: z.strictObject({
      maxSameFieldAliases: positiveCount(10_000).default(5).describe("One field requested under more aliases than this: e.g. 100 login mutations in one call."),
      maxDirectivesPerField: positiveCount(1000).default(5),
      maxSameFieldRepeats: positiveCount(100_000).default(50),
      maxFragments: positiveCount(10_000).default(50),
    }),
  }),
  http_parameter_pollution: detector("http_parameter_pollution", "HTTP parameter pollution", "full", "Detects parameters repeated with different values, which parsers resolve differently."),
  insecure_deserialization: detector("insecure_deserialization", "Insecure deserialization", "field", "Detects serialized Java, .NET, PHP, Python and YAML object payloads."),
  jndi_lookup: detector("jndi_lookup", "JNDI lookup (Log4Shell)", "field", "Detects ${jndi:...} lookups, including nested and obfuscated forms."),
  ldap_injection: detector("ldap_injection", "LDAP injection", "field", "Detects LDAP filter metacharacters that change a directory query."),
  malicious_file_upload: detector("malicious_file_upload", "Malicious file upload", "file", "Detects executables, scripts, server pages and server-configuration files uploaded by name or content."),
  nosql_injection: detector("nosql_injection", "NoSQL injection", "field", "Detects MongoDB operators, server-side JavaScript and shell methods in values."),
  null_byte: detector("null_byte", "Null byte", "field", "Detects raw and encoded NUL bytes that truncate strings in lower layers."),
  path_traversal: detector("path_traversal", "Path traversal", "field", "Detects ../ sequences, including encoded forms, and references to sensitive files."),
  polyglot_file: detector("polyglot_file", "Polyglot file", "file", "Detects uploads that are valid as two formats at once (an image that is also a script or archive)."),
  prompt_injection: detector("prompt_injection", "Prompt injection", "full", "Detects instructions aimed at an LLM that override its system prompt or exfiltrate data."),
  prototype_pollution: detector("prototype_pollution", "Prototype pollution", "field", "Detects __proto__, constructor and prototype keys that modify object prototypes."),
  regex_injection: detector("regex_injection", "Regex injection (ReDoS)", "field", "Detects user-supplied patterns with catastrophic backtracking."),
  shellshock: detector("shellshock", "Shellshock", "full", "Detects bash function definitions in headers (CVE-2014-6271)."),
  sql_injection: detector("sql_injection", "SQL injection", "field", "Detects SQL syntax that breaks out of a literal or adds clauses."),
  ssi_injection: detector("ssi_injection", "Server-side include injection", "field", "Detects <!--#exec --> and other server-side include directives."),
  ssti: detector("ssti", "Server-side template injection (SSTI)", "field", "Detects template expressions for Jinja, Twig, Freemarker, Velocity, Handlebars and others."),
  svg_script: detector("svg_script", "Script in SVG", "file", "Detects script, event handlers, external references and embedded documents in uploaded SVG images."),
  webshell_signature: detector("webshell_signature", "Webshell signature", "full", "Detects known webshell code and command-and-control parameters in bodies and uploads."),
  xpath_injection: detector("xpath_injection", "XPath injection", "field", "Detects XPath syntax that breaks out of a predicate."),
  xss: detector("xss", "Cross-site scripting (XSS)", "field", "Detects script tags, event handlers and javascript: URLs, including encoded forms."),
  xxe: detector("xxe", "XML external entity (XXE)", "full", "Detects DOCTYPE declarations with external entities or parameter entities in XML bodies."),
  zip_slip: detector("zip_slip", "Zip slip", "file", "Detects archive entries whose paths escape the extraction directory."),
} as const;
