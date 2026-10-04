import { z } from "zod";
import { defineTool, list, name, names, noConfig, positiveCount, regexFlags, regexSource } from "./common";

const MAX_JSON_SCHEMA_BYTES = 100_000;

export const STRING_LENGTH_OPERATORS = ["<", ">", "<=", ">="] as const;

const textLocations = () => list(name(32), 20).default(["query", "header", "headers", "path", "cookie", "form"])
  .describe("Locations whose transport only carries text, where \"42\" is the only way to send 42.");

const jsonSchema = z.record(z.string(), z.unknown()).refine((value) => {
  try {
    if (JSON.stringify(value).length > MAX_JSON_SCHEMA_BYTES) return false;
    z.fromJSONSchema(value as Parameters<typeof z.fromJSONSchema>[0]);
    return true;
  } catch {
    return false;
  }
}, `a JSON Schema zod can compile, at most ${MAX_JSON_SCHEMA_BYTES} bytes`);

export const schemaTools = {
  additional_properties: defineTool({
    id: "additional_properties",
    displayName: "Additional properties",
    category: "schema",
    contextType: "full",
    description: "Rejects top-level JSON body properties the endpoint does not declare.",
    config: z.strictObject({
      properties: names().describe("Top-level body properties the endpoint accepts; anything else is undeclared."),
    }),
  }),
  array_uniqueness: defineTool({
    id: "array_uniqueness",
    displayName: "Array uniqueness",
    category: "schema",
    contextType: "full",
    description: "Rejects repeated items in body arrays that must be unique (votes, coupon codes).",
    config: z.strictObject({
      properties: names().min(1).describe("Top-level body properties holding arrays whose items must be unique."),
    }),
  }),
  duplicate_json_keys: defineTool({
    id: "duplicate_json_keys",
    displayName: "Duplicate JSON keys",
    category: "schema",
    contextType: "full",
    description: "Rejects JSON bodies that repeat a key in one object, which parsers resolve differently.",
    config: noConfig(),
  }),
  enum_validation: defineTool({
    id: "enum_validation",
    displayName: "Enum validation",
    category: "schema",
    contextType: "field",
    description: "Rejects field values outside the allowed set (exact, case-sensitive match).",
    config: z.strictObject({
      values: list(z.union([z.string().max(256), z.number().finite()]), 1000).min(1),
    }),
  }),
  file_name_validation: defineTool({
    id: "file_name_validation",
    displayName: "File name validation",
    category: "schema",
    contextType: "file",
    description: "Rejects upload file names with path separators, reserved device names, control or invisible characters.",
    config: z.strictObject({
      maxLength: positiveCount(4096).default(255),
    }),
  }),
  format_validation: defineTool({
    id: "format_validation",
    displayName: "Format validation",
    category: "schema",
    contextType: "field",
    description: "Rejects string fields that do not match a well-known format.",
    config: z.strictObject({
      format: z.enum(["email", "uuid", "date", "datetime", "phone", "iban", "uri", "postalcode", "currency"]),
    }),
  }),
  integer_range: defineTool({
    id: "integer_range",
    displayName: "Integer range",
    category: "schema",
    contextType: "field",
    description: "Rejects integer fields outside inclusive bounds.",
    config: z.strictObject({
      min: z.number().int().optional(),
      max: z.number().int().optional(),
    }).refine((value) => value.min !== undefined || value.max !== undefined, "set min, max or both")
      .refine((value) => value.min === undefined || value.max === undefined || value.min <= value.max, "min must not exceed max"),
  }),
  invalid_utf8: defineTool({
    id: "invalid_utf8",
    displayName: "Invalid UTF-8 and charset",
    category: "schema",
    contextType: "full",
    description: "Rejects unexpected charsets, lone surrogates and noncharacters; flags replacement characters and UTF-7.",
    config: z.strictObject({
      allowedCharsets: list(name(40).regex(/^[a-z0-9._:-]+$/), 50).default(["utf-8", "utf8", "us-ascii", "ascii"]).describe("Lowercase charsets a Content-Type may declare."),
    }),
  }),
  json_schema: defineTool({
    id: "json_schema",
    displayName: "JSON schema",
    category: "schema",
    contextType: "full",
    description: "Validates the whole request body against a JSON Schema.",
    config: z.strictObject({
      schema: jsonSchema,
    }),
  }),
  mime_type: defineTool({
    id: "mime_type",
    displayName: "MIME type",
    category: "schema",
    contextType: "file",
    description: "Rejects uploads whose declared type is not allowed; flags content that does not match its type or is executable.",
    config: z.strictObject({
      allowedTypes: list(name(255).regex(/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/, "lowercase type/subtype"), 200).min(1).default([
        "image/png", "image/jpeg", "image/gif", "image/webp", "application/pdf", "text/plain", "text/csv", "application/json",
      ]).describe("Lowercase MIME types without parameters."),
    }),
  }),
  number_special_values: defineTool({
    id: "number_special_values",
    displayName: "Special number values",
    category: "schema",
    contextType: "field",
    description: "Rejects NaN, Infinity, negative zero, unsafe integers and numbers near overflow.",
    config: z.strictObject({
      maxMagnitude: z.number().finite().positive().default(1e300).describe("Magnitudes above this overflow to Infinity after a multiplication or two."),
    }),
  }),
  openapi_conformance: defineTool({
    id: "openapi_conformance",
    displayName: "OpenAPI conformance",
    category: "schema",
    contextType: "full",
    description: "Rejects query parameters the endpoint's API description does not document.",
    config: z.strictObject({
      queryParameters: names().describe("Query parameters the endpoint documents."),
    }),
  }),
  regex_pattern: defineTool({
    id: "regex_pattern",
    displayName: "Allowlist pattern",
    category: "schema",
    contextType: "field",
    description: "Rejects scalar field values that do not match an allowlist pattern (always anchored to the whole value).",
    config: z.strictObject({
      pattern: regexSource(),
      flags: regexFlags().default(""),
      maxLength: positiveCount(65_536).default(1024).describe("Longer values are rejected without running the pattern, so backtracking can't be abused."),
    }),
  }),
  required_fields: defineTool({
    id: "required_fields",
    displayName: "Required fields",
    category: "schema",
    contextType: "full",
    description: "Rejects JSON bodies missing a required top-level property (null and blank strings count as missing).",
    config: z.strictObject({
      fields: names().min(1),
    }),
  }),
  string_length: defineTool({
    id: "string_length",
    displayName: "String length",
    category: "schema",
    contextType: "field",
    description: "Rejects string fields whose length does not satisfy a comparison (length < N, length > N, length <= N or length >= N).",
    config: z.union([
      z.strictObject({
        operator: z.enum(STRING_LENGTH_OPERATORS).describe("How the value's length must compare to `length`: \"<=\" with 64 allows at most 64 characters."),
        length: z.number().int().min(0).max(1_000_000),
      }),
      // tessera.tools/v1 form, still accepted so bundles from v1 dashboards keep working
      z.strictObject({
        minLength: z.number().int().min(0).max(1_000_000).optional(),
        maxLength: z.number().int().min(0).max(1_000_000).optional(),
      }).refine((value) => value.minLength !== undefined || value.maxLength !== undefined, "set minLength, maxLength or both")
        .refine((value) => value.minLength === undefined || value.maxLength === undefined || value.minLength <= value.maxLength, "minLength must not exceed maxLength")
        .describe("Deprecated (tessera.tools/v1): inclusive bounds, the same as >= minLength and <= maxLength."),
    ]),
  }),
  type_coercion: defineTool({
    id: "type_coercion",
    displayName: "Type coercion",
    category: "schema",
    contextType: "field",
    description: "Flags typed-body values sent as another type (\"true\" for true, \"1\" for 1) that backends coerce silently.",
    config: z.strictObject({
      expectedType: z.enum(["boolean", "number", "integer", "string"]),
      textLocations: textLocations(),
    }),
  }),
  zod_type_check: defineTool({
    id: "zod_type_check",
    displayName: "Type check (Zod)",
    category: "schema",
    contextType: "field",
    description: "Rejects field values that are not of the declared type; text-only locations may carry numbers and booleans as text.",
    config: z.strictObject({
      type: z.enum(["string", "integer", "number", "boolean", "array", "object", "null"]).optional().describe("The declared type; omitted, the field's own declared type is used."),
      textLocations: textLocations(),
    }),
  }),
} as const;
