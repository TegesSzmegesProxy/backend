# Proxy tool registry inventory

`tessera.tools/v1` executes only `string_length`. Its signed configuration
contains `minLength` and/or `maxLength`; both are inclusive limits for a
`body.*` or `query.*` field. The dashboard compiler and proxy verifier reject
unknown tool IDs and incomplete bounds. Changing executable capabilities
requires a new registry version on both sides.

Other prototype tools exist in the proxy source, but no dashboard contract
compiles them and they are not eligible for a signed execution plan:

| Tool | Current policy-sensitive constants or input | Required configuration before activation |
| --- | --- | --- |
| `integer_range` | minimum 0, maximum 100 | inclusive numeric bounds |
| `file_size` | 5 MiB | maximum bytes |
| `request_size` | 1 MiB | maximum bytes and definition of counted bytes |
| `rate_limit` | 100 requests per 60 seconds | limit, window, client key semantics |
| `archive_expansion_ratio` | ratio 100, 1 MiB floor, 1 GiB cap, 10,000 entries | ratio and archive limits |
| `mime_type` | allowed MIME types and signatures | allowed types and signature policy |
| `json_schema` | constructor-supplied schema | versioned JSON Schema and validation limits |
| `url_validator` | 2,048 characters, HTTP(S) | URL length and scheme allowlist |
| `sequence_analysis`, `duplicate_request` | time windows and count thresholds | windows, counts, grouping |
| `profanity_filter` | term list, 5,000 words | term list and scan limit |

Injection and anomaly checks also contain fixed detection rules and traversal
limits. Those rules need a deliberate versioned registry contract if the
dashboard is to enable or tune them. Until then they remain outside the
executable registry. The current signed bundle cannot activate them by name.
