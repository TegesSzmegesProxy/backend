# Tessera Application Analysis

## Purpose

Control-plane analysis that converts an application and its environment into structured context for tenant-wide policy generation. Never runs in the request path and never directly blocks traffic.

## Flow

`Collector (client-side): Source -> Redaction -> Environment Context -> Upload` then `Control plane (hosted): AI Analysis -> Structured Application Model -> Policy`

The split exists because environment tools must see the client's network and secrets must be removed before anything leaves it, while the AI analysis and its keys live with us.

## Source

The collector accepts either `Git URL + commit` or a local project path, typically running in the client's CI. A source revision must be recorded for reproducibility and sent with the upload.

## Environment

Before upload, the collector gathers available environment context using security/inventory tools such as `Syft`, `Trivy` and `Nmap`, inside the client's environment. Tool choice may evolve. Results provide context; they do not directly make runtime decisions.

## AI analysis

An external AI model/API performs the application analysis. The implementation must remain provider-independent; examples include Fable- or ChatGPT-class models.
The model analyzes the application as a whole and is responsible for discovering its API surface, request methods, fields, validation behavior and security-relevant application logic.

## Analysis targets

At minimum discover:

* `HTTP method + path` endpoints;
* request fields and their relevant types/constraints;
* application-specific validation and expected behavior;
* dependencies and versions;
* relevant configuration;
* security-relevant application/environment assumptions;
* CVE/vulnerability information supplied by analysis tools.

## Dependencies

Identify dependency names and versions and correlate them with available vulnerability data. A CVE is context/evidence, not automatic proof that a request is malicious.

## Configuration

Analyze relevant configuration such as JSON, `.env` and framework/application config. Redaction happens in the collector, before upload: secrets and credentials never reach our control plane or the external model. Redact while preserving useful structure.

## Environment tools

Environment results may include software inventory, known vulnerabilities, exposed services, ports and network context. Keep tool output structured and attributable to its source.

## Incremental analysis

Analysis runs per application release. Initial analysis may inspect the full application. Later releases should prefer `previous analysis + Git diff + changed environment/dependencies/configuration` and recompute only affected information where practical.

## Output

Produce structured, versioned application context containing at least:
`source_revision, analysis_version, api_surface, dependencies, environment, configuration, cves, findings`
Findings should retain evidence/source so the policy agent can distinguish observed facts from inference.

## Policy handoff

The analysis model feeds the policy-generation process. Analysis describes the application; policy generation decides the security rules. Do not mix runtime enforcement logic into analysis.

## Security

Keep all analysis tenant-scoped. The collector authenticates with a collector key scoped to its tenants, and the control plane derives the tenant from that key. Upload only what analysis needs, and make the uploaded scope visible to the customer. Do not expose secrets, credentials or unnecessary sensitive data to our control plane or external AI APIs. Preserve source revision and analysis version for traceability.

## Invariants

Analysis never forwards, modifies or blocks requests. Analysis is reproducible from its source revision and collected context. The runtime proxy must not synchronously depend on analysis or the control plane being available. Unredacted secrets never leave the client environment.

