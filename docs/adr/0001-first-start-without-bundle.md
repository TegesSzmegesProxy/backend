# 0001: First startup requires a verified bundle

## Status

Accepted, 2026-10-04.

## Context

Before its first successful pull, a proxy has neither tenant failure settings
nor a local last known good bundle. The dashboard may be unavailable during
deployment, and an unsigned local policy cannot be trusted.

## Decision

The proxy does not open its ingress port until it has verified a signed bundle
from the dashboard or a verified last known good copy. If neither is available,
startup exits with an error. Once a bundle is loaded, dashboard outages do not
interrupt request enforcement.

## Consequences

First deployment requires a reachable dashboard and an activated compatible
bundle. An outage during first deployment delays service startup. An existing
deployment can restart from its verified local copy.
