---
name: domain-modeling
description: Keeps the project's domain language in GLOSSARY.md and records rejected architecture decisions as ADRs in docs/adr/. Use when a new domain term appears, a fuzzy term needs sharpening, or a decision is rejected for a load-bearing reason.
---

# Domain Modeling

## Glossary (`GLOSSARY.md`, repo root)

- One term per concept. If two words mean the same thing, pick one and note the other as avoided.
- Add a term the moment it is named in a design. Create `GLOSSARY.md` lazily if missing.
- When a term is fuzzy in conversation, update its entry right there.

## ADRs (`docs/adr/`)

- Offer an ADR only when a future reviewer would otherwise re-suggest the rejected option for the same reason. Skip ephemeral reasons ("not worth it now").
- File name: `NNNN-short-title.md`, numbered in order.
- Content: Status, Context, Decision, Consequences.
