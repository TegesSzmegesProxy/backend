---
name: codebase-design
description: Shared architecture vocabulary (module, interface, depth, seam, adapter, leverage, locality) and principles for judging and proposing code structure. Use when reviewing architecture, proposing refactors, or designing module interfaces.
---

# Codebase Design

## Vocabulary

Use these terms exactly. Do not drift into "component," "service," "API," or "boundary."

- **Module**: anything with an interface and an implementation.
- **Interface**: everything a caller must know to use the module (types, invariants, errors, ordering).
- **Depth**: leverage per unit of interface. Deep = small interface, large implementation. Shallow = interface nearly as complex as the implementation.
- **Seam**: a place where behavior can change without editing the caller.
- **Adapter**: the concrete implementation placed at a seam.
- **Leverage**: how many callers benefit from one implementation.
- **Locality**: how much of a change or bug stays inside one module.

## Principles

- **Deletion test**: delete the module in your head. If complexity vanishes, it was shallow. If it reappears across callers, it was earning its place.
- **The interface is the test surface**: test through the interface, not around it.
- **One adapter = hypothetical seam. Two adapters = real seam.** Do not add a seam for a single implementation.
- **Design it twice**: when choosing an interface, sketch at least two alternatives before committing.
