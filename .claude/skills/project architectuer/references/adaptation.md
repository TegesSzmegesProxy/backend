# Tessera Adaptive Control

## Purpose

Controls runtime JEV sampling using observed attack behavior. Adaptive control reduces JEV cost while increasing analysis of suspicious endpoints.

## Flow

`Request -> Static Analysis -> Sampling(N) -> JEV -> Score + Confidence -> Decision`
`JEV ATTACK/BENIGN -> Attack Rate -> EWMA -> Controller -> N`

## Attack rate

Only JEV classifications contribute to attack-rate feedback. Static-analysis blocks are excluded because they represent policy violations/deterministic findings rather than confirmed JEV attacks.
Maintain attack-rate measurements for both tenant and endpoint. Endpoint behavior has greater influence on its own sampling than the tenant-wide rate.

## EWMA

Use EWMA to smooth attack-rate observations and avoid reacting to single requests. The smoothing factor `α` is global. Exact weighting between endpoint and tenant rates belongs to controller configuration/implementation.

## Sampling

`N` is the percentage/probability of eligible requests sent to JEV. `N` is configured per endpoint and dynamically adjusted by the controller.
The controller calculates a new `N` from the smoothed attack-rate signal rather than applying fixed increments.
Each endpoint has configurable `N_min` and `N_max`; the controller must remain within those bounds.

## Initial state

The initial sampling value is configured by the user. Code analysis may suggest an initial value after application analysis.

## Thresholds

The user configures:

* maliciousness score threshold;
* JEV confidence threshold.
  These thresholds may be locked so adaptive/runtime mechanisms cannot modify them. Their exact decision rule belongs to `contracts.md`.

If threshold is not locked, attack-rate can tighten it until it reaches a user defined T_floor. Blocking can only get stricter, never looser.

## Controller

The controller uses smoothed tenant/endpoint attack rates to calculate endpoint sampling. Higher endpoint attack rates should increase that endpoint's sampling more strongly than the tenant-wide baseline. Lower attack rates may reduce sampling toward the configured minimum.
The controller must never bypass static blocking or force an otherwise blocked request to JEV/ALLOW.

## Feedback

Every JEV result classified as `ATTACK` or `BENIGN` is eligible for attack-rate feedback. Unsampled requests do not affect sampling rate, but they do affect threshold.

## Invariants

`N` is adaptive; user security thresholds are not automatically changed. Static-analysis policy violations never enter attack-rate feedback. Sampling never overrides static blocking. `N` always remains within endpoint bounds. EWMA prevents one observation from directly determining sampling.

