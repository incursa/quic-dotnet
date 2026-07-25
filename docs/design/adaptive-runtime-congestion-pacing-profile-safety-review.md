---
title: "Adaptive Runtime Congestion and Pacing Profile Safety Review"
---

# Adaptive Runtime Congestion and Pacing Profile Safety Review

Status: implementation seam reviewed; measurement and activation frozen

## Scope

`congestion_pacing_profile` is a separate Stage 5 protocol-sensitive
architecture. It exposes only two implementations already present in the
runtime:

- `legacy_current`: the retained NewReno congestion controller and existing
  pacing behavior;
- `cubic`: the existing private CUBIC congestion controller with the same
  pacing, recovery, packet, and ownership framework.

This package does not add a congestion algorithm, pacing algorithm, online
model, adaptive threshold, or production rule. CUBIC is a research candidate,
not a conservative or accepted profile. A duplicate conservative name mapping
to NewReno was rejected because it would create a false behavior distinction.

## Decision and state boundary

The runtime evaluates the closed value once during connection construction.
The selected controller is connection-local and immutable for the connection
lifetime. The connection start is therefore the policy decision boundary and
the connection lifetime is the latch lifetime.

Existing path validation and migration logic resets RTT, ECN, pending
reservation, and congestion state for a new path. It reinitializes the same
selected controller and does not re-evaluate the profile. This reconciles the
connection-start policy boundary with the existing per-path recovery-state
boundary.

## Authoritative safety

Forced mode bypasses selection only. It cannot bypass:

- congestion-window, slow-start-threshold, bytes-in-flight, and minimum-window
  invariants;
- pacing, recovery, loss, PTO, persistent-congestion, and ECN handling;
- anti-amplification, address validation, path validation, and migration;
- flow control, stream limits, packet size and protection, queue and buffer
  limits;
- packet and buffer ownership, partial-send handling, cancellation, disposal,
  terminal close, and shutdown;
- connection-local state isolation and exact path-state reset.

Missing, stale, saturated, contradictory, invalid, out-of-domain, or lifecycle
input applies the safety override and constructs NewReno even when CUBIC was
forced. An evidence sink is diagnostic-only and exceptions from it cannot
change construction.

## Shadow and activation posture

Disabled and observe-only modes apply `legacy_current`. Shadow mode is
research-only and recommends `legacy_current`; it deliberately contains no
candidate-selection rule. This allows schema, replay, and provenance
verification without implying safety or performance acceptance.

`active_internal` and production selection remain unavailable. Any later
request to recommend or activate CUBIC requires reviewed network-safety
evidence across loss, ECN, PTO, migration, reference-flow fairness, peers,
hosts, architectures, and workload-family holdouts.

## Review disposition

The force seam is safe to retain for deterministic correctness testing and
future one-axis campaigns. It is not evidence that CUBIC is safe or beneficial
for production. Performance measurement remains frozen.
