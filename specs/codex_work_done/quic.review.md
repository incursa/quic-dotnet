# QUIC Requirement Review

Scope: `SPEC-QUIC-RFC8999.json`, `SPEC-QUIC-RFC9000.json`, `SPEC-QUIC-RFC9001.json`, and `SPEC-QUIC-RFC9002.json`.

## Method

- I reviewed the canonical requirement JSON for each RFC.
- I ran the repo-local workbench validation flow and used it as a quality signal.
- I cross-checked the requirement set against the test sources in `tests/Incursa.Quic.Tests` by scanning for `[Requirement("REQ-...")]` and `Trait("Category", ...)` metadata.
- I reviewed the permanent benchmark suites under `benchmarks/` and the benchmark README.
- I treated the source scan as authoritative for this review because the current workbench inventory undercounts custom requirement metadata.

## Validation Note

The workbench validation run did not complete cleanly, but the failure was not caused by QUIC requirement content in these four specs. The reported problems were pre-existing broken links in `specs/codex_work/results/work23.output.md` and a generated chunk summary JSON under `specs/generated/quic/chunks/`.

That means this review should be read as a requirement/test inventory, not as a clean end-to-end repository validation report.

## Executive Summary

- `RFC 8999` is effectively complete from a trace perspective. I did not find remaining requirement/test gaps in the reviewed surface.
- `RFC 9000` has the largest open surface. A large portion of the canonical requirement set still lacks explicit test refs in the spec, and some areas are intentionally blocked by missing transport architecture.
- `RFC 9001` is partially covered, but the canonical trace metadata is behind the test implementation in the CRYPTO-frame area.
- `RFC 9002` has useful state-machine coverage, but it is still missing a lot of requirement-level traceability and it has no fuzz/property coverage in the parsed test surface.

## Summary Table

| Spec | Total requirements | Requirements covered by parsed tests | Requirements with tests but no `x_test_refs` | Requirements with no `x_test_refs` | Notes |
| --- | ---: | ---: | ---: | ---: | --- |
| RFC 8999 | 8 | 8 | 0 | 0 | Cleanest slice. Positive, negative, and fuzz coverage are all present in the test source. |
| RFC 9000 | 1443 | 479 | 223 | 1187 | Large trace gap. Some uncovered areas are intentionally blocked by `REQUIREMENT-GAPS.md`, but the canonical spec still does not separate blocked vs. unblocked requirements cleanly. |
| RFC 9001 | 61 | 16 | 15 | 58 | Mostly positive coverage with some negative and fuzz tests. Two CRYPTO-frame requirements appear in the spec with xrefs but no parsed test refs. |
| RFC 9002 | 224 | 102 | 102 | 224 | Strong helper coverage, but no parsed fuzz/property coverage. Broad tests carry many requirements at once. |

## Findings

### 1. High: Canonical trace metadata is missing at scale

The biggest issue is not just implementation coverage. It is the lack of stable, requirement-level trace metadata in the canonical spec files.

- `RFC 9000` has 223 requirements that are covered by test source but do not have `x_test_refs` in the canonical spec.
- `RFC 9001` has 15 requirements covered by test source but still missing `x_test_refs`.
- `RFC 9002` has 102 requirements covered by test source but still missing `x_test_refs`.

For `RFC 9000`, some of the uncovered work is intentional and already called out in `specs/requirements/quic/REQUIREMENT-GAPS.md`:

- `9000-19-retransmission-and-frame-reliability`
- `9000-02-stream-state`
- `9000-03-flow-control`
- `9000-11-migration-core`
- `9000-13-idle-and-close`
- `9000-14-stateless-reset`
- `9001-02-security-and-registry`

That is the right place for architectural deferrals, but the current spec surfaces still do not make it easy to tell intentional deferral from accidental omission.

### 2. High: `RFC 9002` does not have fuzz or property coverage in the parsed test surface

For the reviewed test sources, `RFC 9002` is covered only by positive and negative tests.

That is not enough for the kind of boundary-heavy state transitions involved in:

- ACK generation
- ACK delay handling
- loss detection
- RTT sampling and clamping
- congestion window updates
- ECN-driven recovery
- persistent congestion detection

The repo guidance requires fuzzing for boundary-heavy state transitions. This means `RFC 9002` needs a stronger proof plan than it currently has.

### 3. Medium: Several tests are too broad to be strong single-point proof

Some tests are useful integration-style proof, but they carry too many requirements to be the only evidence for a requirement set.

Representative examples:

- `QuicCongestionControlStateTests.TryRegisterLossAndProcessEcn_EnterRecoveryOnlyForEligibleSignals` covers 16 requirements.
- `QuicAckGenerationStateTests.TryBuildAckFrame_RoundsTripProcessedPacketsAndReportsAckDelay` is one of the broadest ACK/recovery proofs.
- `QuicVersionNegotiationTests.TryFormatVersionNegotiationResponse_FormatsEchoedConnectionIdsAndSupportedVersions` spans a large chunk of version-negotiation behavior.
- `QuicFrameCodecPart3Tests.TryParseCryptoFrame_ParsesAndFormatsAllFields` proves several frame codec requirements at once.

These are not bad tests. They just should not be the only proof for their requirement clusters.

### 4. Medium: `RFC 9001` has spec-level xref holes in the CRYPTO-frame area

Two `RFC 9001` requirements show up in the spec with xrefs but did not map to parsed tests in the source scan:

- `REQ-QUIC-RFC9001-S4-0001` - Carry handshake data in CRYPTO frames
- `REQ-QUIC-RFC9001-S4-0002` - Define CRYPTO frame boundaries

This looks like a traceability mismatch, not necessarily a missing implementation. The implementation exists in the frame codec area, but the canonical spec should point at the proof directly.

### 5. Medium: Benchmark coverage exists, but it is not requirement proof

The repo already has benchmark suites for the hot paths that matter here:

- `benchmarks/QuicCongestionControlBenchmarks.cs`
- `benchmarks/QuicRttEstimatorBenchmarks.cs`
- `benchmarks/QuicFrameCodecBenchmarks.cs`
- `benchmarks/QuicTransportParametersBenchmarks.cs`

That is good, but benchmarks are performance evidence, not conformance evidence. They should be treated as supplemental proof only, not as a substitute for requirement-linked tests.

### 6. Low: The current workbench inventory undercounts tests because of custom requirement metadata

The repository uses a custom requirement attribute and a custom trait discoverer in `tests/Incursa.Quic.Tests`.

That means a source scan or workbench sync can miss valid requirement/test links if it does not understand the repo's custom metadata pattern. The review had to go to source to get a reliable count.

## Spec-by-Spec Review

### RFC 8999

Status: clean.

- All 8 requirements were covered by parsed tests.
- I did not find any open requirement-level gaps in this spec.
- Coverage quality is strong: the test source includes positive, negative, and fuzz coverage.
- The main risk is only trace maintenance, not missing behavior.

Representative high-fanout requirement:

- `REQ-QUIC-RFC8999-S5P1-0006` has 10 tests and is covered by positive, negative, and fuzz cases.

### RFC 9000

Status: large partial coverage with intentional deferrals.

- 1443 total requirements.
- 479 requirements have parsed test coverage.
- 964 requirements still have no parsed test coverage.
- 223 requirements have parsed tests but are still missing `x_test_refs` in the canonical spec.
- 1187 requirements have no `x_test_refs` at all.

What looks good:

- Frame codec and transport-parameter areas have strong positive, negative, and fuzz coverage.
- Version negotiation and stateless-reset helper paths have meaningful test depth.

What still needs work:

- Canonical requirement refs need to be filled in far more completely.
- The spec should distinguish intentional architectural deferrals from accidental omissions more clearly.
- Several requirement clusters still depend on the missing stream-state, flow-control, migration, close, and retransmission architecture called out in `REQUIREMENT-GAPS.md`.

Representative broad tests:

- `QuicFrameCodecTests.IsAckElicitingFrameType_ClassifiesKnownFrameTypes`
- `QuicFrameCodecPart3Tests.TryParseCryptoFrame_ParsesAndFormatsAllFields`
- `QuicTransportParametersTests`

### RFC 9001

Status: partial coverage with a small number of concrete trace mismatches.

- 61 total requirements.
- 16 requirements have parsed test coverage.
- 45 requirements remain uncovered by the parsed test surface.
- 15 requirements have tests in source but no `x_test_refs`.
- 2 requirements have xrefs in the spec but did not map to parsed tests.

What looks good:

- Positive coverage exists for the packet-protection and transport-parameter helpers.
- There is some negative and fuzz coverage.

What still needs work:

- CRYPTO-frame requirements need canonical xrefs that point directly at the implemented proof.
- A few security-related clauses are still only positively exercised.
- The current coverage is too small to say the whole spec is proven.

Representative gaps:

- `REQ-QUIC-RFC9001-S4-0001`
- `REQ-QUIC-RFC9001-S4-0002`

### RFC 9002

Status: useful implementation coverage, but weak proof depth.

- 224 total requirements.
- 102 requirements have parsed test coverage.
- 122 requirements remain uncovered by the parsed test surface.
- 102 requirements have tests in source but no `x_test_refs`.
- No parsed requirement was tagged with fuzz or property coverage.

What looks good:

- ACK generation, RTT estimation, loss detection, and congestion-state helpers all have real tests.
- Several of the state-machine helpers are covered from both positive and negative angles.

What still needs work:

- Add fuzz coverage for boundary-heavy state transitions.
- Break out some of the broad state-machine tests so the proof is not concentrated in a few very large methods.
- Add direct requirement refs in the spec for the already-implemented areas.

Representative broad tests:

- `QuicCongestionControlStateTests.TryRegisterLossAndProcessEcn_EnterRecoveryOnlyForEligibleSignals`
- `QuicAckGenerationStateTests.TryBuildAckFrame_RoundsTripProcessedPacketsAndReportsAckDelay`
- `QuicRttEstimatorTests.TryUpdateFromAck_UsesTheLargestNewlyAcknowledgedAckElicitingPacketAsTheFirstSample`
- `QuicRecoveryTimingTests.ShouldDeclarePacketLostByPacketThreshold_UsesTheRecommendedThresholdOfThree`

## What Still Needs More Work

- Repair canonical `x_test_refs` on the specs, especially for `RFC 9000`, `RFC 9001`, and `RFC 9002`.
- Add fuzz tests where the repo guidance expects them, especially for `RFC 9002` state transitions and any remaining wire-facing parsing or encoding paths.
- Add at least some negative tests for currently positive-only proof clusters.
- Split the broadest tests or supplement them with narrower tests so each requirement cluster has a more focused proof path.
- Keep using `REQUIREMENT-GAPS.md` for intentional deferrals, but make sure the owning `SPEC-...` files and verification artifacts clearly separate blocked requirements from completed ones.

## Bottom Line

`RFC 8999` looks done.

`RFC 9001` is close enough to be trace-clean with a small amount of metadata repair, but it is not fully proven yet.

`RFC 9000` and `RFC 9002` still need substantial trace and proof work before they can be called complete. The implementation exists for many of those requirements, but the current tests do not yet prove them at the granularity the repo asks for.
