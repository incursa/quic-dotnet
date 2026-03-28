# SpecTrace Prep

This note defines how `Incursa.Quic` will move from RFC text to traceable implementation work. It is repository guidance, not protocol design. The current repository is still scaffold-only, so this document establishes the working model before the first real QUIC requirements are authored.

## Canonical Homes

- Requirements live under [`../specs/requirements/quic`](../specs/requirements/quic).
- Requirement gaps live in [`../specs/requirements/quic/REQUIREMENT-GAPS.md`](../specs/requirements/quic/REQUIREMENT-GAPS.md).
- Architecture and design artifacts live under [`../specs/architecture/quic`](../specs/architecture/quic).
- Work items live under [`../specs/work-items/quic`](../specs/work-items/quic).
- Verification artifacts live under [`../specs/verification/quic`](../specs/verification/quic).
- Derived navigation and matrices belong under [`../specs/generated`](../specs/generated).
- Permanent benchmark suites belong under [`../benchmarks`](../benchmarks).
- Repo-level testing intent lives in [`../quality/testing-intent.yaml`](../quality/testing-intent.yaml).

## Order Of Operations

1. Start from the relevant RFC section or protocol concern.
2. Check for an existing owning `SPEC-...` file and any open gap in [`REQUIREMENT-GAPS.md`](../specs/requirements/quic/REQUIREMENT-GAPS.md).
3. If the behavior is missing, ambiguous, or under-specified, record the gap before implementation work begins.
4. Write or revise canonical requirements in `specs/requirements/quic`.
5. Add architecture notes when the satisfaction path, invariants, or tradeoffs need explanation.
6. Add or update the linked work item only after the requirement text is stable enough to trace.
7. Write the verification artifact early enough that the proof burden is explicit before coding starts.
8. Implement.
9. Record evidence and outcome in the verification artifact, then close or narrow any remaining gaps.

## Proof Burden

This codebase is low-level infrastructure. Passing happy-path tests is necessary and insufficient.

- Positive tests are required.
- Negative tests are required for malformed inputs, boundary conditions, reserved values, unsupported values, and rejected state transitions.
- Fuzzing is required for wire-facing parsing, serialization, encoding, decoding, and any surface that transforms attacker-controlled bytes.
- Benchmarks are required for processing and serialization hot paths. Benchmark evidence should be kept with permanent suites under [`../benchmarks`](../benchmarks) and linked from verification artifacts.
- Coverage percentage is advisory. It does not replace traceability, adversarial tests, fuzz evidence, or performance evidence.

## Workbench Alignment

The repository now carries [`.workbench/config.json`](../.workbench/config.json) so the local `workbench` tool resolves canonical paths consistently.

Useful commands:

```bash
dotnet tool restore
dotnet tool run workbench -- config show --format json
dotnet tool run workbench -- doctor --json
```

Use the templates under [`../specs/templates`](../specs/templates) when the first requirement, architecture, work-item, or verification artifacts are created.

## Current Scope

The first QUIC requirement slice now exists under [`../specs/requirements/quic/SPEC-QUIC-HDR.md`](../specs/requirements/quic/SPEC-QUIC-HDR.md) with a planned verification artifact under [`../specs/verification/quic/VER-QUIC-HDR-0001.md`](../specs/verification/quic/VER-QUIC-HDR-0001.md).

Future RFC slices should follow the same order of operations: translate the RFC into canonical requirements and gap records first, then add design, work-item, verification, and implementation details after the requirement text is stable.
