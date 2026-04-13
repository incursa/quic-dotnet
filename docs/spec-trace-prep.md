# SpecTrace Prep

This note defines how `Incursa.Quic` will move from RFC text to traceable implementation work. It is repository guidance, not protocol design. The repository now has live QUIC helper code and generated trace artifacts, so this document describes the working model that still applies as the remaining slices are traced and implemented.

## Canonical Homes

- Requirements live under [`../specs/requirements/quic/README.md`](../specs/requirements/quic/README.md).
- Requirement gaps live in [`../specs/requirements/quic/REQUIREMENT-GAPS.md`](../specs/requirements/quic/REQUIREMENT-GAPS.md).
- Architecture and design artifacts live under [`../specs/architecture/quic/README.md`](../specs/architecture/quic/README.md).
- Work items live under [`../specs/work-items/quic/README.md`](../specs/work-items/quic/README.md).
- Verification artifacts live under [`../specs/verification/quic/README.md`](../specs/verification/quic/README.md).
- Derived navigation and matrices belong under [`../specs/generated/README.md`](../specs/generated/README.md).
- SpecTrace schemas live under [`../specs/schemas/README.md`](../specs/schemas/README.md).
- Permanent benchmark suites belong under [`../benchmarks/README.md`](../benchmarks/README.md).
- Repo-level testing intent lives in [`../quality/testing-intent.yaml`](../quality/testing-intent.yaml).

For canonical SpecTrace families, author the sibling `.json` file and keep
workflow references pointed at the canonical JSON path.

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
pwsh -NoProfile -File scripts/Validate-SpecTraceJson.ps1 -Profiles core
dotnet tool run workbench -- config show --format json
dotnet tool run workbench -- --format json validate --profile core
dotnet tool run workbench -- doctor --json
```

`Validate-SpecTraceJson.ps1` pulls the canonical model schema from [incursa/spec-trace](https://github.com/incursa/spec-trace/raw/refs/heads/main/model/model.schema.json) so this repository does not have to mirror that file locally.

Use the templates under [`../specs/templates/README.md`](../specs/templates/README.md) when the first requirement, architecture, work-item, or verification artifacts are created.
