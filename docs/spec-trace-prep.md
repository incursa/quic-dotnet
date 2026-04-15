# SpecTrace Prep

This note defines how `Incursa.Quic` moves from RFC text to traceable implementation work. It is repository guidance, not protocol design.

## Canonical Homes

- Requirements: [`../specs/requirements/quic/README.md`](../specs/requirements/quic/README.md)
- Requirement gaps: [`../specs/requirements/quic/REQUIREMENT-GAPS.md`](../specs/requirements/quic/REQUIREMENT-GAPS.md)
- Architecture: [`../specs/architecture/quic/README.md`](../specs/architecture/quic/README.md)
- Work items: [`../specs/work-items/quic/README.md`](../specs/work-items/quic/README.md)
- Verification: [`../specs/verification/quic/README.md`](../specs/verification/quic/README.md)
- Generated outputs: [`../specs/generated/README.md`](../specs/generated/README.md)
- SpecTrace schemas: [`../specs/schemas/README.md`](../specs/schemas/README.md)
- Benchmarks: [`../benchmarks/README.md`](../benchmarks/README.md)
- Testing intent: [`../quality/testing-intent.yaml`](../quality/testing-intent.yaml)

For canonical SpecTrace families, author the sibling `.json` file and keep workflow references pointed at the canonical JSON path.

## Order Of Operations

1. Start from the relevant RFC section or protocol concern.
2. Check for an owning `SPEC-...` file and any open gap in [`REQUIREMENT-GAPS.md`](../specs/requirements/quic/REQUIREMENT-GAPS.md).
3. If the behavior is missing, ambiguous, or under-specified, record the gap before implementation.
4. Write or revise canonical requirements in `specs/requirements/quic`.
5. Add architecture notes when the satisfaction path, invariants, or tradeoffs need explanation.
6. Add or update the linked work item after the requirement text is stable enough to trace.
7. Write the verification artifact early enough that the proof burden is explicit before coding starts.
8. Implement.
9. Record evidence and outcome in verification, then close or narrow any remaining gaps.

## Proof Burden

- Positive tests are required.
- Negative tests are required for malformed inputs, boundary conditions, reserved values, unsupported values, and rejected state transitions.
- Fuzzing is required for wire-facing parsing, serialization, encoding, decoding, and any surface that transforms attacker-controlled bytes.
- Benchmarks are required for processing and serialization hot paths.
- Coverage percentage is advisory and does not replace traceability, adversarial tests, fuzz evidence, or performance evidence.

## Workbench Alignment

Useful commands:

```bash
dotnet tool restore
pwsh -NoProfile -File scripts/Validate-SpecTraceJson.ps1 -Profiles core
dotnet tool run workbench -- config show --format json
dotnet tool run workbench -- --format json validate --profile core
dotnet tool run workbench -- doctor --json
```

`Validate-SpecTraceJson.ps1` pulls the canonical model schema from [incursa/spec-trace](https://github.com/incursa/spec-trace/raw/refs/heads/main/model/model.schema.json) so the repository does not need to mirror that file locally.
