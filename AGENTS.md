# Incursa.Quic Agent Guidance

This repository is trace-first. Do not start protocol implementation from RFC prose alone when the canonical requirement or gap record does not exist yet.

## Required Order Of Operations

1. Check [`docs/requirements-workflow.md`](docs/requirements-workflow.md).
2. Check [`specs/requirements/quic/REQUIREMENT-GAPS.md`](specs/requirements/quic/REQUIREMENT-GAPS.md) and the nearest owning `SPEC-...` file.
3. If the requirement is missing or ambiguous, record or refine the gap before implementation.
4. Author or revise the canonical requirement in [`specs/requirements/quic`](specs/requirements/quic).
5. Create or update architecture, work-item, and verification artifacts in [`specs/architecture/quic`](specs/architecture/quic), [`specs/work-items/quic`](specs/work-items/quic), and [`specs/verification/quic`](specs/verification/quic) as needed.
6. Implement only after the requirement and proof plan are stable enough to trace.
7. Close the loop with verification evidence.

## Proof Burden

Every protocol slice MUST define how it will be proven before code review is considered complete.

- Positive tests are required.
- Negative tests are required.
- Fuzzing is required for wire-facing parsers, serializers, decoders, encoders, and boundary-heavy state transitions.
- Benchmarks are required for processing, parsing, encoding, decoding, and serialization hot paths. Keep permanent suites under [`benchmarks/README.md`](benchmarks/README.md).
- Verification artifacts in [`specs/verification/quic/README.md`](specs/verification/quic/README.md) must record the evidence used to prove the requirement set.

## Tooling Alignment

- Use the repo-local Workbench configuration in [`.workbench/config.json`](.workbench/config.json) for canonical artifact paths.
- Use the SpecTrace templates in [`specs/templates/README.md`](specs/templates/README.md) when creating new artifacts.
- Use the quality intent contract in [`quality/testing-intent.yaml`](quality/testing-intent.yaml) as the repo-level testing bar, but do not treat coverage percentages as a substitute for protocol correctness evidence.

## ProtocolLab Rack Lab

Use the ProtocolLab rack controller for clean lab execution of performance-sensitive changes when local developer-machine noise would make a result hard to trust.

- Start with [`docs/protocol-lab/rack-lab-controller.md`](docs/protocol-lab/rack-lab-controller.md).
- Controller endpoint: `http://10.10.99.176:5088`.
- Package local development builds as `.plabpkg` archives. The archive is ZIP-compatible and must contain a root `protocol-lab-package.json` manifest with `schemaVersion: protocol-lab-package-v2`.
- Prefer package-backed controller jobs over source-root launches. QUIC.NET should not require a full ProtocolLab checkout for ordinary lab execution; the long-term boundary is ProtocolLab harness contracts/tooling via NuGet or a small CLI plus controller package upload.
- The `quic-dotnet-dev` package target is HTTP/3 only. Do not broaden it for raw QUIC validation.
- Raw QUIC lab validation is supported only by the separate `quic-dotnet-raw-dev` package target. Its package manifest and implementation manifest must explicitly advertise `protocol: quic`, workload family `quic.transport`, the raw QUIC scenario IDs, and raw QUIC capabilities before requesting controller validation.
- Record the controller job ID, package ID/version/SHA-256, run ID, and outcome summary in the verification artifact for any performance claim.

## Guardrails

- Do not hide missing requirements inside work items, tests, or code comments.
- Do not treat a passing happy-path test as sufficient evidence for packet or frame handling.
- Do not merge new protocol behavior without a stable requirement ID and a linked verification plan.
