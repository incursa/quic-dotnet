# Testing Docs

This folder documents the testing strategy and generated inventory outputs for `Incursa.Quic`.

Testing is one part of the proof burden. Protocol work also requires traceability, fuzzing, and benchmark evidence for wire-facing and hot-path code.

## Tooling

- [`.config/dotnet-tools.json`](../../.config/dotnet-tools.json): repo-local tools.
- `dotnet-stryker`: mutation testing.
- `SharpFuzz.CommandLine`: fuzz harness instrumentation for wire-facing parsers and boundary code.
- [`../../tests/Incursa.Quic.Tests/stryker-config.json`](../../tests/Incursa.Quic.Tests/stryker-config.json): Stryker configuration.

Run `dotnet tool restore` before invoking repo-local tools.

## Quality Expectations

- Add positive and negative tests for each behavior slice.
- Add FsCheck-backed property coverage for byte-oriented parsers and boundary-heavy state transitions.
- Keep fuzz harnesses for wire-facing code under [`../../fuzz/README.md`](../../fuzz/README.md).
- Keep permanent benchmarks under [`../../benchmarks/README.md`](../../benchmarks/README.md).
- Record canonical proof outcomes under [`../../specs/verification/quic/README.md`](../../specs/verification/quic/README.md).

## Requirement Tagging

- Tag requirement-linked xUnit tests with `[Trait("Requirement", "REQ-...")]`.
- Add category markers such as `[CoverageType(RequirementCoverageType.Positive)]`, `[CoverageType(RequirementCoverageType.Negative)]`, `[Trait("Category", "Property")]`, or `[Trait("Category", "Fuzz")]` when they help downstream filtering or coverage checks.
