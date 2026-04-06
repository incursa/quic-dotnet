# Requirements and Quality Workflow

This note captures the working order for RFC-derived QUIC work in `Incursa.Quic`. It is not normative and does not replace future requirement artifacts.

## Order Of Operations

1. Capture source material.
   - Record the RFC section, extracted behavior, open questions, and any interoperability or wire-format concern.
   - If a rule is unclear, add it to [`../specs/requirements/quic/REQUIREMENT-GAPS.md`](../specs/requirements/quic/REQUIREMENT-GAPS.md) before implementation.
2. Draft the smallest stable requirement slice.
   - Keep each spec narrow and grouped by stable technical concern.
   - Keep normative statements separate from notes, examples, and rationale.
3. Add architecture only after the requirement slice is stable enough to design against.
4. Add work items after the requirement and design shape are clear.
5. Add verification artifacts before implementation reaches review.
6. Implement code, tests, fuzzing, and benchmarks in the same slice when they affect the same behavior.
7. Revisit gaps whenever implementation uncovers new edge cases.

## Quality Expectations

- Positive tests prove the expected behavior on valid inputs.
- Negative tests cover malformed, truncated, out-of-range, unsupported, and forbidden inputs.
- Fuzz or property tests should target untrusted input paths, length handling, state machines, and any parser that accepts attacker-controlled bytes.
- Benchmarks should cover parsing, serialization, encoding, decoding, and other allocation-sensitive or throughput-sensitive code paths.
- Regression tests should be added for every bug found during implementation or fuzzing.

## Canonical Paths

- Requirements: [`../specs/requirements/quic/README.md`](../specs/requirements/quic/README.md)
- Architecture: [`../specs/architecture/quic/README.md`](../specs/architecture/quic/README.md)
- Work items: [`../specs/work-items/quic/README.md`](../specs/work-items/quic/README.md)
- Verification: [`../specs/verification/quic/README.md`](../specs/verification/quic/README.md)
- Generated outputs: [`../specs/generated/README.md`](../specs/generated/README.md)

Canonical artifacts in those families are authored as sibling `.json` files.
The repository does not keep sibling canonical `.md` companions for those families.

## Notes For QUIC Work

- For version-independent packet handling, version negotiation, connection ID handling, and related wire-format work, keep the requirement slices small and stable.
- Prefer traceable gaps over guesswork when RFC text leaves more than one plausible interpretation.
- The repository now has live helper code and generated trace artifacts; do not treat this note as a substitute for canonical requirements.
