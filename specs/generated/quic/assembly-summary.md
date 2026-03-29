# QUIC Assembly Summary

## Output Model

- Canonical RFC-level specs written under `./specs/requirements/quic/`.
- Per-RFC assembly maps written under `./specs/generated/quic/`.
- Combined overlap report written to `./specs/generated/quic/assembly-overlap-report.md`.

## Counts

### RFC 8999

- Draft requirements ingested: 8
- Final requirements emitted: 8
- Clear duplicates merged: 0
- Draft clauses split during canonicalization: 0
- Draft clauses rejected: 0
- Possible overlaps remaining for review: 3

### RFC 9000

- Draft requirements ingested: 1524
- Final requirements emitted: 1443
- Clear duplicates merged: 64
- Draft clauses split during canonicalization: 1
- Draft clauses rejected: 1
- Possible overlaps remaining for review: 75

### RFC 9001

- Draft requirements ingested: 61
- Final requirements emitted: 61
- Clear duplicates merged: 0
- Draft clauses split during canonicalization: 0
- Draft clauses rejected: 0
- Possible overlaps remaining for review: 15

### RFC 9002

- Draft requirements ingested: 224
- Final requirements emitted: 224
- Clear duplicates merged: 0
- Draft clauses split during canonicalization: 0
- Draft clauses rejected: 0
- Possible overlaps remaining for review: 10

## Core Validation

- Target: `./specs/requirements/quic`
- Profile: `core`
- Result: blocked by 1736 requirement-namespace errors.
- Non-blocking warnings under `core`: 1736 downstream-trace warnings and 1736 verification-coverage warnings, which are expected because this run did not create ARC/WI/VER artifacts.

## Blockers

- `REQ-NAMESPACE`: the repository validator requires a requirement namespace to exactly match the specification namespace. These assembled requirements intentionally use RFC-level specification IDs plus section-scoped requirement IDs such as `REQ-QUIC-RFC9000-S10-0001`, so the validator reports every requirement as misaligned.
- This blocker is in the current helper logic rather than in the assembled RFC content. The helper extracts `QUIC-RFC9000-S10` as the requirement namespace and compares it to the specification namespace `QUIC-RFC9000` without allowing the extra section grouping segment.
- The assembly kept the section token because the task explicitly required one section token in every final requirement ID.

## Notes

- Validation against `./specs/requirements` also surfaces preexisting failures in the repository’s own `spec-trace` specifications because the current validator only recognizes plain `## REQ-...` headings there as well.
- The QUIC spec files were normalized to plain `## REQ-...` headings so the remaining blocker is isolated to namespace matching rather than markdown section discovery.
