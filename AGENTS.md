# Incursa.Quic Agent Instructions

This repository is the scaffold for the Incursa QUIC library. It currently contains build, test, packaging, and documentation structure only. Treat future protocol work as requirements-driven: capture the behavior first, then design, then verification, then code.

## Authority

Follow this order when working here:

1. [`specs/README.md`](specs/README.md) and [`specs/requirements/REQUIREMENT-GAPS.md`](specs/requirements/REQUIREMENT-GAPS.md) for future RFC-derived behavior and open questions
2. [`docs/requirements-workflow.md`](docs/requirements-workflow.md) for the local order of operations and quality expectations
3. root guidance such as [`README.md`](README.md), [`docs/README.md`](docs/README.md), [`docs/testing/README.md`](docs/testing/README.md), and [`CONTRIBUTING.md`](CONTRIBUTING.md)
4. this file and [`LLMS.txt`](LLMS.txt) as convenience surfaces

If two sources conflict, prefer the higher item in the list.

## Working Rules

- For any protocol behavior change, start from the source RFC and record unresolved questions in [`specs/requirements/REQUIREMENT-GAPS.md`](specs/requirements/REQUIREMENT-GAPS.md) before implementation work begins.
- Do not invent missing rules in work items, test names, implementation comments, or benchmark plans.
- Keep requirements, architecture, work items, verification, tests, and benchmarks as separate artifacts.
- Slice future protocol work by stable technical concern, not by release date or sprint.
- For parser, serializer, encoder, decoder, packet-processing, or frame-processing code, plan:
  - positive tests for valid inputs and expected transitions
  - negative tests for malformed, truncated, out-of-range, or forbidden inputs
  - fuzz or property tests for untrusted input paths and state transitions
  - benchmarks for hot paths and allocation-sensitive code
- Prefer relative links in repository Markdown.
- Preserve the scaffold until a requirement or verification artifact says otherwise.
