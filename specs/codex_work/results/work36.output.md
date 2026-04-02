Wrote the review artifact at [specs/codex_work/quic.review.md](/C:/src/incursa/quic-dotnet/specs/codex_work/quic.review.md).

What it covers:
- Requirement/test inventory for `RFC 8999`, `RFC 9000`, `RFC 9001`, and `RFC 9002`
- Workbench validation caveat
- Missing `x_test_refs` and other traceability gaps
- Missing fuzz/property coverage, especially for `RFC 9002`
- Tests that are too broad to count as strong single-point proof
- Benchmark coverage that exists but does not substitute for conformance proof

Main takeaways:
- `RFC 8999` looks complete.
- `RFC 9000` still has the biggest trace/proof gap, though some uncovered chunks are intentionally blocked in `REQUIREMENT-GAPS.md`.
- `RFC 9001` has a small but real spec/test trace mismatch around the CRYPTO-frame requirements.
- `RFC 9002` has useful coverage, but it still needs direct requirement refs plus fuzz/property-style proof for the state-machine and boundary-heavy paths.

Commit:
- `f0cd8f8` - `Add QUIC requirement review`

I left the unrelated existing local changes alone.
