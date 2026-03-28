# QUIC Requirement Gaps

Use this file to record missing, ambiguous, or blocked QUIC requirements before implementation starts.

## How To Use This File

1. Record the RFC or source reference.
2. State the ambiguity or missing behavior directly.
3. Name the impacted future `SPEC-...` file if it is known.
4. Keep the gap open until the canonical requirement text exists.

## Open Gaps

- None for this slice.

## Resolved Gaps

- Source: RFC 8999 short-header packet form
  Gap: RFC 8999 says a short-header packet carries a destination connection ID immediately after the first byte, but it does not encode the destination connection ID length, so a generic parser cannot infer a unique byte boundary without version-specific context.
  Needed decision: Decide whether the version-independent short-header model will preserve the post-first-byte bytes as an opaque remainder, require version-specific parsing hooks, or use another deterministic boundary rule.
  Affected spec slice: [`SPEC-QUIC-HDR`](./SPEC-QUIC-HDR.md)
  Resolution: Preserve the bytes after the first byte as an opaque remainder in `QuicShortHeaderPacket`; defer version-specific boundary handling to later parsing layers.
