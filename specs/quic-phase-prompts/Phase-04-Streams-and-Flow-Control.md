# Phase 04 — Streams and Flow Control

With basic recovery in place, implement stream abstractions, stream state machines, and flow control.

Code roots used in generated prompts:
- ./src

Test roots used in generated prompts:
- ./tests

## Chunk Order

- $(@{ChunkId=9000-01-streams-core; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P2P3P4; Reason=Existing stream parser, stream-ID parser, and STREAM-frame tests already exist and carry stale STRM IDs.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-01-streams-core; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P2P3P4; Reason=Existing stream parser, stream-ID parser, and STREAM-frame tests already exist and carry stale STRM IDs.; Confidence=high}.Mode) — Existing stream parser, stream-ID parser, and STREAM-frame tests already exist and carry stale STRM IDs.
- $(@{ChunkId=9000-02-stream-state; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield stream state-machine work.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-02-stream-state; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield stream state-machine work.; Confidence=high}.Mode) — Greenfield stream state-machine work.
- $(@{ChunkId=9000-03-flow-control; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield stream and connection flow-control work.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-03-flow-control; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield stream and connection flow-control work.; Confidence=high}.Mode) — Greenfield stream and connection flow-control work.

## 9000-01-streams-core

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S2, S2P1, S2P2, S2P3, S2P4`
- Mode: `P2P3P4`
- Confidence: `high`
- Reason: Existing stream parser, stream-ID parser, and STREAM-frame tests already exist and carry stale STRM IDs.

### Prompt 2

```text
```

### Prompt 3

```text
```

### Prompt 4

```text
```

## 9000-02-stream-state

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S3, S3P1, S3P2, S3P3, S3P4, S3P5`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield stream state-machine work.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

```text
```

### Prompt 4

```text
```

## 9000-03-flow-control

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S4, S4P1, S4P2, S4P4, S4P5, S4P6`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield stream and connection flow-control work.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

```text
```

### Prompt 4

```text
```
