# Phase 01 — Foundation — Wire Format and Packet/Frame Substrate

Start here. RFC 8999 invariants are already complete, so this phase begins with the remaining transport substrate and frame/header work that other phases depend on.

Code roots used in generated prompts:
- .\src

Test roots used in generated prompts:
- .\tests

## Chunk Order

- $(@{ChunkId=8999-01-invariants; Rfc=8999; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC8999.md; SectionTokens=System.String[]; Mode=SKIP; Reason=Already implemented, tested, fuzzed, benchmarked, and closed out.; Confidence=high}.ChunkId) — mode $(@{ChunkId=8999-01-invariants; Rfc=8999; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC8999.md; SectionTokens=System.String[]; Mode=SKIP; Reason=Already implemented, tested, fuzzed, benchmarked, and closed out.; Confidence=high}.Mode) — Already implemented, tested, fuzzed, benchmarked, and closed out.
- $(@{ChunkId=9000-21-long-header-general-and-initial; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.md; SectionTokens=System.String[]; Mode=P2P3P4; Reason=Packet-header wire format and varint-related work already exists and carries stale VINT IDs.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-21-long-header-general-and-initial; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.md; SectionTokens=System.String[]; Mode=P2P3P4; Reason=Packet-header wire format and varint-related work already exists and carries stale VINT IDs.; Confidence=high}.Mode) — Packet-header wire format and varint-related work already exists and carries stale VINT IDs.
- $(@{ChunkId=9000-22-long-header-handshake-and-0rtt; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.md; SectionTokens=System.String[]; Mode=P2P3P4; Reason=Version Negotiation and Initial packet header parsing already exist; Handshake/0-RTT packet semantics remain to be filled in.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-22-long-header-handshake-and-0rtt; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.md; SectionTokens=System.String[]; Mode=P2P3P4; Reason=Version Negotiation and Initial packet header parsing already exist; Handshake/0-RTT packet semantics remain to be filled in.; Confidence=high}.Mode) — Version Negotiation and Initial packet header parsing already exist; Handshake/0-RTT packet semantics remain to be filled in.
- $(@{ChunkId=9000-23-retry-version-short-header; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.md; SectionTokens=System.String[]; Mode=P2P3P4; Reason=Short-header and long-header envelope parsing exist, but Retry and remaining packet semantics are still incomplete.; Confidence=medium}.ChunkId) — mode $(@{ChunkId=9000-23-retry-version-short-header; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.md; SectionTokens=System.String[]; Mode=P2P3P4; Reason=Short-header and long-header envelope parsing exist, but Retry and remaining packet semantics are still incomplete.; Confidence=medium}.Mode) — Short-header and long-header envelope parsing exist, but Retry and remaining packet semantics are still incomplete.
- $(@{ChunkId=9000-24-frame-encodings-part-1; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.md; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield transport-parameter, PADDING, PING, and ACK frame work.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-24-frame-encodings-part-1; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.md; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield transport-parameter, PADDING, PING, and ACK frame work.; Confidence=high}.Mode) — Greenfield transport-parameter, PADDING, PING, and ACK frame work.
- $(@{ChunkId=9000-25-frame-encodings-part-2; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.md; SectionTokens=System.String[]; Mode=P2P3P4; Reason=This slice includes existing STREAM-frame parsing/tests and stale STRM IDs alongside greenfield frame encoding work.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-25-frame-encodings-part-2; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.md; SectionTokens=System.String[]; Mode=P2P3P4; Reason=This slice includes existing STREAM-frame parsing/tests and stale STRM IDs alongside greenfield frame encoding work.; Confidence=high}.Mode) — This slice includes existing STREAM-frame parsing/tests and stale STRM IDs alongside greenfield frame encoding work.
- $(@{ChunkId=9000-26-frame-encodings-part-3; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.md; SectionTokens=System.String[]; Mode=P2P3P4; Reason=This slice still overlaps existing STREAM-frame parsing/tests before moving into greenfield frame families.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-26-frame-encodings-part-3; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.md; SectionTokens=System.String[]; Mode=P2P3P4; Reason=This slice still overlaps existing STREAM-frame parsing/tests before moving into greenfield frame families.; Confidence=high}.Mode) — This slice still overlaps existing STREAM-frame parsing/tests before moving into greenfield frame families.
- $(@{ChunkId=9000-27-frame-encodings-part-4; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.md; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield frame-encoding work.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-27-frame-encodings-part-4; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.md; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield frame-encoding work.; Confidence=high}.Mode) — Greenfield frame-encoding work.

## 8999-01-invariants

- RFC: `8999`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC8999.md`
- Section tokens: `S5P1`
- Mode: `SKIP`
- Confidence: `high`
- Reason: Already implemented, tested, fuzzed, benchmarked, and closed out.

This chunk is already complete and is included here only to preserve phase order.

## 9000-21-long-header-general-and-initial

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.md`
- Section tokens: `S17, S17P1, S17P2`
- Mode: `P2P3P4`
- Confidence: `high`
- Reason: Packet-header wire format and varint-related work already exists and carries stale VINT IDs.

### Prompt 2

```text

```

### Prompt 3

```text

```

### Prompt 4

```text

```

## 9000-22-long-header-handshake-and-0rtt

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.md`
- Section tokens: `S17P2P1, S17P2P2, S17P2P3`
- Mode: `P2P3P4`
- Confidence: `high`
- Reason: Version Negotiation and Initial packet header parsing already exist; Handshake/0-RTT packet semantics remain to be filled in.

### Prompt 2

```text

```

### Prompt 3

```text

```

### Prompt 4

```text

```

## 9000-23-retry-version-short-header

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.md`
- Section tokens: `S17P2P4, S17P2P5, S17P2P5P1, S17P2P5P2, S17P2P5P3, S17P3, S17P3P1, S17P4`
- Mode: `P2P3P4`
- Confidence: `medium`
- Reason: Short-header and long-header envelope parsing exist, but Retry and remaining packet semantics are still incomplete.

### Prompt 2

```text

```

### Prompt 3

```text

```

### Prompt 4

```text

```

## 9000-24-frame-encodings-part-1

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.md`
- Section tokens: `S18, S18P1, S18P2`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield transport-parameter, PADDING, PING, and ACK frame work.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

```text
```

### Prompt 4

```text
```

## 9000-25-frame-encodings-part-2

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.md`
- Section tokens: `S19P1, S19P2, S19P3, S19P3P1, S19P3P2, S19P4, S19P5`
- Mode: `P2P3P4`
- Confidence: `high`
- Reason: This slice includes existing STREAM-frame parsing/tests and stale STRM IDs alongside greenfield frame encoding work.

### Prompt 2

```text
```

### Prompt 3

```text
```

### Prompt 4

```text
```

## 9000-26-frame-encodings-part-3

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.md`
- Section tokens: `S19P6, S19P7, S19P8, S19P9, S19P10, S19P11`
- Mode: `P2P3P4`
- Confidence: `high`
- Reason: This slice still overlaps existing STREAM-frame parsing/tests before moving into greenfield frame families.

### Prompt 2

```text
```

### Prompt 3

```text
```

### Prompt 4

```text
```

## 9000-27-frame-encodings-part-4

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.md`
- Section tokens: `S19P12, S19P13, S19P14, S19P15, S19P16, S19P17, S19P18`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield frame-encoding work.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

```text
```

### Prompt 4

```text
```
