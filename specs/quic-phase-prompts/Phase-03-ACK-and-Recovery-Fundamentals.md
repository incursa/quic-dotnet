# Phase 03 — ACK and Recovery Fundamentals

Once the handshake path exists, add acknowledgment generation, retransmission rules, RTT estimation, and loss detection so the connection can make forward progress reliably.

Code roots used in generated prompts:
- ./src

Test roots used in generated prompts:
- ./tests

## Chunk Order

- $(@{ChunkId=9000-18-ack-generation; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield ACK-generation behavior.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-18-ack-generation; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield ACK-generation behavior.; Confidence=high}.Mode) — Greenfield ACK-generation behavior.
- $(@{ChunkId=9000-19-retransmission-and-frame-reliability; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield retransmission/frame-reliability work.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-19-retransmission-and-frame-reliability; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield retransmission/frame-reliability work.; Confidence=high}.Mode) — Greenfield retransmission/frame-reliability work.
- $(@{ChunkId=9002-01-transport-basics; Rfc=9002; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9002.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield ack-eliciting, packets-in-flight, and packet-number-space basics.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9002-01-transport-basics; Rfc=9002; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9002.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield ack-eliciting, packets-in-flight, and packet-number-space basics.; Confidence=high}.Mode) — Greenfield ack-eliciting, packets-in-flight, and packet-number-space basics.
- $(@{ChunkId=9002-02-rtt-estimation; Rfc=9002; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9002.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield RTT-estimation behavior.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9002-02-rtt-estimation; Rfc=9002; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9002.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield RTT-estimation behavior.; Confidence=high}.Mode) — Greenfield RTT-estimation behavior.
- $(@{ChunkId=9002-03-loss-detection; Rfc=9002; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9002.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield loss detection and PTO behavior.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9002-03-loss-detection; Rfc=9002; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9002.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield loss detection and PTO behavior.; Confidence=high}.Mode) — Greenfield loss detection and PTO behavior.

## 9000-18-ack-generation

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S13, S13P1, S13P2, S13P2P1, S13P2P2, S13P2P3, S13P2P4, S13P2P5, S13P2P6, S13P2P7`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield ACK-generation behavior.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

```text
```

### Prompt 4

```text
```

## 9000-19-retransmission-and-frame-reliability

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S13P3`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield retransmission/frame-reliability work.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

```text
```

### Prompt 4

```text
```

## 9002-01-transport-basics

- RFC: `9002`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9002.json`
- Section tokens: `S2, S3`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield ack-eliciting, packets-in-flight, and packet-number-space basics.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

```text
```

### Prompt 4

```text
```

## 9002-02-rtt-estimation

- RFC: `9002`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9002.json`
- Section tokens: `S5, S5P1, S5P2, S5P3`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield RTT-estimation behavior.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

```text
```

### Prompt 4

```text
```

## 9002-03-loss-detection

- RFC: `9002`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9002.json`
- Section tokens: `S6, S6P1, S6P1P1, S6P1P2, S6P2, S6P2P1, S6P2P2, S6P2P2P1, S6P2P3, S6P2P4, S6P3, S6P4`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield loss detection and PTO behavior.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

```text
```

### Prompt 4

```text
```
