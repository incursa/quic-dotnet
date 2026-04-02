# Phase 02 — Connection Establishment and Crypto Bootstrap

After the wire substrate is in place, build connection establishment, CID policy, version negotiation behavior, TLS carriage, transport parameters, and address/path validation.

Code roots used in generated prompts:
- ./src

Test roots used in generated prompts:
- ./tests

## Chunk Order

- $(@{ChunkId=9000-04-connection-ids-basics; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P2P3P4; Reason=Existing packet-classification and Version Negotiation parser/tests already exist, so CID basics should reconcile first.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-04-connection-ids-basics; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P2P3P4; Reason=Existing packet-classification and Version Negotiation parser/tests already exist, so CID basics should reconcile first.; Confidence=high}.Mode) — Existing packet-classification and Version Negotiation parser/tests already exist, so CID basics should reconcile first.
- $(@{ChunkId=9000-05-connection-id-management; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P2P3P4; Reason=Connection-ID management builds on existing packet parsing and CID-related logic.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-05-connection-id-management; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P2P3P4; Reason=Connection-ID management builds on existing packet parsing and CID-related logic.; Confidence=high}.Mode) — Connection-ID management builds on existing packet parsing and CID-related logic.
- $(@{ChunkId=9000-06-version-negotiation; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield Version Negotiation behavior layered on top of existing header parsing.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-06-version-negotiation; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield Version Negotiation behavior layered on top of existing header parsing.; Confidence=high}.Mode) — Greenfield Version Negotiation behavior layered on top of existing header parsing.
- $(@{ChunkId=9001-01-tls-core; Rfc=9001; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9001.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield QUIC TLS and packet-protection core.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9001-01-tls-core; Rfc=9001; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9001.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield QUIC TLS and packet-protection core.; Confidence=high}.Mode) — Greenfield QUIC TLS and packet-protection core.
- $(@{ChunkId=9000-07-handshake-properties; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield cryptographic handshake and connection-ID authentication semantics.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-07-handshake-properties; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield cryptographic handshake and connection-ID authentication semantics.; Confidence=high}.Mode) — Greenfield cryptographic handshake and connection-ID authentication semantics.
- $(@{ChunkId=9000-08-transport-params-and-crypto-buffers; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield transport-parameter and CRYPTO buffering behavior.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-08-transport-params-and-crypto-buffers; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield transport-parameter and CRYPTO buffering behavior.; Confidence=high}.Mode) — Greenfield transport-parameter and CRYPTO buffering behavior.
- $(@{ChunkId=9000-09-address-validation-and-tokens; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield address-validation token and amplification-limit behavior.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-09-address-validation-and-tokens; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield address-validation token and amplification-limit behavior.; Confidence=high}.Mode) — Greenfield address-validation token and amplification-limit behavior.
- $(@{ChunkId=9000-10-path-validation; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield path-challenge/response behavior.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-10-path-validation; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield path-challenge/response behavior.; Confidence=high}.Mode) — Greenfield path-challenge/response behavior.

## 9000-04-connection-ids-basics

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S5, S5P1, S5P1P1`
- Mode: `P2P3P4`
- Confidence: `high`
- Reason: Existing packet-classification and Version Negotiation parser/tests already exist, so CID basics should reconcile first.

### Prompt 2

```text
```

### Prompt 3

```text
```

### Prompt 4

```text
```

## 9000-05-connection-id-management

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S5P1P2, S5P2, S5P2P1, S5P2P2, S5P2P3`
- Mode: `P2P3P4`
- Confidence: `high`
- Reason: Connection-ID management builds on existing packet parsing and CID-related logic.

### Prompt 2

```text
```

### Prompt 3

```text
```

### Prompt 4

```text
```

## 9000-06-version-negotiation

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S6, S6P1, S6P2, S6P3`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield Version Negotiation behavior layered on top of existing header parsing.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

```text
```

### Prompt 4

```text
```

## 9001-01-tls-core

- RFC: `9001`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9001.json`
- Section tokens: `S2, S3, S4, S5`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield QUIC TLS and packet-protection core.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

```text
```

### Prompt 4

```text
```

## 9000-07-handshake-properties

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S7, S7P2, S7P3`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield cryptographic handshake and connection-ID authentication semantics.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

```text
```

### Prompt 4

```text
```

## 9000-08-transport-params-and-crypto-buffers

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S7P4, S7P4P1, S7P4P2, S7P5`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield transport-parameter and CRYPTO buffering behavior.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

```text
```

### Prompt 4

```text
```

## 9000-09-address-validation-and-tokens

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S8, S8P1, S8P1P1, S8P1P2, S8P1P3, S8P1P4`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield address-validation token and amplification-limit behavior.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

```text
```

### Prompt 4

```text
```

## 9000-10-path-validation

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S8P2, S8P2P1, S8P2P2, S8P2P3, S8P2P4`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield path-challenge/response behavior.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

```text
```

### Prompt 4

```text
```
