# Phase 06 — Lifecycle, Close, and Error Handling

Add idle timeout, connection close, stateless reset, and error signaling after the main path is alive.

Code roots used in generated prompts:
- ./src

Test roots used in generated prompts:
- ./tests

## Chunk Order

- $(@{ChunkId=9000-13-idle-and-close; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield idle-timeout and connection-close behavior.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-13-idle-and-close; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield idle-timeout and connection-close behavior.; Confidence=high}.Mode) — Greenfield idle-timeout and connection-close behavior.
- $(@{ChunkId=9000-14-stateless-reset; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield stateless-reset behavior.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-14-stateless-reset; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield stateless-reset behavior.; Confidence=high}.Mode) — Greenfield stateless-reset behavior.
- $(@{ChunkId=9000-15-error-handling; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield transport/application error-handling behavior.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-15-error-handling; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield transport/application error-handling behavior.; Confidence=high}.Mode) — Greenfield transport/application error-handling behavior.

## 9000-13-idle-and-close

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S10, S10P1, S10P1P1, S10P1P2, S10P2, S10P2P1, S10P2P2, S10P2P3`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield idle-timeout and connection-close behavior.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

```text
```

### Prompt 4

```text
```

## 9000-14-stateless-reset

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S10P3, S10P3P1, S10P3P2, S10P3P3`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield stateless-reset behavior.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

```text
```

### Prompt 4

```text
```

## 9000-15-error-handling

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S11, S11P1, S11P2`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield transport/application error-handling behavior.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

```text
```

### Prompt 4

```text
```
