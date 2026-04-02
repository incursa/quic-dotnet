# Phase 05 — Migration and Path Management

Once streams, ACK, and validation exist, implement migration and path-management behavior.

Code roots used in generated prompts:
- ./src

Test roots used in generated prompts:
- ./tests

## Chunk Order

- $(@{ChunkId=9000-11-migration-core; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield migration-core behavior.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-11-migration-core; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield migration-core behavior.; Confidence=high}.Mode) — Greenfield migration-core behavior.
- $(@{ChunkId=9000-12-migration-followup; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield migration follow-up and preferred-address behavior.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-12-migration-followup; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield migration follow-up and preferred-address behavior.; Confidence=high}.Mode) — Greenfield migration follow-up and preferred-address behavior.

## 9000-11-migration-core

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S9, S9P1, S9P2, S9P3, S9P3P1, S9P3P2, S9P3P3`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield migration-core behavior.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

```text
```

### Prompt 4

```text
```

## 9000-12-migration-followup

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S9P4, S9P5, S9P6, S9P6P1, S9P6P2, S9P6P3, S9P7`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield migration follow-up and preferred-address behavior.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

```text
```

### Prompt 4

```text
```
