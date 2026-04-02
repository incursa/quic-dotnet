# Phase 07 — Congestion Control and Recovery State

After loss detection exists, add congestion control and then review appendix-driven recovery-state implementation work.

Code roots used in generated prompts:
- ./src

Test roots used in generated prompts:
- ./tests

## Chunk Order

- $(@{ChunkId=9002-04-congestion-control; Rfc=9002; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9002.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield congestion-control, ECN, and persistent-congestion behavior.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9002-04-congestion-control; Rfc=9002; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9002.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield congestion-control, ECN, and persistent-congestion behavior.; Confidence=high}.Mode) — Greenfield congestion-control, ECN, and persistent-congestion behavior.
- $(@{ChunkId=9002-05-appendix-a-recovery-state; Rfc=9002; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9002.json; SectionTokens=System.String[]; Mode=REVIEW; Reason=Inventory marked this appendix slice human_review_first because the retained SAP11/BP9 overlap pair needs manual judgment before automation.; Confidence=medium}.ChunkId) — mode $(@{ChunkId=9002-05-appendix-a-recovery-state; Rfc=9002; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9002.json; SectionTokens=System.String[]; Mode=REVIEW; Reason=Inventory marked this appendix slice human_review_first because the retained SAP11/BP9 overlap pair needs manual judgment before automation.; Confidence=medium}.Mode) — Inventory marked this appendix slice human_review_first because the retained SAP11/BP9 overlap pair needs manual judgment before automation.

## 9002-04-congestion-control

- RFC: `9002`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9002.json`
- Section tokens: `S7, S7P1, S7P2, S7P3P1, S7P3P2, S7P3P3, S7P4, S7P5, S7P6, S7P6P1, S7P6P2, S7P7, S7P8`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield congestion-control, ECN, and persistent-congestion behavior.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

```text
```

### Prompt 4

```text
```

## 9002-05-appendix-a-recovery-state

- RFC: `9002`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9002.json`
- Section tokens: `SAP1, SAP1P1, SAP2, SAP4, SAP5, SAP6, SAP7, SAP8, SAP9, SAP10, SAP11`
- Mode: `REVIEW`
- Confidence: `medium`
- Reason: Inventory marked this appendix slice human_review_first because the retained SAP11/BP9 overlap pair needs manual judgment before automation.

This chunk was marked `human_review_first` by the inventory, so it gets a manual-review prompt instead of automatic Prompt 2/3/4 generation.

### Review Prompt

```text
```
