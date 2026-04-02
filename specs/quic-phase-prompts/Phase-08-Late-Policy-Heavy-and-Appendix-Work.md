# Phase 08 — Late, Policy-Heavy, and Appendix Work

Finish the smaller late-policy slices and then review the remaining appendix B material.

Code roots used in generated prompts:
- ./src

Test roots used in generated prompts:
- ./tests

## Chunk Order

- $(@{ChunkId=9001-02-security-and-registry; Rfc=9001; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9001.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield key-update, security-consideration, and registry behavior.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9001-02-security-and-registry; Rfc=9001; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9001.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield key-update, security-consideration, and registry behavior.; Confidence=high}.Mode) — Greenfield key-update, security-consideration, and registry behavior.
- $(@{ChunkId=9001-03-appendix-b-aead-limits; Rfc=9001; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9001.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield appendix B AEAD limit behavior.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9001-03-appendix-b-aead-limits; Rfc=9001; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9001.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield appendix B AEAD limit behavior.; Confidence=high}.Mode) — Greenfield appendix B AEAD limit behavior.
- $(@{ChunkId=9000-20-datagram-and-mtu; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield datagram-size and PMTU behavior.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-20-datagram-and-mtu; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield datagram-size and PMTU behavior.; Confidence=high}.Mode) — Greenfield datagram-size and PMTU behavior.
- $(@{ChunkId=9000-28-errors-registry-and-security; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield error-code, security, and late-policy material.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-28-errors-registry-and-security; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield error-code, security, and late-policy material.; Confidence=high}.Mode) — Greenfield error-code, security, and late-policy material.
- $(@{ChunkId=9000-29-iana-and-late-sections; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield IANA and late-section work.; Confidence=high}.ChunkId) — mode $(@{ChunkId=9000-29-iana-and-late-sections; Rfc=9000; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9000.json; SectionTokens=System.String[]; Mode=P3P4; Reason=Greenfield IANA and late-section work.; Confidence=high}.Mode) — Greenfield IANA and late-section work.
- $(@{ChunkId=9002-06-appendix-b-constants-and-examples; Rfc=9002; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9002.json; SectionTokens=System.String[]; Mode=REVIEW; Reason=Inventory marked this appendix slice human_review_first because the retained SAP11/BP9 overlap pair needs manual judgment before automation.; Confidence=medium}.ChunkId) — mode $(@{ChunkId=9002-06-appendix-b-constants-and-examples; Rfc=9002; SpecFile=./specs/requirements/quic/SPEC-QUIC-RFC9002.json; SectionTokens=System.String[]; Mode=REVIEW; Reason=Inventory marked this appendix slice human_review_first because the retained SAP11/BP9 overlap pair needs manual judgment before automation.; Confidence=medium}.Mode) — Inventory marked this appendix slice human_review_first because the retained SAP11/BP9 overlap pair needs manual judgment before automation.

## 9001-02-security-and-registry

- RFC: `9001`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9001.json`
- Section tokens: `S6, S7, S8, S9, S10`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield key-update, security-consideration, and registry behavior.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

```text
```

### Prompt 4

```text
```

## 9001-03-appendix-b-aead-limits

- RFC: `9001`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9001.json`
- Section tokens: `SB, SBP1P1, SBP1P2, SBP2`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield appendix B AEAD limit behavior.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

```text
```

### Prompt 4

```text
```

## 9000-20-datagram-and-mtu

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S13P4, S13P4P1, S13P4P2, S13P4P2P1, S13P4P2P2, S14, S14P1, S14P2, S14P2P1, S14P3, S14P4`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield datagram-size and PMTU behavior.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

```text
```

### Prompt 4

```text
```

## 9000-28-errors-registry-and-security

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S19P19, S19P20, S19P21, S20P1, S20P2, S21P1P1P1, S21P2, S21P3, S21P4, S21P5, S21P5P3, S21P5P6, S21P6, S21P7, S21P9, S21P10, S21P11, S21P12`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield error-code, security, and late-policy material.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

```text
```

### Prompt 4

```text
```

## 9000-29-iana-and-late-sections

- RFC: `9000`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Section tokens: `S22P1P1, S22P1P2, S22P1P3, S22P1P4, S22P2, S22P3, S22P4, S22P5`
- Mode: `P3P4`
- Confidence: `high`
- Reason: Greenfield IANA and late-section work.

Prompt 2 is intentionally omitted for this chunk because the inventory found no existing implementation/test evidence that needs reconciliation first.

### Prompt 3

```text
```

### Prompt 4

```text
```

## 9002-06-appendix-b-constants-and-examples

- RFC: `9002`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9002.json`
- Section tokens: `SBP1, SBP2, SBP3, SBP4, SBP5, SBP6, SBP7, SBP8, SBP9`
- Mode: `REVIEW`
- Confidence: `medium`
- Reason: Inventory marked this appendix slice human_review_first because the retained SAP11/BP9 overlap pair needs manual judgment before automation.

This chunk was marked `human_review_first` by the inventory, so it gets a manual-review prompt instead of automatic Prompt 2/3/4 generation.

### Review Prompt

```text
```
