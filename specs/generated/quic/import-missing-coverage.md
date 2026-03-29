# QUIC Import Missing Coverage Review

Full overlap context remains in [`assembly-overlap-report.md`](./assembly-overlap-report.md). This file only records audit-relevant gaps or suspicious coverage surfaces.

## Draft Requirements Not Represented In Final Or Rejected/Merged Lists

- None. Every draft requirement found in the step-2 draft Markdown files is represented in an assembly map final record, split record, merged record, or rejection record.

## Final Requirements Missing Provenance

- None. Every final QUIC requirement carries `Trace -> Source Refs` with RFC-specific provenance.

## Source-Batch Coverage Anomalies

- None. The repaired `step2_out/9000/10.coverage.json` and `step2_out/9001/1-6.coverage.json` surfaces now match their corresponding draft Markdown files, and no other step-2 coverage artifact shows an audit-relevant mismatch.

## Retained Overlaps Likely To Need Human Review

- RFC 8999 section 5.1 remains intentionally overlap-prone against RFC 9000 packet-format requirements; see the review carry-forward notes in [`assembly-overlap-report.md`](./assembly-overlap-report.md).
- RFC 9000 keeps large retained overlap families in sections 17.2, 17.3.1, 19.4, 19.5, 19.8, 19.10, 19.11, 19.13, and 19.15. Those are surfaced explicitly in the overlap report and should remain human-reviewed rather than auto-merged.
- RFC 9002 retains the appendix overlap pair `REQ-QUIC-RFC9002-SAP11-0003` / `REQ-QUIC-RFC9002-SBP9-0003` and it should remain under review because the wording is near-duplicate across normative appendix material.

## Coverage Summary

- Final provenance coverage: complete.
- Draft-to-assembly accounting: complete for all four RFC draft Markdown surfaces.
- Step-2 coverage artifact quality: clean for RFC 8999, RFC 9000, RFC 9001, and RFC 9002.
