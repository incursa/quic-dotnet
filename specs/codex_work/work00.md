You are working in this repository after a recent RFC 9000 S10P1 idle-timeout partial-coverage pass may have completed.

Goal:
Refresh the QUIC requirement coverage triage so the latest S10P1 work is reflected before any more slices are attempted.

Tasks:
1. Run the existing QUIC requirement coverage triage generation flow.
2. Regenerate:
   - machine-readable JSON triage
   - markdown summary
3. Specifically inspect the refreshed state of:
   - REQ-QUIC-RFC9000-S10P1-0001
   - REQ-QUIC-RFC9000-S10P1-0003
   - REQ-QUIC-RFC9000-S10P1-0007
4. Report whether each of those moved to:
   - trace_clean
   - still partially_covered
   - or some other state

Important rules:
- Do not change product code in this prompt.
- Only adjust tooling/reporting if required for correct triage.
- Be conservative.

Output expectations:
- Update the triage files directly.
- At the end, summarize:
  - new overall totals
  - new RFC 9000 totals
  - the exact state of S10P1-0001, 0003, and 0007

Before coding:
- Briefly state which script/tool you will use to regenerate triage.
Then implement.
