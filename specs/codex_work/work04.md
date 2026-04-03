You are working in this repository after an RFC 9002 ack-delay cleanup pass may have completed.

Goal:
Refresh the QUIC requirement coverage triage and report whether the RFC 9002 ack-delay partials improved.

Tasks:
1. Regenerate the JSON and markdown triage outputs.
2. Check the updated state of the RFC 9002 ack-delay requirements worked in the previous pass.
3. Report whether they are now trace_clean or still partial.

Important rules:
- Do not change product code.
- Only adjust tooling/reporting if required.

Output expectations:
- Updated triage files.
- Summary:
  - new overall totals
  - new RFC 9002 totals
  - updated state of the ack-delay targets

Before coding:
- State that this refresh is for validating the ack-delay slice.
Then implement.
