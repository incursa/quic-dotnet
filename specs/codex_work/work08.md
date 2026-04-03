You are working in this repository after an RFC 9002 congestion-related cleanup pass may have completed.

Goal:
Refresh the QUIC requirement coverage triage and report whether the congestion-related RFC 9002 partials improved.

Tasks:
1. Regenerate the JSON and markdown triage outputs.
2. Check the updated state of the RFC 9002 congestion-related requirements worked in the previous pass.
3. Report whether they are now trace_clean or still partial.

Important rules:
- Do not change product code.
- Only adjust tooling/reporting if required.

Output expectations:
- Updated triage files.
- Summary:
  - new overall totals
  - new RFC 9002 totals
  - updated state of the targeted congestion-related requirements

Before coding:
- State that this refresh is for validating the congestion-related slice.
Then implement.
