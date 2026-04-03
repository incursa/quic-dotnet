You are working in this repository after a small RFC 9000 S17 parsing slice may have completed.

Goal:
Refresh the QUIC requirement coverage triage and report whether the chosen S17 subsection improved.

Tasks:
1. Regenerate the JSON and markdown triage outputs.
2. Check the updated state of the targeted S17 requirements from the previous pass.
3. Report whether the chosen subsection is improving cleanly enough to justify future overnight slices.

Important rules:
- Do not change product code.
- Only adjust tooling/reporting if required.

Output expectations:
- Updated triage files.
- Summary:
  - new overall totals
  - new RFC 9000 totals
  - updated state of the targeted S17 subsection
  - whether more S17 work seems worthwhile

Before coding:
- State that this refresh is to validate the chosen S17 subsection.
Then implement.
