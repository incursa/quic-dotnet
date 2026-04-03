You are working in this repository after the latest refreshed QUIC requirement coverage triage.

Goal:
Improve RFC 9002 proof depth for a bounded congestion-related partial cluster.

Scope:
Read the latest triage and focus only on RFC 9002 requirements that are still partially_covered in:
- persistent congestion
- congestion window update rules

Priority targets include:
- REQ-QUIC-RFC9002-S7P6P2-0003
- REQ-QUIC-RFC9002-SBP5-0001
- REQ-QUIC-RFC9002-SBP5-0003
- REQ-QUIC-RFC9002-SBP5-0004
plus any immediately adjacent partial requirements in those same subsections.

Do NOT work on:
- blocked RFC 9002 requirements
- unrelated RFCs
- product code unless a very small low-risk testability seam is absolutely necessary

Ownership rule:
- One requirement-home per requirement.
- Tests inside that home prove only that requirement.

Required approach:
1. Read the latest triage and confirm which of the target requirements are still partial.
2. Inspect:
   - requirement-home files
   - existing broad recovery/congestion tests only as reference
   - implementation directly
3. Add missing proof dimensions, especially negative and edge cases.
4. Prefer narrow invariant-focused tests over broad simulations unless the repo already has a stable deterministic pattern.
5. Preserve broad tests as supplemental proof.

Output expectations:
- Implement one or more focused congestion-related requirement-home improvements.
- At the end, summarize:
  - which requirements improved
  - which missing proof dimensions were added
  - any remaining partials in this cluster

Before coding:
- Briefly list the target congestion-related partial requirements and their missing proof dimensions.
Then implement.
