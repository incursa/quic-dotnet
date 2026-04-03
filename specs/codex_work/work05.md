You are working in this repository after the latest refreshed QUIC requirement coverage triage.

Goal:
Improve RFC 9002 loss-delay proof depth by closing a bounded partial cluster.

Scope:
Read the latest triage and focus only on RFC 9002 loss-delay requirements that are still partially_covered, especially:
- REQ-QUIC-RFC9002-S6P1P2-0001
- REQ-QUIC-RFC9002-S6P1P2-0003
- REQ-QUIC-RFC9002-S6P1P2-0004
and any immediately adjacent loss-delay requirements in the same subsection that are still partial.

Do NOT work on:
- blocked RFC 9002 requirements
- congestion window or persistent congestion unless they are strictly needed as immediate helper context
- unrelated RFCs
- product code unless a very small low-risk testability seam is absolutely necessary

Ownership rule:
- One requirement-home per requirement.
- Tests inside that home prove only that requirement.

Required approach:
1. Read the latest triage and confirm the current partial loss-delay targets.
2. Inspect:
   - requirement-home files
   - broad recovery/timing tests only as reference
   - implementation directly
3. Add missing negative and edge coverage where required.
4. Prefer focused boundary/invariant checks over broad time-sequence tests.
5. Preserve broad tests as supplemental proof.

Output expectations:
- Implement one or more focused loss-delay requirement-home improvements.
- At the end, summarize:
  - which requirements improved
  - which missing proof dimensions were added
  - any remaining loss-delay gaps

Before coding:
- Briefly list the current partial loss-delay requirements and their missing proof dimensions.
Then implement.
