You are working in this repository after the latest refreshed QUIC requirement coverage triage.

Goal:
Improve RFC 9002 ack-delay proof depth by closing a small partial cluster first.

Why this slice:
RFC 9002 still has many partials, and the ack-delay area is a bounded, implementation-backed slice that tends to need missing negative and edge proof rather than brand-new architecture.

Scope:
Read the latest triage and focus only on RFC 9002 ack-delay requirements that are still partially_covered, especially:
- REQ-QUIC-RFC9002-S5P3-0009
- REQ-QUIC-RFC9002-S5P3-0012
and any immediately adjacent ack-delay requirements in the same subsection that are still partial.

Do NOT work on:
- blocked RFC 9002 requirements
- broad repo-wide cleanup
- unrelated RFCs
- product code unless a very small low-risk testability seam is absolutely necessary

Ownership rule:
- Each canonical requirement-home file/class owns exactly one requirement.
- Tests inside that home should prove only that owning requirement.

Required approach:
1. Read the latest triage and confirm the partial ack-delay targets.
2. Inspect:
   - existing requirement homes for those requirements
   - broad RFC 9002 timing/recovery tests only as reference
   - implementation directly
3. Add only the missing proof dimensions required by the requirement JSON.
4. Prefer small negative and edge cases over broad scenario tests.
5. Preserve existing broad tests as supplemental proof.

Output expectations:
- Implement one or more focused ack-delay requirement-home improvements.
- At the end, summarize:
  - which requirements were improved
  - which missing dimensions were added
  - any remaining ack-delay gaps

Before coding:
- Briefly list the current partial ack-delay requirements and their missing proof dimensions.
Then implement.
