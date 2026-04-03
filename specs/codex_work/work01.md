You are working in this repository after a refreshed QUIC requirement coverage triage.

Goal:
Finish any remaining RFC 9000 S10P1 idle-timeout computation partials, but only if they are still not trace_clean.

Scope:
Read the latest triage and act only on:
- REQ-QUIC-RFC9000-S10P1-0001
- REQ-QUIC-RFC9000-S10P1-0003
- REQ-QUIC-RFC9000-S10P1-0007
if and only if they are still partially_covered or otherwise not trace_clean.

Do NOT work on:
- S10P1-0002
- S10P1-0004
- close/draining lifecycle behavior
- unrelated RFC 9000 sections
- product code unless a very small low-risk testability seam is absolutely necessary

Ownership rule:
- Each canonical requirement-home file/class owns exactly one requirement.
- Tests inside that home should prove only that owning requirement.
- Do not add multiple Requirement IDs inside canonical homes.

Required approach:
1. Read the latest triage and confirm the current state of the three S10P1 targets.
2. Inspect:
   - QuicIdleTimeoutStateTests.cs
   - requirement-home files for those requirements
   - idle-timeout implementation directly
3. If any of the targets are still partial, add only the missing proof dimensions.
4. Keep the slice strictly about idle-timeout computation and PTO bounding.
5. Do not drift into actual connection close or timer expiry behavior.
6. If all three are already trace_clean, do not invent work; just report that the slice is complete.

Output expectations:
- Implement missing proof only where still needed.
- At the end, summarize:
  - which of the three changed
  - which are now trace_clean
  - any remaining gaps

Before coding:
- Briefly list the current state of S10P1-0001, 0003, and 0007 and say which one you will handle first, if any.
Then implement.
