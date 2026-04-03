You are working in this repository after the latest refreshed QUIC requirement coverage triage.

Goal:
Take one cautious exploratory pass at RFC 9001, but only if you can find a very small non-blocked or broad-only slice that is clearly implemented.

Why:
RFC 9001 still has a backlog, but much of it is blocked. This prompt should only proceed if there is a very small, safe, implementation-backed slice.

Scope:
Read the latest triage and identify at most one very small RFC 9001 cluster that is:
- covered_but_proof_too_broad
or
- partially_covered
and is clearly implemented without requiring handshake orchestration, key updates, or broader TLS state machinery.

Do NOT work on:
- blocked RFC 9001 requirements
- any slice that needs TLS orchestration
- broad RFC 9001 rewrites
- product code unless a very small low-risk testability seam is absolutely necessary

Ownership rule:
- One requirement-home per requirement.
- Tests inside that home prove only that requirement.

Required approach:
1. Read the latest triage and decide whether a safe RFC 9001 slice exists.
2. If no clearly safe slice exists, stop and report that RFC 9001 should be deferred.
3. If a safe slice exists:
   - inspect existing broad tests only as reference
   - create or refine requirement-owned proof for that slice only
4. Preserve broad tests as supplemental proof.

Output expectations:
- Either:
  - implement one very small safe RFC 9001 slice, or
  - explicitly report that RFC 9001 should be deferred for now
- At the end, summarize what you decided and why.

Before coding:
- Briefly state whether you found a safe RFC 9001 slice and what it is.
Then implement.
