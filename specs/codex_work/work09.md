You are working in this repository after the latest refreshed QUIC requirement coverage triage.

Goal:
Take a safe first pass at RFC 9000 S17 packet parsing by carving a small, implementation-backed boundary slice out of the broad header parsing tests.

Why this slice:
The repository already has substantial header parsing implementation and broad tests. A bounded S17 parsing slice is a good overnight target if we keep it narrow and avoid broad rewrites.

Scope:
Read the latest triage and identify a small cluster of RFC 9000 S17 requirements in one adjacent subsection that are:
- covered_but_proof_too_broad
or
- partially_covered
and are clearly implemented through existing packet parsing code.

Preferred area:
A single tight subsection around version negotiation parsing or long-header field parsing, not the whole S17 family.

Do NOT work on:
- the entire S17 family at once
- unrelated frame codecs
- blocked architecture areas
- product code unless a very small low-risk testability seam is absolutely necessary

Ownership rule:
- One requirement-home per requirement.
- Tests inside that home prove only that requirement.

Required approach:
1. Read the latest triage and choose one tight adjacent S17 cluster that is clearly implemented and currently broad/partial.
2. Inspect existing broad parsing tests only as reference.
3. Create or refine requirement-owned proof for that one cluster.
4. Prefer a small cluster that can realistically be completed in one pass.
5. Preserve broad tests as supplemental proof.

Output expectations:
- Implement one small S17 requirement-owned parsing slice.
- At the end, summarize:
  - which requirements were targeted
  - which moved toward trace_clean
  - what remains broad in the chosen subsection

Before coding:
- Briefly state which S17 subsection you chose and why it is a safe bounded slice.
Then implement.
