# RFC9000 Section 2 Migration Review

Generated: 2026-05-22T04:41:48Z

This report reflects the clarified pilot rule: overlapping obligations adopt the incoming staged RFC9000 ID as canonical, and downstream trace moves with that ID.

## Summary

- `rename-with-lineage`: 8
- `new-only`: 2
- `preserve`: 0
- `split-merge`: 0
- `blocked/deferred`: 1

## Applied Mappings

| Classification | Live ID | Incoming Canonical ID | Action |
| --- | --- | --- | --- |
| $(System.Collections.Specialized.OrderedDictionary.classification) | $live | $(System.Collections.Specialized.OrderedDictionary.staged_requirement_id) | Renamed canonical requirement ID to staged ID, adopted staged statement and coverage, moved requirement-home file/class and x_test_refs. |
| $(System.Collections.Specialized.OrderedDictionary.classification) | $live | $(System.Collections.Specialized.OrderedDictionary.staged_requirement_id) | Renamed canonical requirement ID to staged ID, adopted staged stronger capability statement and coverage, moved requirement-home file/class and x_test_refs. |
| $(System.Collections.Specialized.OrderedDictionary.classification) | $live | $(System.Collections.Specialized.OrderedDictionary.staged_requirement_id) | Added as incoming canonical requirement with upstream refs only; no downstream proof assigned in this slice. |
| $(System.Collections.Specialized.OrderedDictionary.classification) | $live | $(System.Collections.Specialized.OrderedDictionary.staged_requirement_id) | Renamed canonical requirement ID to staged ID, adopted staged stronger capability statement and coverage, retargeted dependent proof refs. |
| $(System.Collections.Specialized.OrderedDictionary.classification) | $live | $(System.Collections.Specialized.OrderedDictionary.staged_requirement_id) | Renamed canonical requirement ID to staged ID, adopted staged stronger capability statement and coverage, moved requirement-home file/class and API xref. |
| $(System.Collections.Specialized.OrderedDictionary.classification) | $live | $(System.Collections.Specialized.OrderedDictionary.staged_requirement_id) | Renamed canonical requirement ID to staged ID, adopted staged stronger capability statement and coverage, moved requirement-home file/class and related frame proof refs. |
| $(System.Collections.Specialized.OrderedDictionary.classification) | $live | $(System.Collections.Specialized.OrderedDictionary.staged_requirement_id) | Renamed canonical requirement ID to staged ID, adopted staged statement and coverage, moved requirement-home file/class and x_test_refs. |
| $(System.Collections.Specialized.OrderedDictionary.classification) | $live | $(System.Collections.Specialized.OrderedDictionary.staged_requirement_id) | Renamed canonical requirement ID to staged ID, adopted staged stronger capability statement and coverage, moved requirement-home file/class and related flow-control proof refs. |
| $(System.Collections.Specialized.OrderedDictionary.classification) | $live | $(System.Collections.Specialized.OrderedDictionary.staged_requirement_id) | Renamed canonical requirement ID to staged ID, adopted staged stronger capability statement and coverage, moved requirement-home file/class and related max-stream proof refs. |
| $(System.Collections.Specialized.OrderedDictionary.classification) | $live | $(System.Collections.Specialized.OrderedDictionary.staged_requirement_id) | Added as incoming canonical requirement with upstream refs only; no downstream proof assigned in this slice. |

## Deferred Mapping

| Live ID | Reason |
| --- | --- |
| `REQ-QUIC-RFC9000-S2-0003` | No clear staged replacement found for the long-lived stream MAY statement. Left unchanged until an explicit withdrawal or replacement decision exists. |

## Lineage Handling

- Retired live IDs are recorded in `specs/generated/quic/rfc9000-migration-retired-requirements.json`.
- The crosswalk records `derived_from` and `supersedes` semantics for each renamed requirement.
- Canonical `trace.derived_from` / `trace.supersedes` fields are intentionally deferred because the current repo validator requires those references to resolve to live IDs.

## Validation Plan

- `pwsh -NoProfile -File scripts\Validate-SpecTraceJson.ps1 -RepoRoot . -Profiles core`
- `pwsh -NoProfile -File scripts\Validate-SpecTraceJson.ps1 -RepoRoot . -Profiles traceable -JsonReportPath artifacts/spec-trace-rfc9000-migration-traceable-report.json`
- Focused requirement-home test filter for renamed section 2 classes.
- `git diff --check`
