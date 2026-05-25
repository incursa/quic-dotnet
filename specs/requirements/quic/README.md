---
workbench:
  type: specification
  workItems: []
  codeRefs: []
  pathHistory: []
  path: /specs/requirements/quic/README.md
---

# QUIC Requirements

This directory holds the QUIC requirement slice for the repository.
Each canonical artifact is authored in `.json`.

## Current Artifacts

- [`SPEC-QUIC-INT.json`](SPEC-QUIC-INT.json): canonical interop-harness adapter, endpoint-host shell, and local execution-report helper source
- [`SPEC-QUIC-RFC8999.json`](SPEC-QUIC-RFC8999.json): canonical RFC 8999 invariants source
- [`SPEC-QUIC-RFC9000.json`](SPEC-QUIC-RFC9000.json): canonical RFC 9000 transport source
- [`SPEC-QUIC-RFC9001.json`](SPEC-QUIC-RFC9001.json): canonical RFC 9001 TLS source
- [`SPEC-QUIC-RFC9002.json`](SPEC-QUIC-RFC9002.json): canonical RFC 9002 recovery source
- [`SPEC-QUIC-RFC9221.json`](SPEC-QUIC-RFC9221.json): canonical RFC 9221 QUIC DATAGRAM source
- [`SPEC-QUIC-RFC9287.json`](SPEC-QUIC-RFC9287.json): canonical RFC 9287 QUIC Bit greasing source
- [`SPEC-QUIC-CRT.json`](SPEC-QUIC-CRT.json): canonical connection-runtime source
- [`SPEC-QUIC-API.json`](SPEC-QUIC-API.json): canonical public API surface source
- [`REQUIREMENT-GAPS.md`](REQUIREMENT-GAPS.md): the local gap ledger
- [`../rfcs/README.md`](../rfcs/README.md): local QUIC RFC text corpus index for the later planning-only families

## Migration References

- [`../generated/quic/rfc9000-requirement-migration-crosswalk.json`](../generated/quic/rfc9000-requirement-migration-crosswalk.json) and [`../generated/quic/rfc9000-requirement-migration-crosswalk.md`](../generated/quic/rfc9000-requirement-migration-crosswalk.md): derived RFC9000 live-to-staged crosswalk for conservative requirement-ID updates
- [`../generated/quic/rfc9000-migration-retired-requirements.json`](../generated/quic/rfc9000-migration-retired-requirements.json): derived retired-ID ledger for references that no longer remain live
- [`../generated/quic/rfc9000-migration-exact-statement-renames.json`](../generated/quic/rfc9000-migration-exact-statement-renames.json) and [`../generated/quic/rfc9000-migration-exact-statement-renames.md`](../generated/quic/rfc9000-migration-exact-statement-renames.md): exact-statement rename slice used to preserve lineage when the obligation text is unchanged
- [`../generated/quic/rfc9000-migration-section-2-review.json`](../generated/quic/rfc9000-migration-section-2-review.json), [`../generated/quic/rfc9000-migration-s15-review.json`](../generated/quic/rfc9000-migration-s15-review.json), and [`../generated/quic/rfc9000-migration-s16-review.json`](../generated/quic/rfc9000-migration-s16-review.json): derived review slices for the staged RFC9000 migration pilot
- The remaining section-style RFC9000 IDs that still appear in canonical spec JSON are live canonical requirements, not retired migration leftovers, unless the retired ledger says otherwise.

## Notes

- Keep new QUIC work traceable to a stable `SPEC-...` file before implementation.
- Use the gap ledger when a source rule is unclear or needs an explicit decision record.
- Use the migration references above when reconciling stale RFC9000 requirement IDs or retired requirement references.
- RFC 8999 now carries the shared header-invariant slice.
- The broader QUIC RFC text corpus now lives locally under `../rfcs`; use the corpus index there together with `REQUIREMENT-GAPS.md` when planning later RFC families.
