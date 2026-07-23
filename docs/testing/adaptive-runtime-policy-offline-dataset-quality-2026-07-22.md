---
title: "Adaptive Runtime Offline Dataset Quality - 2026-07-22"
---

# Adaptive Runtime Offline Dataset Quality - 2026-07-22

Status: local post-SSD corpus validated and materialized; split blocked for
insufficient group diversity; offline review only

This record evaluates whether the retained receive-credit evidence is ready
for offline regime discovery. It does not train a model, derive a production
rule, authorize online exploration, or change the runtime selector. The
existing `legacy_current` behavior remains authoritative.

## Source Cohort

The bounded source cohort contains ten post-SSD `local-result.json`
documents:

- five `neutral_local`;
- three `invalid_environment`;
- two `invalid_contract`.

The eight contract-complete results join to 57,876 epoch documents. Of those,
23,853 belong to neutral local results and enter the default curation pass.
That pass includes 20,172 rows and excludes 3,681 rows carrying analysis flags.
The remaining 34,023 rows belong to environment-invalid results. They are
retained for environment and regime analysis but excluded from policy-effect
learning.

The two contract-invalid results reference another 4,885 retained
observations. They do not have evidence-validation summaries and are not
represented as ML-eligible epoch rows. Their result, manifest, inventory,
stdout, stderr, and diagnostic artifacts remain append-only negative evidence.
The normalized dataset records eight unmatched source-result entries for their
four duplex and four multiplex samples; it does not manufacture epoch rows for
them.

## Integrity And Compatibility

The ten checksum inventories reference 58,323 files. The campaign integrity
audit found no missing path and no SHA-256 mismatch.

The full evidence validator accepts all 57,876 epoch rows when the explicit
legacy result-level environment-exclusion compatibility gate is enabled.
That gate is required because some environment-invalid results were captured
before result health flags were copied into every epoch row. The rows are not
rewritten or promoted: the joined result classification still excludes all
34,023 affected environment-invalid rows.

Standalone validation remains strict by default. Compatibility is enabled
only by the dataset pipeline, is recorded in normalized provenance, and
reports the exact number of rows admitted under the legacy exclusion rule.

## Curation Semantics

Default curation is intentionally conservative:

- `neutral_local` rows with no analysis exclusion flag are included;
- `invalid_environment`, `invalid_contract`, `failed_correctness`, and
  `stress_only` results are excluded;
- excluded and unmatched rows remain addressable instead of being deleted;
- missing numeric signals remain null;
- missing and stale masks remain available for later quality analysis;
- workload labels are analysis-only and must not become production selector
  inputs.

The completed curation manifest reports 20,172 included rows, 37,704 excluded
rows, and zero `negative_retained` rows. The excluded set is the union of all
34,023 `invalid_environment` rows and 3,681 flagged `neutral_local` rows.
Observed analysis flags are `warmup` (8,890 rows),
`observation_missing` (575 rows), and `terminal_partial_epoch` (61 rows);
flags may overlap.

Epoch rows are the independent observation layer. Values joined from a
result sample, including sample throughput, latency, retained memory, and
fairness status, repeat across every epoch in that sample. Offline analysis
must not treat those repeated sample values as independent measurements or
inflate their statistical weight.

Managed allocation, retained-memory, buffer-pool, and fairness fields that
were not measured must remain null or explicitly unassessed. Absence must not
be converted to zero.

This cohort makes that limitation concrete. All 57,876 normalized epoch rows
have null throughput, latency, allocation, retained-memory,
queue-to-service-ratio, and flow-blocked metrics at epoch scope. Sample-scoped
throughput and latency are present on every joined row, while buffer-pool,
managed-allocation, and retained-memory outcomes are null on every joined row.
`fairnessAssessed` is present but false. This dataset can support regime and
observation-quality review, but it cannot independently estimate the missing
resource or fairness outcomes.

## Holdout Readiness

The local rows span six workload-family keys but only one host fingerprint and
one binary cohort. A leakage-resistant
train, validation, and test split requires at least three workload families
and three host fingerprints, with complete workload-family and host holdouts.
The deterministic seed-17 split therefore reports
`insufficient_group_diversity`: train, validation, and test each contain zero
rows, and all 57,876 rows are assigned `holdout_blocked`.

This is a dataset-readiness blocker, not a reason to discard the local
evidence. Distinct-host ProtocolLab campaigns are the next source of host
diversity. VM results must retain their substrate and operator-attested
physical-host provenance and must not be relabeled as bare-metal or
publishable evidence.

## Materialization Checkpoint

The append-only materialization target is:

`.artifacts/adaptive-runtime/offline-review-postssd-20260722-v1`

The pipeline completed from 2026-07-23 04:59:01 UTC through the final split
write at 07:04:31 UTC, approximately 2 hours 5 minutes 30 seconds. It emitted:

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `catalog/policy-catalog.json` | 11,385 | `36ae444f6ab386351bb43a8fc61ad2b53435315734ce28d1fd12659c734ca773` |
| `normalized/normalized-dataset.json` | 269,879,031 | `7873a22eae3abbad5a9402a7ce98c32bb5bcd5f8596ecbec4dff418915d3afb5` |
| `curated/curated-manifest.json` | 65,616,250 | `6309e6ea28c88c2256070ae5951be7d18c80d8896d24bed85458fd2e1fd3dab9` |
| `split/split-manifest.json` | 52,339,168 | `1c38632e264e1f43b30a04e1627b15c71b0167dd18c8a842aeb2839e2da85e06` |

The normalized artifact records ten result inputs, 57,876 epoch inputs, a
successful evidence-validation summary, zero unmatched epoch rows, and eight
retained unmatched result samples. Its provenance pins transformation commit
`951db888ddcac44d8373e3df562f05a7fc9c1d28`.

The current implementation reads and schema-validates tens of thousands of
small JSON documents, retains the normalized document in memory, serializes
one large JSON object, and schema-validates that object before writing it.
The full run reached a sampled maximum of 13.51 GiB working set and 14.57 GiB
private memory near serialization. These are observed samples, not
instrumented process peaks. The duration and memory footprint are an
operational scalability constraint. That finding does not invalidate the
source cohort; a future pipeline-maintenance slice should evaluate streaming
or partitioned materialization before repeated large-corpus iterations.

## Review Decision

The cohort is suitable for offline data-quality review and exploratory regime
analysis. It is not yet suitable for model selection or a production-rule
claim because:

- only one host fingerprint is represented;
- the eligible rows do not populate leakage-resistant holdouts;
- sample-scoped outcomes repeat across epoch rows;
- several resource and fairness outcomes remain unmeasured;
- no valid row demonstrates a material receive-credit improvement.

The next permitted work is to preserve this immutable local checkpoint,
collect the same forced-policy and shadow observation contracts on distinct
hosts, and review the resulting coverage. The separate ProtocolLab raw-QUIC
handshake campaign qualifies cross-worker routing and implementation behavior;
it is not receive-credit policy training data. Model training, rule derivation,
shadow promotion, and production implementation remain separate reviewed
stages.
