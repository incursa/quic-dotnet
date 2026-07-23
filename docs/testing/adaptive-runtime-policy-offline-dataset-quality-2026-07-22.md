---
title: "Adaptive Runtime Offline Dataset Quality - 2026-07-22"
---

# Adaptive Runtime Offline Dataset Quality - 2026-07-22

Status: local post-SSD corpus validated; append-only materialization in
progress; offline review only

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
23,853 belong to neutral local results and are eligible for the default
curation pass. The remaining 34,023 belong to environment-invalid results.
They are retained for environment and regime analysis but excluded from
policy-effect learning.

The two contract-invalid results reference another 4,885 retained
observations. They do not have evidence-validation summaries and are not
represented as ML-eligible epoch rows. Their result, manifest, inventory,
stdout, stderr, and diagnostic artifacts remain append-only negative evidence.

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

Epoch rows are the independent observation layer. Values joined from a
result sample, including sample throughput, latency, retained memory, and
fairness status, repeat across every epoch in that sample. Offline analysis
must not treat those repeated sample values as independent measurements or
inflate their statistical weight.

Managed allocation, retained-memory, buffer-pool, and fairness fields that
were not measured must remain null or explicitly unassessed. Absence must not
be converted to zero.

## Holdout Readiness

The eligible local rows come from one host fingerprint. A leakage-resistant
train, validation, and test split requires at least three workload families
and three host fingerprints, with complete workload-family and host holdouts.
The local corpus therefore must produce
`insufficient_group_diversity`, with eligible rows assigned
`holdout_blocked`.

This is a dataset-readiness blocker, not a reason to discard the local
evidence. Distinct-host ProtocolLab campaigns are the next source of host
diversity. VM results must retain their substrate and operator-attested
physical-host provenance and must not be relabeled as bare-metal or
publishable evidence.

## Materialization Checkpoint

The append-only materialization target is:

`.artifacts/adaptive-runtime/offline-review-postssd-20260722-v1`

The pipeline validates all source schemas and artifact joins, builds the
policy catalog, normalizes joined rows, applies default curation, and emits a
deterministic blocked split manifest when holdout diversity is insufficient.
The full-corpus run is still in progress at this checkpoint. Its completed
file identities, exact summaries, elapsed time, and peak observed working set
will be added without replacing the source evidence.

The current implementation reads and schema-validates tens of thousands of
small JSON documents, retains the normalized document in memory, serializes
one large JSON object, and schema-validates that object before writing it.
The first full run has already shown that this is an operational scalability
constraint. That finding does not invalidate the source cohort; it means a
future pipeline-maintenance slice should evaluate streaming or partitioned
materialization before repeated large-corpus iterations.

## Review Decision

The cohort is suitable for offline data-quality review and exploratory regime
analysis after materialization completes. It is not yet suitable for model
selection or a production-rule claim because:

- only one host fingerprint is represented;
- the eligible rows do not populate leakage-resistant holdouts;
- sample-scoped outcomes repeat across epoch rows;
- several resource and fairness outcomes remain unmeasured;
- no valid row demonstrates a material receive-credit improvement.

The next permitted work is to complete and profile this immutable dataset,
collect the same forced-policy and shadow observation contracts on distinct
hosts, and review the resulting coverage. Model training, rule derivation,
shadow promotion, and production implementation remain separate reviewed
stages.
