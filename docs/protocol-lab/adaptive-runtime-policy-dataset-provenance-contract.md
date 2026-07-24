---
title: "Adaptive Runtime Offline Dataset And Provenance Contract"
---

# Adaptive Runtime Offline Dataset And Provenance Contract

Status: proposed contract; no training or production inference authorized

The offline dataset contains one row per bounded connection epoch. Rows are
generated from forced-policy and shadow campaigns so offline analysis can
compare policies without asking production traffic to explore.

The general epoch row schema is
[`../../schemas/adaptive-runtime-policy-epoch-dataset-v1.schema.json`](../../schemas/adaptive-runtime-policy-epoch-dataset-v1.schema.json).
Forced `application_send_turn_planning` evidence that has only
connection-construction provenance instead uses the distinct
[`../../schemas/adaptive-runtime-policy-construction-dataset-v1.schema.json`](../../schemas/adaptive-runtime-policy-construction-dataset-v1.schema.json).
It is a provenance join record, not an epoch row, and must never be substituted
for one in epoch-based analysis.

For `application_send_turn_planning`, the retained raw connection records are
exported by
[`../../eng/adaptive-runtime/Convert-AdaptiveRuntimeApplicationSendTurnProvenance.ps1`](../../eng/adaptive-runtime/Convert-AdaptiveRuntimeApplicationSendTurnProvenance.ps1).
The exporter is write-once: it preserves the raw SHA-256, records a semantic
row hash and an output checksum inventory, normalizes the runtime enum to the
closed dataset values, and requires caller-supplied source correctness flags.
[`../../eng/adaptive-runtime/Test-AdaptiveRuntimePolicyEvidence.ps1`](../../eng/adaptive-runtime/Test-AdaptiveRuntimePolicyEvidence.ps1)
validates these construction rows separately from epochs: each must join a
forced send-turn result, its source sample, and the retained raw artifact in
that result's checksum inventory. A join failure remains invalid or excluded;
it is never repaired by relabeling a receive-credit epoch.

The raw QUIC host also emits the separate
`adaptive-runtime-application-send-turn-raw-v1` trace for observe-only and
shadow turns. That trace contains only a run-local connection pseudonym, the
versioned observation, and the optional versioned recommendation snapshot.
[`../../schemas/adaptive-runtime-application-send-turn-raw-v1.schema.json`](../../schemas/adaptive-runtime-application-send-turn-raw-v1.schema.json)
closes that raw contract. The write-once standalone
[`../../eng/adaptive-runtime/Convert-AdaptiveRuntimeApplicationSendTurnEvidence.ps1`](../../eng/adaptive-runtime/Convert-AdaptiveRuntimeApplicationSendTurnEvidence.ps1)
validates every raw record and version identity, rejects duplicate or
out-of-order turns, maps observe-only and shadow records to the common epoch
schema, retains the source checksum, and writes a checksum manifest. Rows stay
under a retained `.pending` directory until the complete input validates, so a
failed conversion cannot expose partial rows as completed output.

For this axis, one exported epoch is the interval from a planning capture to
the next planning capture for the same run-local connection. This interval is
not the one-turn policy latch lifetime and is not an exact actor-service
duration. The last record has no next boundary, so it receives the minimum
positive schema duration and `terminal_partial_epoch`; it is retained but
excluded. Post-epoch outcome fields remain null until the permanent runner can
join attributable outcomes. `hasIssuedApplicationData` also remains null
because the send-turn v1 observation does not capture that receive-credit
signal.

The standalone converter and canonical fixtures prove raw-to-epoch schema
materialization. The permanent runner now invokes the same converter for
send-turn shadow cells and joins completed rows to schema-valid local results,
source samples, raw artifacts, and checksum inventories. Canonical fixtures,
dry runs, and focused tests remain verification artifacts rather than campaign
evidence or analysis inputs; only executed, classified, schema-valid cells may
enter the append-only campaign layers.

The normalized v1 dataset keeps `receive_credit_publication` and
`application_send_turn_planning` as separate closed `policyAxis` values. The
pipeline may materialize either axis through the same join contract, but it
must not pool their observations, rule identities, counterfactual groups, or
curation claims. Construction-only send-turn provenance remains outside the
epoch pipeline.

Each normalized epoch also retains a closed `modelFeatures` block copied only
from bounded pre-decision runtime observations. For the send-turn v1 axis this
includes queue depth and bytes, distinct queued streams, oldest-send age,
queue and actor-service EWMAs, their fixed-point ratio, burst-limit hits,
congestion window, bytes in flight, retained send buffers and bytes, and the
missing, stale, lifecycle, and out-of-domain flags. Workload identity remains
in the separate analysis-only block and is not copied into `modelFeatures`.

## Row Semantics

An epoch row contains pre-decision observations, the policy applied during the
epoch, the shadow recommendation, transition/dwell state, outcomes observed
after the decision, correctness and fairness flags, and immutable provenance.
It is not one packet, one frame, or one application operation.

Pre-decision fields must be captured before the policy snapshot for that epoch
is selected. Post-epoch outcomes must not leak into that epoch's production
features. A transformation may create labels from post-epoch outcomes, but
must version the label logic and keep it outside the observation object.

## Required Identity And Provenance

Every row carries or resolves through an immutable campaign manifest to:

- dataset, campaign, run, cell, repetition, connection, and epoch identity;
- repository URL/path, commit, branch, and dirty state;
- benchmark, runtime, schema, rule, script, and tool versions;
- SHA-256 for frozen benchmark and runtime binaries;
- pseudonymous host fingerprint, OS, architecture, CPU count, runtime version,
  monotonic timer frequency, topology, and pressure-capture availability;
- script and tool versions plus requested and effective workload shape,
  including connection, stream, concurrency, warmup, and measurement values;
- forced/applied/shadow policy values and reason codes;
- source artifact path and SHA-256; and
- transformation name, version, code commit, inputs, and output checksum.

`connection_key` is a run-local pseudonym. Transport connection IDs, peer
addresses, stream IDs, URLs, and application identifiers are prohibited.

## Workload Identity Boundary

Workload identity, scenario ID, payload size, requested concurrency, and
traffic label are retained under `workload_analysis_only`. They may be used to
stratify results, create holdouts, detect coverage holes, and audit leakage.
They are excluded from production rule inputs.

An offline model that depends on those fields may be useful for diagnosis but
cannot be distilled into a production rule until the same boundary is
expressed using observable connection and optional advisor signals.

## Dataset Layers

| Layer | Content | Mutation rule |
| --- | --- | --- |
| `raw` | Schema-valid epoch rows and source result documents exactly as exported | Immutable; corrections append a superseding row or manifest |
| `normalized` | Unit normalization, bounded derived ratios, missing-value masks, and stable enumerations | Deterministic versioned transform from raw checksums |
| `curated` | Explicit inclusion/exclusion, outcome labels, matched counterfactual groups, and split assignments | Append-only manifest with reasons for every excluded row |
| `analysis` | Model files, notebooks/reports, feature importance, regime boundaries, and candidate rules | Reproducible from a curated dataset ID; never a production input by itself |

No layer overwrites its predecessor. Every artifact has a checksum inventory.

## Quality And Exclusion Flags

Rows remain present but are excluded from training when any of these flags is
true:

- payload or protocol correctness failed;
- requested and effective workload shapes differ;
- binary or schema identity is missing or changed mid-campaign;
- target or generator health is invalid;
- observation is missing, stale, saturated, or out of domain for the analysis;
- instrumentation configuration differs from the matched cohort;
- the row belongs to warmup, cooldown, shutdown, or a terminal partial epoch;
- the policy was not actually forced/applied as declared; or
- the row cannot be joined to its source result and checksum inventory.

Excluded rows are still valuable negative or data-quality evidence and must
not be deleted.

## Counterfactual Grouping

Forced-policy rows may be compared only when campaign, workload shape, binary
cohort, environment class, repetition protocol, and pre-decision regime are
compatible. Epochs from the same connection are not independent samples;
train/test splitting and uncertainty calculations must group by run and
connection.

Shadow recommendations are evaluated against forced-policy cohorts, not
against the behavior they happened to observe under `legacy_current` alone.
The contract does not claim exact per-epoch causal identity when a forced
policy changes later connection state.

## Split Contract

At minimum, hold out complete workload families and complete host fingerprints.
Rows from one run, binary pair, or connection may not cross train and test
boundaries. Repeated samples of the same scenario are grouped before splitting.

The split manifest records group keys, random seed when used, deterministic
sorting rules, inclusion counts, exclusion counts, and checksums. A candidate
rule is rejected when it succeeds only on workload or host groups represented
in training.

## Offline Learning Boundary

Permitted analysis begins with decision/regression trees, generalized additive
models, interaction analysis, change-point analysis, clustering, feature
importance, and partial-dependence review. Models discover regimes and propose
boundaries. They do not update runtime state or production thresholds.

A proposed rule must be rewritten as deterministic integer/fixed-point logic,
reviewed for feature leakage, replayed against held-out rows, adversarially
tested at boundaries and missing-value combinations, and assigned a stable
rule version. The runtime consumes only that reviewed rule version.

Online reinforcement learning, bandit exploration, production A/B exploration,
and self-updating thresholds are prohibited.

## Retention And Supersession

Datasets, rejected transforms, rejected models, and rejected rules remain
addressable by ID and checksum. A correction creates a new dataset version and
records `supersedes`; it does not edit prior rows. Evidence roots from the July
2026 experiments remain source references even when later permanent campaigns
supersede their schema.
