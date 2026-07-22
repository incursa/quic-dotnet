# Adaptive Runtime Evidence Validation And Dataset Materialization

This directory contains the local validation gate for adaptive-runtime policy
campaign results plus the measurement-only catalog and offline dataset
materialization scripts. It does not train a model, submit a ProtocolLab job,
or provide runtime controller inputs.

Validate one or more result documents and their joined epoch rows from the
repository root:

```powershell
./eng/adaptive-runtime/Test-AdaptiveRuntimePolicyEvidence.ps1 `
  -LocalResultPath ./path/to/local-result.json `
  -EpochDatasetPath ./path/to/epoch-row.json
```

The command validates each document against the versioned schema in
`schemas/`, checks unique result run IDs, requires every epoch row to join to a
result by run/campaign/cell identity, and verifies that rule, observation, and
result-schema versions agree across the join. Local results must include a
checksum inventory, and source, sample, target-attribution, summary, and epoch
artifacts must resolve through that inventory with matching SHA-256 values. It
also requires
`workloadAnalysisOnly.excludedFromProductionFeatures` to remain true.

The command emits a machine-readable
`adaptive-runtime-policy-evidence-validation-v1` summary and exits nonzero on
any schema or join failure. Input files are read-only. Negative, noisy,
excluded, and failed campaign rows remain in their source evidence set.

Materialize the measurement-only catalog metadata for the known adaptive seams:

```powershell
./eng/adaptive-runtime/New-AdaptiveRuntimePolicyCatalog.ps1 `
  -OutputPath ./.artifacts/adaptive-runtime/catalog/policy-catalog.json
```

The catalog records all currently known seams as review metadata while keeping
`receive_credit_publication` as the only executable measurement seam in this
v1 substrate. Every catalog entry remains seam-local, versioned,
`activationAuthorized = false`, and non-authoritative for runtime behavior.

Build the deterministic raw -> normalized -> curated -> split chain from
validated local results and epoch rows:

```powershell
./eng/adaptive-runtime/Invoke-AdaptiveRuntimeDatasetPipeline.ps1 `
  -LocalResultPath ./tests/fixtures/adaptive-runtime-policy/local-result.shadow.checksum.example.json `
  -EpochDatasetPath ./tests/fixtures/adaptive-runtime-policy/epoch-row.shadow.checksum.example.json `
  -OutputRoot ./.artifacts/adaptive-runtime/pipeline-example
```

The pipeline validates the raw inputs before it creates the append-only output
root, emits a versioned catalog when one is not supplied, preserves null
derived metrics as null, retains unmatched results/rows with explicit reason
codes, and writes schema-valid:

- `catalog/policy-catalog.json`
- `normalized/normalized-dataset.json`
- `curated/curated-manifest.json`
- `split/split-manifest.json`

The standalone validator rejects unmatched epoch rows by default. The dataset
pipeline invokes its explicit retention mode so schema-valid unmatched rows
remain addressable under `unmatchedEpochRows` with reason codes while every
other integrity failure still blocks materialization. Counterfactual keys also
include the declared repetition protocol and a SHA-256 key over the complete,
property-sorted pre-decision observation vector; rows from different protocols
or observation regimes are therefore not silently grouped together.
Each normalized epoch row also retains a `sampleScopedOutcomes` join containing
the checksum-backed sample throughput, p95 latency, buffer-pool measurements,
and explicit availability of managed-memory and fairness outcomes. The block is
marked `scope = sample` because its values repeat across the sample's epoch rows
and must not be treated as independent epoch observations.

The split stage blocks rather than inventing train/validation/test assignments
when complete host-fingerprint and workload-family holdouts cannot be satisfied
honestly. The canonical illustrative fixture therefore produces
`status = insufficient_group_diversity` because it contains only one host and
one workload family.

Run one permanent forced-policy A/B/B/A or B/A/A/B local cell with the
source-backed raw QUIC ProtocolLab harness:

```powershell
./eng/adaptive-runtime/Invoke-AdaptiveRuntimePolicyLocalCell.ps1 `
  -CampaignId adaptive-receive-credit-20260721 `
  -CellId duplex-64kb-x1-s16 `
  -SequenceProtocol ABBA `
  -PolicyA legacy_current `
  -PolicyB read_dominant_batch `
  -ScenarioId quic.transport.duplex-streams-peer-matrix `
  -TrafficShape duplex `
  -AccountingMode fixed_per_stream `
  -PayloadBytes 65536 `
  -Connections 1 `
  -StreamsPerConnection 16
```

The runner builds the internal campaign host once, freezes and rechecks the
host and runtime hashes for every treatment, forwards the forced mode only
through the friend-assembly campaign host, verifies the host-reported mode and
effective workload shape, retains every sample, and emits a schema-valid v1
result, manifest, raw ProtocolLab artifacts, commands, and checksum inventory
under `.artifacts/adaptive-runtime/<campaignId>/<cellId>`. Host/process
counters are captured for every sample so forced-policy evidence keeps a
pressure artifact by default. The local result also retains per-sample target
attribution proving root, resolved, measured, and counter PID alignment, plus
the retained runner artifacts used for that proof. It populates the explicit
`bufferPoolRentedBytes` and `bufferPoolOutstandingPeakBytes` measurements only
from retained `quic-buffer-pool-summary.json` metrics. Generic managed-allocation,
peak-retained-memory, and stream-fairness outcomes remain null or unassessed;
request-level result latency is not relabeled as stream fairness. Per-epoch
completion and memory outcomes remain null because the contract does not claim
same-connection phase-local attribution. A single-cell
result is diagnostic and cannot authorize activation or rack-lab submission.

The local classifier is conjunctive. Known throughput, p95, or peak outstanding
buffer-pool regressions beyond five percent retain a negative result. It cannot
emit `accepted_local` until managed-allocation and true stream-fairness evidence
are also populated, so a throughput-only win remains neutral.

Run a deterministic higher-count measurement schedule with the same permanent
cell runner:

```powershell
./eng/adaptive-runtime/Invoke-AdaptiveRuntimePolicyLocalSchedule.ps1 `
  -CampaignId adaptive-receive-credit-varied-20260721 `
  -ScheduleProfile balanced
```

The `balanced`, `connection_first`, and `stream_first` profiles run the same
bounded existing ProtocolLab scenarios in different declared orders. The
default set covers 16 simultaneous one-stream connections, one and four
connections with 16 streams per connection, and one connection with 100
streams. A/B/B/A and B/A/A/B alternate by cell. `-IncludeStress` appends
32-connection and four-by-100-stream cells; those remain stress-only inputs to
review, not regression or promotion gates.

The schedule builds and freezes the campaign host once, writes an immutable
`measurement-schedule.json`, invokes the append-only local-cell contract for
each entry, and records every attempt separately. Use `-Resume` after an
interruption; completed cell results are retained and skipped only after their
frozen binary hashes match. These are measurement schedules, not alternative
production runtime schedulers, and they do not authorize `active_internal`,
online learning, or ProtocolLab submission.

Every schedule also writes a schema-valid `phase-transition-schedule.json`
with stable phase IDs and exact command lineage. The execution model for
metrics collection remains an independent-cell sequence. The recovery return
phase is declared as `same_connection_probe`, and non-dry-run schedules now
retain a separate `same-connection-phase-execution.json` proof produced by
`Invoke-AdaptiveRuntimeSameConnectionPhaseExecutor.ps1`. That helper preserves
one real QUIC connection across the few-stream baseline, many-stream burst,
and few-stream recovery return. The proof artifact is retained beside the
schedule so resume comparisons can keep the schedule contract deterministic.

Capture one behavior-neutral shadow sample with the same permanent runner by
adding `-ShadowOnly`. The runner applies `legacy_current`, asks the internal
controller only for a recommendation, enables one-second host/process counters,
and exports:

- the authoritative raw host stream as `adaptive-runtime-epochs.raw.jsonl`;
- one schema-valid file per connection epoch under `epoch-rows/`;
- a schema/join validation summary in `evidence-validation.json`; and
- shadow epoch, transition, missing/stale, and reason counts in
  `local-result.json`.

Every forced-policy sample also retains `counters-summary.json` as the result's
pressure artifact, which keeps `environment.pressureArtifactPath` populated in
the local result. The shadow sample retains the same
`counters-summary.json` pressure artifact. Because target and generator still
share one developer host, this extra evidence does not upgrade either health
classification above `limited`; it exists to make noise and queue-pressure
review concrete before any rerun or rack-lab eligibility decision.

The raw host contract contains only a run-local connection pseudonym, the
bounded runtime observation, and the immutable shadow snapshot. Workload
identity, provenance, correctness, and analysis-exclusion fields are joined by
the runner outside the transport. `transformation.outputSha256` is the SHA-256
of the canonical row with that field filled by 64 zeroes, avoiding a
self-referential file hash while keeping the transformation payload
independently reproducible.

Forced cells use the same epoch capture path and preserve the actual forced
policy on each row while recording the controller's recommendation as the
shadow recommendation. The summary result records whether a single forced
policy applied across the captured epochs; mixed A/B cells keep that field
`not_applicable` and rely on the epoch rows for the per-sample policy record.

Canonical schema examples live under
`tests/fixtures/adaptive-runtime-policy/`. Their identities and hashes are
illustrative and are not campaign evidence.
