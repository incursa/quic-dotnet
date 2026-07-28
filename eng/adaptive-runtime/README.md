# Adaptive Runtime Evidence Validation And Dataset Materialization

The correctness-only hardening entry points are
`Update-AdaptiveRuntimeExperimentHardeningFixtures.ps1`,
`Test-AdaptiveRuntimeExperimentHardening.ps1`, and
`New-AdaptiveRuntimeExperimentEvidenceProjection.ps1`. They regenerate and
validate additive v2 contracts from explicit immutable inputs. They do not
execute campaigns or authorize performance or active behavior.

This directory contains the local validation gate for adaptive-runtime policy
campaign results plus the measurement-only catalog and offline dataset
materialization scripts. It does not train a model or provide runtime
controller inputs. The ProtocolLab campaign driver is plan-only by default and
submits jobs only when its explicit `-Execute` switch is supplied.

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
any schema or join failure. Each append-only artifact path is hashed once per
invocation while every repeated join is checked against the verified digest;
the summary reports `uniqueArtifactHashCount`. Input files are read-only.
Negative, noisy, excluded, and failed campaign rows remain in their source
evidence set.

Validate the Stage 1 four-axis unified epoch and its separate construction,
packet-plan, actor-turn, and logical-write decision records:

```powershell
./eng/adaptive-runtime/Test-AdaptiveRuntimeStage1UnifiedEvidence.ps1 `
  -UnifiedEpochPath ./path/to/stage1-unified-epoch.json `
  -AxisDecisionPath ./path/to/stage1-axis-decisions.json
```

This gate accepts individual JSON objects, JSON arrays, or JSONL inputs and
validates every record against the versioned Stage 1 schemas. It then enforces
the semantic rules JSON Schema cannot express: the canonical four-axis order,
axis-specific closed policy values, at most one forced axis per epoch,
`legacy_current` on every unforced adjacent axis, forced/selected/applied
identity unless a named safety guard overrides it, shadow neutrality, exact
decision-boundary and latch identity, unique deterministic join keys, and
complete epoch-to-decision joins. Separate decision artifacts retain their own
source path and SHA-256 provenance; they are not relabeled as the unified epoch
artifact.

Validate the raw four-axis epoch emitted by the permanent raw QUIC host:

```powershell
./eng/adaptive-runtime/Test-AdaptiveRuntimeStage1RawEvidence.ps1 `
  -RawEpochPath ./.artifacts/adaptive-runtime/stage1-smoke/raw-unified-epochs.jsonl
```

The raw validator requires exactly the canonical four axis properties,
monotonic per-connection epochs, matching common decisions and policy
snapshots, at most one forced axis, and `LegacyCurrent` on every unforced
adjacent axis. An axis without an event remains present as missing and
unlatched; the later curated `epoch_summary` join keeps operation and plan keys
null rather than inventing an operation identity.

Export and validate the permanent joined receive-credit, Stage 1, actor, and
buffer raw rows:

```powershell
./eng/adaptive-runtime/Export-AdaptiveRuntimeUnifiedRawEpochs.ps1 `
  -HostLogPath ./path/to/campaign-host.stdout.log `
  -OutputDirectory ./.artifacts/adaptive-runtime/unified-raw-export
```

The exporter reads `QUIC_ADAPTIVE_RUNTIME_UNIFIED_EPOCH_JSON=`,
`QUIC_ACTOR_SERVICE_OBSERVATION_JSON=`,
`QUIC_ADAPTIVE_BACKPRESSURE_EVIDENCE_JSON=`, and
`QUIC_PACKET_FLUSH_CADENCE_EVIDENCE_JSON=`, and
`QUIC_RECEIVE_DELIVERY_QUANTUM_EVIDENCE_JSON=` records, validates unified raw
v13 as a congestion-profile delta composed with the complete v12 transport,
v11 placement, and v10 base projections,
actor raw v4, backpressure raw v1, packet-flush raw v1, and
receive-delivery raw v1, and writes five append-only raw JSONL streams,
semantic validation, and a checksum manifest v14. Semantic
validation requires matching
connection-observation, receive-credit, post-service boundary, and Stage 1
epoch keys; monotonic unique connection epochs; exactly four Stage 1 axis
records plus one `buffer_copy_coalescing` and one `adaptive_backpressure`
record plus one `packet_flush_cadence` and one `receive_delivery_quantum`
record plus one immutable `connection_shard_placement`, one
`application_datagram_batch_transport`, and one immutable
`congestion_pacing_profile` record per row; no more than one
non-legacy applied axis across receive credit, Stage 1, buffer coalescing,
backpressure, packet flush, receive delivery, connection placement, and
application datagram transport, and congestion profile;
one nonzero placement handle, one valid applied shard, and stable placement
identity across every source-scoped connection epoch;
stable transport configuration, a nonzero socket-capability epoch, consistent
decision and socket-call partitions, and accepted bytes no greater than
submitted bytes;
one legal congestion-profile decision, stable connection-lifetime profile
identity, legal initial congestion state, and an applied NewReno or CUBIC
controller matching the applied closed value;
configured buffer identity and bounded aggregate consistency; and exact
source-scoped `connectionKey + serviceSequence` coverage for every inclusive
actor summary range; and exact raw-to-epoch contender observation count,
maximum, and count-above-one aggregation plus accepted-connection-work
coverage, total, maximum, and positive-turn aggregation. Actor dispatch rows are
sample-scoped rather than epoch-independent. Missing, contradictory, invalid,
duplicate, orphan, and out-of-order actor records are rejected. Connection
Continuation assessment state and remaining-count pairs are validated per
producer, and complete, drained, scheduled, blocked, ready-after-yield, and
maximum-remaining epoch aggregates must match their raw dispatch members
exactly. Backpressure admission rows remain sample-scoped and must join by
exact source-scoped `connectionKey + operationSequence` membership in the
inclusive epoch range; operation, delayed, safety, fallback, and maximum
queue/capacity aggregates are recomputed from those raw members. Packet-flush
opportunity rows use the same source-scoped operation join and recompute
eligible, delayed, prompt, safety, fallback, maximum-payload, and maximum-queue
aggregates. Distinct epoch and sample counts prevent sample-scoped admission
or packet-opportunity records from being treated as epoch-independent
outcomes. Productive receive-delivery rows use the same exact source-scoped
operation join and recompute single-segment, completion, batched-credit,
safety, fallback, delivered-byte, source-segment, and bounded-maximum
aggregates. A pending count is never relabeled
continuation-ready unless its
closed state is `ReadyAfterCooperativeYield`. Connection keys are scoped to
their hashed source log because
separate host processes restart their connection counters. Supply
retained stderr logs as additional `-HostLogPath` values to preserve
unified and actor export-failure records. Any such record classifies the
export `invalid_contract` and causes a nonzero exit after the failure file and
manifest are retained.

Validate the separate buffer construction and terminal-release raw streams:

```powershell
./eng/adaptive-runtime/Test-AdaptiveRuntimeBufferLifetimeEvidence.ps1 `
  -CopyPath ./path/to/buffer-copy-operations.raw.jsonl `
  -ReleasePath ./path/to/buffer-release-evidence.raw.jsonl
```

The raw construction stream contains only lifetimes that promise terminal
release correlation; untracked operations remain in the fixed-field epoch
summary with explicit missing correlation. The validator applies the wrapper
and observation schemas independently, requires monotonic connection-local
construction and release sequences, joins only by exact
`connectionKey + operationSequence`, rejects duplicate or orphan releases, and
verifies that path and retained capacity survive the lifetime. Implemented
terminal-release paths are receive-segment delivery/reset and flow-control
retry request replacement, downstream copy, completion, cancellation,
terminal, disposal, or defensive recycle. Other buffer-copy paths continue to
report
`MissingTerminalReleaseCorrelation` and remain non-forceable.

The standalone validator remains strict about epoch-local exclusion flags.
The dataset pipeline uses the explicit
`-AllowLegacyResultLevelEnvironmentExclusions` compatibility gate for retained
campaigns created before result-level target/generator health was propagated
into every epoch row. The validation summary counts each tolerated legacy row;
the curated manifest still excludes it through the joined
`invalid_environment` result classification. Source rows are never rewritten
or silently promoted.

Materialize the measurement-only catalog metadata for the known adaptive seams:

```powershell
./eng/adaptive-runtime/New-AdaptiveRuntimePolicyCatalog.ps1 `
  -OutputPath ./.artifacts/adaptive-runtime/catalog/policy-catalog.json
```

The catalog records all currently known seams as review metadata.
`receive_credit_publication` and shadow-only
`application_send_turn_planning` now have separate runner-integrated
controller-epoch measurement paths. Forced
`application_send_turn_planning` retains its distinct construction-provenance
path and is never relabeled as shadow epoch evidence. Every catalog entry
remains seam-local, versioned,
`activationAuthorized = false`, and non-authoritative for runtime behavior.

## Experiment-control contract suite

The v1 experiment-control contract suite under
`eng/adaptive-runtime/experiment-control/` supersedes the measurement-only
policy catalog for new experiment planning. Its architecture is defined in
`docs/design/adaptive-runtime-experiment-control-architecture.md`, and its
eight strict schemas live under `schemas/`.

`adaptive-runtime-policy-catalog-v1.schema.json`,
`New-AdaptiveRuntimePolicyCatalog.ps1`, their fixtures, and retained evidence
remain valid and unchanged. The existing generator is a historical
compatibility producer; it is not a current capability resolver and must not
be used to authorize an executable experiment cell. No migration, relabeling,
or evidence rewrite is implied by the new suite.

Validate the canonical catalogs and the complete valid/invalid fixture corpus
without compiling or executing a plan:

```powershell
./eng/adaptive-runtime/Test-AdaptiveRuntimeExperimentControl.ps1
```

The validator performs schema, reference, duplicate, authorization,
canonical-serialization, and content-hash checks only. It does not build a
compiled execution manifest, run a campaign or transform, authorize
performance acceptance, or enable `active_internal`.

Validate and compile one immutable source plan into a deterministic
plan-validation result:

```powershell
./eng/adaptive-runtime/Compile-AdaptiveRuntimeExperimentPlan.ps1 `
  -PlanPath ./tests/fixtures/adaptive-runtime-experiment-plan-compiler/valid/batch-actuation.plan.json `
  -OutputPath ./.artifacts/adaptive-runtime/batch-actuation.validation.json
```

Run the complete focused compiler corpus, including valid, warning,
verification-only, inactive, capability-pending, blocked, preparation-only,
invalid-plan, invalid-validation, and invalid-manifest cases:

```powershell
./eng/adaptive-runtime/Test-AdaptiveRuntimeExperimentPlanCompiler.ps1
```

The compiler reports planning eligibility and expected behavior only. It does
not report runtime operation eligibility or materialize actual behavior.
Current send-composition interaction cells remain capability-pending.

After the plan and validation are committed, the worktree is clean, and a
focused build succeeds, create a dry-run manifest by supplying the exact
binary, runner version, and resolved capabilities:

```powershell
./eng/adaptive-runtime/New-AdaptiveRuntimeCompiledExecutionManifest.ps1 `
  -PlanPath <committed-plan.json> `
  -ValidationPath <committed-validation.json> `
  -BinaryPath <focused-build-binary> `
  -RunnerPath ./eng/adaptive-runtime/Compile-AdaptiveRuntimeExperimentPlan.ps1 `
  -RunnerVersion 1.0.0-dry-run `
  -ResolvedCapability adaptive_runtime_internal_forced_mode=available `
  -OutputPath <dry-run-manifest.json>
```

Manifest creation hashes and records provenance. It does not execute a
benchmark, campaign, policy cell, transform, or runtime mechanism.

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
The separate closed `modelFeatures` block retains only bounded pre-decision
runtime observations suitable for offline regime discovery. Scenario,
payload, requested concurrency, peer, URL, and application identity remain
outside that block and cannot become production controller inputs.
Raw epoch `rowId` values are scoped to their source run. Normalized rows preserve
that value as `sourceRowId` and use `campaignId|runId|sourceRowId` as the stable,
dataset-wide `rowId`, so independent append-only campaigns can be combined
without rewriting their retained evidence.
Both fields remain optional at the persisted v1 schema boundary so previously
retained v1 normalized datasets remain valid; the current transformation emits
them and its requirement tests enforce their presence and semantics.

The split stage blocks rather than inventing train/validation/test assignments
when complete host-fingerprint and workload-family holdouts cannot be satisfied
honestly. The canonical illustrative fixture therefore produces
`status = insufficient_group_diversity` because it contains only one host and
one workload family.

Create the versioned, axis-specific descriptive analysis handoff only after
the normalized, curated, and split artifacts exist:

```powershell
./eng/adaptive-runtime/Measure-AdaptiveRuntimeApplicationSendTurnDataset.ps1 `
  -NormalizedDatasetPath ./.artifacts/adaptive-runtime/dataset/normalized/normalized-dataset.json `
  -CuratedManifestPath ./.artifacts/adaptive-runtime/dataset/curated/curated-manifest.json `
  -SplitManifestPath ./.artifacts/adaptive-runtime/dataset/split/split-manifest.json `
  -OutputPath ./.artifacts/adaptive-runtime/analysis/application-send-turn-analysis.json `
  -AnalysisId application-send-turn-analysis-v1
```

The adapter validates each artifact and the normalized-to-curated-to-split
checksum chain, requires exact unique row-ID coverage, rejects policy values
outside the closed `application_send_turn_planning` set, and audits forbidden
production features. Feature distributions use only curated included epochs.
Sample throughput, p95 latency, and buffer-pool outcomes are deduplicated by
sample and labeled `descriptive_only_not_epoch_independent`; they are not
treated as thousands of independent epoch outcomes. Insufficient host or
workload diversity emits `ruleProposal.status = holdout_blocked`, a null
candidate rule, and `activeInternalAuthorized = false`.

Summarize forced `legacy_current` versus `conservative` cell medians without
relabelling them as epoch-independent observations:

```powershell
./eng/adaptive-runtime/Measure-AdaptiveRuntimeApplicationSendTurnCounterfactuals.ps1 `
  -LocalResultPath ./path/to/c1/local-result.json,./path/to/c24/local-result.json `
  -OutputPath ./.artifacts/adaptive-runtime/analysis/send-turn-counterfactuals.json `
  -AnalysisId application-send-turn-counterfactuals-v1
```

The versioned report retains every input result and classification, the exact
result and binary hashes, sequence protocol, workload identity as
analysis-only metadata, construction-row counts, median throughput and p95
deltas, and the maximum within-treatment relative range. Upload-only server
cells remain present but are marked as not exercising server application
sends. `invalid_contract`, `invalid_environment`, `failed_correctness`, and
`stress_only` cells remain excluded with their original classification.
The report labels cell outcomes `cell_median_not_epoch_independent`, recommends
continued evidence generation, and always leaves
`activeInternalAuthorized = false`.

Create a permanent controller-owned, independent-host ProtocolLab campaign
plan for the current send-turn axis without contacting the controller:

```powershell
./eng/adaptive-runtime/Invoke-AdaptiveRuntimeProtocolLabCampaign.ps1 `
  -CampaignId application-send-turn-shadow-20260724-r001 `
  -ControllerUri http://10.10.99.176:5088 `
  -CampaignKind shadow `
  -Sequence ABBA `
  -ProtocolLabRoot ../protocol-lab `
  -ProtocolLabExecutionRoot ../protocol-lab-internal
```

The schema-valid plan freezes every adjacent axis at `legacy_current`, uses
distinct `legacy_current` and `shadow` package versions, requests
controller-owned `isolated-pair` placement, records no explicit worker ID, and
emits four ordered cell commands plus a checksum inventory under
`.artifacts/adaptive-runtime/protocol-lab/<campaignId>`. Use
`-CampaignKind forced_counterfactual` for the independently forceable
`legacy_current` versus `conservative` identity campaign. Both identities
retain the current legal scheduler in this measurement-only slice.

After reviewing the plan, commit the package-source slice and add `-Execute`.
Execution refuses a dirty worktree, snapshots the live controller registry,
runs the four jobs sequentially in the declared ABBA or BAAB order, and records
each package, upload, job result, SUT/load node, physical-host identity, and
topology classification. A completed job remains
`completed_unclassified` until dataset ingestion applies correctness,
environment, workload, and policy gates. Repeated physical-host pairs remain
`host_rotation_unverified`; shared physical hosts are
`environment_invalid`. The driver never authorizes `active_internal`.

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

The same runner can execute the independent forced-only construction campaign
for `application_send_turn_planning`:

```powershell
./eng/adaptive-runtime/Invoke-AdaptiveRuntimePolicyLocalCell.ps1 `
  -CampaignId adaptive-send-turn-20260723 `
  -PolicyAxis application_send_turn_planning `
  -SequenceProtocol ABBA `
  -PolicyA legacy_current `
  -PolicyB conservative `
  -ScenarioId quic.transport.duplex-streams-peer-matrix `
  -TrafficShape duplex `
  -AccountingMode fixed_per_stream `
  -PayloadBytes 65536 `
  -Connections 1 `
  -StreamsPerConnection 16
```

That path sets only the internal application-send-turn force environment
variable, requires the host-reported forced identity, retains the raw
`application-send-turn-policy.raw.jsonl` record stream for each sample, and
exports checksum-joined construction rows. It never relabels receive-credit
epochs and does not authorize active policy selection or a ProtocolLab
submission. The raw host now exposes separate `observe_only` and `shadow`
record streams. Convert a retained stream independently with:

```powershell
./eng/adaptive-runtime/Convert-AdaptiveRuntimeApplicationSendTurnEvidence.ps1 `
  -RawEvidencePath ./path/to/application-send-turn-evidence.raw.jsonl `
  -OutputDirectory ./.artifacts/adaptive-runtime/send-turn-epoch-export `
  -DatasetId send-turn-dataset-v1 `
  -CampaignId send-turn-campaign-v1 `
  -RunId send-turn-run-v1 `
  -CellId send-turn-cell-v1 `
  -SampleId send-turn-sample-v1 `
  -BenchmarkSha256 <64-hex-digest> `
  -RuntimeSha256 <64-hex-digest> `
  -HostFingerprint <pseudonymous-host-fingerprint> `
  -CorrectnessFlagsJson '{"payloadValid":true,"protocolValid":true,"timedOut":false,"ownershipValid":true,"terminalValid":true,"violationCodes":[]}' `
  -ScenarioId quic.transport.stream-throughput.1mb `
  -TrafficShape upload `
  -AccountingMode fixed_per_stream `
  -ArrivalPattern sustained `
  -PayloadBytes 1048576 `
  -Connections 1 `
  -StreamsPerConnection 1 `
  -WarmupMicros 0 `
  -MeasurementMicros 1000000
```

The converter validates the closed raw schema and snapshot versions, retains
the source SHA-256, and emits schema-valid interval rows plus a checksum
manifest. The last interval is retained with `terminal_partial_epoch`; missing
axis-external signals remain null. With
`-PolicyAxis application_send_turn_planning -ShadowOnly`, the permanent runner
captures this raw stream per sample, invokes the converter, adds the completed
rows and export manifest to the cell checksum inventory, and validates each
row's result, sample, and raw-source join. Standalone fixture output and a dry
run remain verification evidence rather than campaign evidence; an executed
schema-valid cell must still be classified and retained before it can enter a
campaign dataset.

The local classifier is conjunctive. Known throughput, p95, or peak outstanding
buffer-pool regressions beyond five percent retain a negative result. It cannot
emit `accepted_local` until managed-allocation and true stream-fairness evidence
are also populated, so a throughput-only win remains neutral.

Run a same-binary disabled-versus-observe-only A/B/B/A neutrality cell for the
send-turn axis with:

```powershell
./eng/adaptive-runtime/Invoke-AdaptiveRuntimePolicyLocalCell.ps1 `
  -CampaignId adaptive-send-turn-observation-neutrality-20260724 `
  -CellId duplex-64kb-x1-s16-neutrality `
  -PolicyAxis application_send_turn_planning `
  -ObservationNeutrality `
  -SequenceProtocol ABBA `
  -ScenarioId quic.transport.duplex-streams-peer-matrix `
  -TrafficShape duplex `
  -AccountingMode fixed_per_stream `
  -PayloadBytes 65536 `
  -Connections 1 `
  -StreamsPerConnection 16
```

Treatment A leaves the application-send observation environment variable
unset and verifies that the host emits neither observation evidence nor forced
construction provenance. Treatment B selects `observe_only`, requires
schema-valid recommendation-free records, and exports only those records to
epoch rows. Both treatments apply `legacy_current`; receive credit and every
other axis remain `legacy_current`. The local result records mode
`observe_only`, retains the ABBA sample outcomes and counters, and can classify
a known throughput, p95, or peak outstanding buffer-pool regression as
`negative_retained`. It remains same-host diagnostic evidence and cannot
authorize activation.

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

- the authoritative receive-credit raw stream as
  `adaptive-runtime-epochs.raw.jsonl`, or the axis-specific send-turn stream as
  `application-send-turn-evidence.raw.jsonl`;
- one schema-valid file per receive-credit connection epoch under
  `epoch-rows/`, or per send-turn interval under
  `send-turn-epoch-rows/`;
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

## Experiment Runtime Evidence

The first correctness-only runtime/evidence slice is validated with:

```powershell
pwsh -NoProfile -File eng/adaptive-runtime/Test-AdaptiveRuntimeExperimentRuntimeEvidence.ps1
```

To regenerate the deterministic fixture corpus and checked-in expected
materialization/projection documents:

```powershell
pwsh -NoProfile -File eng/adaptive-runtime/Update-AdaptiveRuntimeExperimentRuntimeEvidenceFixtures.ps1
pwsh -NoProfile -File eng/adaptive-runtime/Test-AdaptiveRuntimeExperimentRuntimeEvidence.ps1 -UpdateExpectedOutputs
```

The command validates the three strict operation/materialization/projection
schemas, resolves the effective-behavior catalog by exact hash, recomputes
aggregates, proves deterministic canonical bytes and hashes, and checks 21
expected-invalid closed codes. It supports only
`application_send_batch_formation` and `buffer_copy_coalescing`; it is not a
campaign runner and authorizes neither measurement nor active behavior.

## Experiment evidence-integrity closeout

The additive closeout contracts preserve every v1 and v2 document while making
outcome derivation, release correlation, classification targets, aggregate
accounting, and projection joins exact:

```powershell
pwsh -NoProfile -File eng/adaptive-runtime/Update-AdaptiveRuntimeExperimentEvidenceIntegrityCloseoutFixtures.ps1
pwsh -NoProfile -File eng/adaptive-runtime/Test-AdaptiveRuntimeExperimentEvidenceIntegrityCloseout.ps1
```

The regression validates six additive schemas, fifteen explicit immutable
projection inputs, all nine catalog result-to-outcome mappings, nine invalid
evidence documents, eight invalid classification documents, all 66 unordered
classification pairs, and seven invalid projection substitutions. The general
projection entry point is
`New-AdaptiveRuntimeExperimentEvidenceProjectionV3.ps1`; it requires every
input path explicitly, validates hashes and cross-document identities, and
recomputes behavior and outcome materializations before accepting them.

These scripts are offline correctness tooling. They do not read catalogs on a
runtime path, launch a workload, migrate an axis, authorize measurement, or
enable active policy behavior.

## Reviewed send-composition correctness

The original single-axis candidates remain preserved under
`tests/fixtures/adaptive-runtime-independent-actuation-proof/`. Fresh
production-selector captures and independent passed reviews for the exact
`single_eligible` and `memory_conservative` values are retained under
`tests/fixtures/adaptive-runtime-send-composition-correctness/single-axis/`.
The canonical family catalog references only those passed review records.

The exact manifest-bound correctness interaction, its 15 immutable inputs,
catalog-derived materializations, projection, proof, and independent review
live under
`tests/fixtures/adaptive-runtime-send-composition-correctness/interaction/`.
Validate the complete milestone with:

```powershell
pwsh -NoProfile -File eng/adaptive-runtime/Test-AdaptiveRuntimeIndependentActuationProof.ps1
pwsh -NoProfile -File eng/adaptive-runtime/Test-AdaptiveRuntimeSendCompositionCorrectness.ps1
```

The interaction regression validates ten primary content-hashed documents,
11 composite-keyed operations, four exact terminal releases, 11 behavior
aggregates, five outcome aggregates, the deterministic 15-input projection,
the passed independent interaction review, and 28 adversarial cases. The
runtime capability is internal, fixed-field, exact-cell-only, and denied by
default. It is not reachable through public production configuration.
Active behavior remains unauthorized.

## Send-composition offline performance

The only released measurement scope is the reviewed four configured cells for
`application_send_batch_formation` and `buffer_copy_coalescing`. Validate and
rebuild the retained external evidence with:

```powershell
pwsh -NoProfile -File eng/adaptive-runtime/Test-AdaptiveRuntimeSendCompositionPerformance.ps1 `
  -ManifestPath <evidence-root>\compiled-manifest.json `
  -RawEvidencePath (Get-ChildItem <evidence-root>\raw\*.json).FullName
pwsh -NoProfile -File eng/adaptive-runtime/Test-AdaptiveRuntimeSendCompositionPerformancePilot.ps1 `
  -EvidenceRoot <evidence-root>
pwsh -NoProfile -File eng/adaptive-runtime/New-AdaptiveRuntimeSendCompositionPerformanceProjection.ps1 `
  -EvidenceRoot <evidence-root>
pwsh -NoProfile -File eng/adaptive-runtime/Measure-AdaptiveRuntimeSendCompositionPerformance.ps1 `
  -EvidenceRoot <evidence-root>
pwsh -NoProfile -File eng/adaptive-runtime/Test-AdaptiveRuntimeSendCompositionPerformanceAdversarial.ps1 `
  -EvidenceRoot <evidence-root>
```

Manifest v2 preserves counterbalanced execution order with an explicit
`execution_sequence` while retaining the sorted cell set for membership
validation. The completed 160-run campaign produced 66 eligible, 18
expected-equivalent, 40 inactive-control, and 36 activation-missing runs. No
holdout context supplied all four eligible/equivalent cells, so the reviewed
outcome is `measurement_completed_more_context_required`. No shadow selector
or runtime selection rule was added.

The completed holdout extension is generated and validated with:

```powershell
pwsh -NoProfile -File eng/adaptive-runtime/Update-AdaptiveRuntimeSendCompositionPerformanceHoldoutCampaign.ps1
pwsh -NoProfile -File eng/adaptive-runtime/Test-AdaptiveRuntimeSendCompositionPerformanceHoldoutExtension.ps1
pwsh -NoProfile -File eng/adaptive-runtime/Test-AdaptiveRuntimeSendCompositionPerformanceHoldoutResults.ps1 `
  -EvidenceRoot <extension-evidence-root>
```

It preserves the reviewed cells, proofs, thresholds, authorization boundary,
and training contexts while replacing the non-activating holdouts with three
predeclared upload contexts at new continuous workload points. The completed
176-run extension produced complete activation-qualified holdout blocks,
rebuilt projection and analysis bytes identically, and concluded
`measurement_completed_no_stable_rule`. No selector was emitted; shadow,
active, performance-acceptance, and production authorization remain false.

## Implemented-factor onboarding

The additive factor-onboarding contracts cover exactly
`oversized_write_admission_quantum` and `queued_send_burst_budget`:

```powershell
pwsh -NoProfile -File eng/adaptive-runtime/Test-AdaptiveRuntimeFactorOnboarding.ps1
dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj `
  -c Release --no-build `
  --filter FullyQualifiedName~REQ_QUIC_CRT_0238
```

The canonical planning spaces contain 12 explicit
`send_admission_composition` cells and two explicit
`queued_send_burst_correctness` cells. These small spaces are exhaustively
enumerated; no covering-array generator is implemented. Cell-space v2 counts
the baseline in `distinct_effective_cell_count_including_baseline` (5
admission, 2 queued) and separately counts nonlegacy behavior-distinct
treatment values (4 admission, 1 queued). Its primary partition counts are
disjoint, while explicitly named annotation counts may overlap. The six
oversized/downstream same-operation cases are
`operation_local_noncoactivation` annotations, not workload-cell exclusions.
The three new actuation proofs are candidate-only, no new reviewed-proof
metadata exists, and every multi-axis cell involving an onboarded factor
remains blocked. Packet-flush onboarding, performance measurement, active
behavior, and production authorization remain outside this checkpoint.

Runtime-derived replacement candidates are captured and validated with:

```powershell
$sourceCommit = git rev-parse HEAD
$binary = Resolve-Path src/Incursa.Quic/bin/Release/net10.0/Incursa.Quic.dll
$env:INCURSA_ADAPTIVE_RUNTIME_FACTOR_RUNTIME_CAPTURE_ROOT = `
  'C:\shared\temp\quic-dotnet\runtime-proof-capture\raw'
$env:INCURSA_ADAPTIVE_RUNTIME_FACTOR_SOURCE_COMMIT = $sourceCommit
$env:INCURSA_ADAPTIVE_RUNTIME_FACTOR_BINARY_SHA256 = `
  (Get-FileHash $binary -Algorithm SHA256).Hash.ToLowerInvariant()
$env:INCURSA_ADAPTIVE_RUNTIME_FACTOR_CAPTURE_SESSION_ID = `
  'runtime_capture.factor_proof'

dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj `
  -c Release --no-build `
  --filter FullyQualifiedName~RuntimeProofHarnessExportsOnlySinkEmittedMechanismFacts

pwsh -NoProfile -File `
  eng/adaptive-runtime/New-AdaptiveRuntimeFactorActuationProofCandidates.ps1 `
  -RuntimeCaptureRoot $env:INCURSA_ADAPTIVE_RUNTIME_FACTOR_RUNTIME_CAPTURE_ROOT `
  -BinaryPath $binary

pwsh -NoProfile -File `
  eng/adaptive-runtime/Test-AdaptiveRuntimeRuntimeProofCapture.ps1
```

The adapter accepts actual bounded sink exports only. Capture v3 carries
logical-write request/continuation identity or actor-turn/wake-generation
identity as applicable, and the regression recomputes behavior, outcome, and
projection hashes. `single_fragment` and `single_datagram` have no failed proof
assertions. `bounded_multi_fragment` remains an honest candidate with
`shadow_recommendation_value_mismatch`: the current production shadow rule
recommends `single_fragment`, and this evidence-only workflow does not alter
selection semantics.

## Reviewed admission-family correctness

The runtime-derived candidates were independently reviewed. `single_fragment`
and `single_datagram` passed and were promoted one at a time;
`bounded_multi_fragment` remains blocked and unpromoted on
`shadow_recommendation_value_mismatch`. Validate the reviews and sequential
catalog updates with:

```powershell
pwsh -NoProfile -File eng/adaptive-runtime/Test-AdaptiveRuntimeRuntimeProofReview.ps1
pwsh -NoProfile -File eng/adaptive-runtime/Test-AdaptiveRuntimeProofPromotion.ps1
```

The exact `send_admission_composition_correctness_v1` plan authorizes only A0
through A7 across reviewed `single_fragment`, `single_eligible`, and
`memory_conservative` levels. Compile and validate that finite authorization,
then validate the retained per-cell evidence with:

```powershell
pwsh -NoProfile -File eng/adaptive-runtime/Test-AdaptiveRuntimeAdmissionCorrectnessAuthorization.ps1
pwsh -NoProfile -File eng/adaptive-runtime/Test-AdaptiveRuntimeAdmissionCorrectness.ps1
```

Each cell retains 18 immutable documents, including the correctness
authorization, runtime and host identity, production and harness binary
bindings, three operation records, exactly one buffer release, catalog-derived
behavior and outcome materializations, correctness-only metrics, a
deterministic analytical projection, and a cell result. All eight results are
`correctness_passed`. This capability is exact-cell-only, internal, and denied
by default; it authorizes neither performance nor active behavior.

## Admission-family offline performance readiness

The reviewed admission family now has an additive factor-cell-space v3 bound
to experiment-family catalog v5. It preserves all 12 configured cells,
classifies exactly A0 through A7 as the reviewed exhaustive subset, and keeps
all four `bounded_multi_fragment` cells blocked on
`shadow_recommendation_value_mismatch`. The space is far below the effective
cell trigger of 65, so covering arrays remain disabled and no generator is
implemented.

Regenerate and validate the current readiness contracts with:

```powershell
pwsh -NoProfile -File eng/adaptive-runtime/Update-AdaptiveRuntimeAdmissionPerformanceFixtures.ps1
pwsh -NoProfile -File eng/adaptive-runtime/Test-AdaptiveRuntimeAdmissionPerformanceReadiness.ps1
```

Compile the no-timing manifest outside the repository with:

```powershell
pwsh -NoProfile -File eng/adaptive-runtime/Compile-AdaptiveRuntimeAdmissionPerformanceCampaign.ps1 `
  -OutputPath C:\shared\temp\quic-dotnet\admission-performance\dry-run-manifest.json
```

`send_admission_composition_performance_v1` is internal, exact-cell-only, and
manifest-bound. It cannot join `bounded_multi_fragment`, nonlegacy queued
burst, a fourth axis, a correctness token, the prior two-axis performance
token, or public production configuration. The retained dry run still
compiles all eight cells with timing disabled and produces no performance
number.

The additive rack pilot selects exactly A0, A3, A4, and A7, executes them in
A0, A4, A3, A7 order, and uses the package-backed raw QUIC lane with
controller-owned `isolated-pair` placement. Compile and exercise its plan-only
path with:

```powershell
pwsh -NoProfile -File eng/adaptive-runtime/Test-AdaptiveRuntimeAdmissionPerformancePilot.ps1

pwsh -NoProfile -File eng/adaptive-runtime/Invoke-AdaptiveRuntimeAdmissionPerformancePilot.ps1 `
  -OutputRoot C:\shared\temp\quic-dotnet\admission-performance-pilot
```

Only an explicit `-Execute` submits rack work. Performance acceptance, active
behavior, and production activation remain false. The four-cell pilot can
measure the oversized seam and the combined batch-plus-buffer effect; it
cannot attribute batch and buffer independently.
