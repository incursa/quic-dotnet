# Adaptive Runtime Evidence Validation And Dataset Materialization

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
v12 as an application-datagram-transport delta composed with the complete v11
placement projection and v10 base projection,
actor raw v4, backpressure raw v1, packet-flush raw v1, and
receive-delivery raw v1, and writes five append-only raw JSONL streams,
semantic validation, and a checksum manifest v13. Semantic
validation requires matching
connection-observation, receive-credit, post-service boundary, and Stage 1
epoch keys; monotonic unique connection epochs; exactly four Stage 1 axis
records plus one `buffer_copy_coalescing` and one `adaptive_backpressure`
record plus one `packet_flush_cadence` and one `receive_delivery_quantum`
record plus one immutable `connection_shard_placement` and one
`application_datagram_batch_transport` record per row; no more than one
non-legacy applied axis across receive credit, Stage 1, buffer coalescing,
backpressure, packet flush, receive delivery, connection placement, and
application datagram transport;
one nonzero placement handle, one valid applied shard, and stable placement
identity across every source-scoped connection epoch;
stable transport configuration, a nonzero socket-capability epoch, consistent
decision and socket-call partitions, and accepted bytes no greater than
submitted bytes;
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
