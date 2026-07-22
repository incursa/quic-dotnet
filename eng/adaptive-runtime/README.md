# Adaptive Runtime Evidence Validation

This directory contains the local validation gate for adaptive-runtime policy
campaign results and offline epoch rows. It does not train a model, submit a
ProtocolLab job, or provide runtime controller inputs.

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
result-schema versions agree across the join. It also requires
`workloadAnalysisOnly.excludedFromProductionFeatures` to remain true.

The command emits a machine-readable
`adaptive-runtime-policy-evidence-validation-v1` summary and exits nonzero on
any schema or join failure. Input files are read-only. Negative, noisy,
excluded, and failed campaign rows remain in their source evidence set.

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
pressure artifact by default. A single-cell result is diagnostic and cannot
authorize activation or rack-lab submission.

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

Capture one behavior-neutral shadow sample with the same permanent runner by
adding `-ShadowOnly`. The runner applies `legacy_current`, asks the internal
controller only for a recommendation, enables one-second host/process counters,
and exports:

- the authoritative raw host stream as `shadow-epochs.raw.jsonl`;
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

Canonical schema examples live under
`tests/fixtures/adaptive-runtime-policy/`. Their identities and hashes are
illustrative and are not campaign evidence.
