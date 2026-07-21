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
  -CellId sustained-upload-1kb-c16 `
  -SequenceProtocol ABBA `
  -PolicyA legacy_current `
  -PolicyB read_dominant_batch `
  -ScenarioId quic.transport.sustained-stream.16384x1kb `
  -TrafficShape upload `
  -AccountingMode fixed_total `
  -PayloadBytes 1024 `
  -Connections 1 `
  -StreamsPerConnection 16
```

The runner builds the internal campaign host once, freezes and rechecks the
host and runtime hashes for every treatment, forwards the forced mode only
through the friend-assembly campaign host, verifies the host-reported mode and
effective workload shape, retains every sample, and emits a schema-valid v1
result, manifest, raw ProtocolLab artifacts, commands, and checksum inventory
under `.artifacts/adaptive-runtime/<campaignId>/<cellId>`. A single-cell result
is diagnostic and cannot authorize activation or rack-lab submission.

Canonical schema examples live under
`tests/fixtures/adaptive-runtime-policy/`. Their identities and hashes are
illustrative and are not campaign evidence.
