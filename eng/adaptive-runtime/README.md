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

Canonical schema examples live under
`tests/fixtures/adaptive-runtime-policy/`. Their identities and hashes are
illustrative and are not campaign evidence.
