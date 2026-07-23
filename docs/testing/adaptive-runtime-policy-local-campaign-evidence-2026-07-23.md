# Application-Send Turn Local Campaign Evidence — 2026-07-23

Status: retained local evidence only. The first three cells are
`invalid_environment`; the corrected fourth cell is `neutral_local` on a
limited same-host topology. None is eligible for policy acceptance, rule
derivation, shadow verification, ProtocolLab submission, or activation.

## Scope

- Axis: `application_send_turn_planning`.
- Treatments: forced `legacy_current` and forced `conservative` in ABBA order.
- Adjacent axes: legacy/current; the receive-credit environment variable was
  reported as `unset` by every raw server host.
- Runtime source commit: `a670c66d88b826420191ef40b66f5cafe72ff9cf`.
- Campaign commit after the exporter correction: `b50daee8`.
- Command: `Invoke-AdaptiveRuntimePolicyLocalCell.ps1` with
  `-CampaignId adaptive-send-turn-local-20260723-c1-abba`,
  `-CellId duplex-64kb-x1-s16`,
  `-PolicyAxis application_send_turn_planning`, `-SequenceProtocol ABBA`,
  `-PolicyA legacy_current`, `-PolicyB conservative`, one connection, sixteen
  streams per connection, two-second warmup, and five-second measurement.

## Retained Artifacts And Classification

The complete retained root is
`C:\shared\src\incursa\quic-dotnet\.artifacts\adaptive-runtime\adaptive-send-turn-local-20260723-c1-abba\duplex-64kb-x1-s16`.

| Item | Count / value | Classification |
| --- | --- | --- |
| ABBA samples | 4 | All exact-payload valid; no failed, timed-out, or protocol-error operations. |
| Raw construction records | 8 | Two versioned connection records per sample; forced identity matches each sample treatment. |
| Local-result classification | `invalid_environment` | Same-host target/generator health was invalid and maximum within-treatment relative range was `0.05650001823266077`, above the five-percent bound. |
| Original exporter output | 0 rows | Preserved empty `construction-rows` directory from the argument-expansion failure. |
| Diagnostic export | 2 rows | Preserved under `construction-rows.export-001`; excluded from the correction join to avoid duplicate identities. |
| Corrected construction export | 8 rows | Preserved under each sample's `construction-rows.export-002` directory. |
| Corrected validation | valid | 8 unique construction rows, one checksum inventory, 44 verified artifacts; summary SHA-256 `27259465a443a56ab9122a2715e372c5f831d612f060b1c3b02ba7b6cd09d513`. |

The first runner attempt exposed two retained implementation defects: multiple
exclusion flags were passed as one comma-delimited value, and a successful
PowerShell exporter could be mistaken for failure when `$LASTEXITCODE` was
unset. `b50daee8` corrects the first defect and `d262bd08` corrects the
second before another campaign is started. The raw run, empty output, duplicate diagnostic rows,
and validated `export-002` correction remain preserved rather than replaced.

## Dataset Disposition

- Raw layer: retain all twenty samples and all sixty-four source records across
  the original c1 cell, its three c1 reruns, and the c4 guardrail.
- Construction-provenance layer: retain the original eight `export-002` rows
  with `target_health_invalid` and `generator_health_invalid` exclusions, and
  the eight automatically exported `rerun-004` rows. Retain the c4 cell's
  thirty-two automatically exported rows with its health exclusions. The two
  original diagnostic rows remain outside the correction join to avoid
  duplicate identities.
- Curated and analysis layers: zero included rows. The invalid rows remain
  excluded; the `neutral_local` rows remain uncurated until independent-host,
  fairness, and managed-allocation gates are populated.
- No benchmark claim, threshold tuning, rule proposal, shadow conclusion, or
  active-policy recommendation follows from any of these runs.

## Subsequent Retained Cells

Each cell retained its own root, command output, source commit, raw records,
and classification. They are not pooled with one another or with a future
independent-host cohort.

| Campaign | Runtime source commit | Samples / raw records | Construction rows | Classification and retained reason |
| --- | --- | --- | --- | --- |
| `adaptive-send-turn-local-20260723-c1-abba-rerun-002` | `18a792ffc9a477cb8e452a65b2b03470b05210ec` | 4 / 8; all payload-valid | 0 | `invalid_environment`; target and generator health invalid, maximum within-treatment relative range `0.20145001529357126`. The then-current runner still withheld construction export after the environment failure. |
| `adaptive-send-turn-local-20260723-c1-abba-rerun-003` | `fb9d6782651bee6d0594e316b2375e0689a10ead` | 4 / 8; all payload-valid | 0 | `invalid_environment`; target and generator health invalid, maximum relative range `0.10069728847618635`. Its retained console log records the positional PowerShell argument-binding failure for `ExpectedPolicy`. |
| `adaptive-send-turn-local-20260723-c1-abba-rerun-004` | `86b7744e0a3bc966158102ef819349a432feabfa` | 4 / 8; all payload-valid | 8 | `neutral_local`; automatically exported and validated after the named-splat fix. Maximum relative range `0.049935014487130155`; target and generator health are `limited` because the topology remains same-host. |
| `adaptive-send-turn-local-20260723-c4-abba-r001` | `9b3398c84c073180d104ffb278c312d5e034ec68` | 4 / 32; all payload-valid | 32 | `invalid_environment`; target and generator health invalid, maximum relative range `0.05932185685129216`. This was the bounded four-connection guardrail (16 streams per connection), not a stress cell. |

The `rerun-004` root is
`C:\shared\src\incursa\quic-dotnet\.artifacts\adaptive-runtime\adaptive-send-turn-local-20260723-c1-abba-rerun-004\duplex-64kb-x1-s16`.
Its `evidence-validation.json` reports eight unique construction rows, one
checksum inventory, forty-four unique artifact hashes, and zero failures. The
validation summary SHA-256 is
`27259465a443a56ab9122a2715e372c5f831d612f060b1c3b02ba7b6cd09d513`.
The command used the same bounded c1 ABBA shape as the original cell with the
`rerun-004` campaign ID and source commit `86b7744e`; its retained console log
is `.artifacts\adaptive-runtime\adaptive-send-turn-local-20260723-c1-abba-rerun-004.runner-console.log`.

Commit `86b7744e` changes only runner argument binding: construction exporter
and evidence-validator parameters are named PowerShell splats rather than
positional arrays. Commit `f0be4875` verifies that two exclusion flags are
passed through that named-splat contract. The focused requirement home passed
6/6 after the latter commit.

The c4 root is
`C:\shared\src\incursa\quic-dotnet\.artifacts\adaptive-runtime\adaptive-send-turn-local-20260723-c4-abba-r001\duplex-64kb-c4-s16`.
Its validation reports thirty-two unique construction rows, one checksum
inventory, forty-four unique artifact hashes, and zero failures; validation
summary SHA-256:
`b0999a164b94963c7a6a64f36397a8db9b77d8415c813b23978b6002cec2c10e`.
The c4 raw records and validated construction rows remain excluded from curated
and analysis layers because the local host-health contract failed.

## BenchmarkDotNet Mechanism Check

`QuicApplicationSendTurnPlannerBenchmarks` was built in Release and run on
2026-07-23 against commit `937db223`. The permanent benchmark class compares
the direct legacy selector with the null and explicit planner dispatch paths at
one and sixteen queued writes; it also checks forced conservative continuation
dispatch. This is a local mechanism-cost and allocation check, not a policy
acceptance result.

- Dry run: 10/10 cases completed. Report SHA-256:
  `58cbc9498cc4a8ea6c50dfbfab79dc901f6f0a52e0a6df4491c5a270089cfbe6`.
- Short run: 10/10 cases completed with no managed allocations. Report
  SHA-256: `dbfe650f23af239601cc6a0538a3333bd1e1c2db9f9ac43584d9beed937814fe`.
- Selector mean, one queued write: direct `42.4505 ns`, null dispatch
  `39.8114 ns` (ratio `0.939`), explicit planner `45.1284 ns` (ratio `1.065`).
- Selector mean, sixteen queued writes: direct `52.0590 ns`, null dispatch
  `52.8650 ns` (ratio `1.016`), explicit planner `57.4535 ns` (ratio `1.104`).
- The two continuation methods measured below timer resolution in this short
  run. They prove neither allocation nor execution failure, but provide no
  useful timing comparison.

The retained reports and full console logs are under
`C:\shared\src\incursa\quic-dotnet\.artifacts\adaptive-runtime\benchmarkdotnet\send-turn-planner-20260723`.
BenchmarkDotNet version was `0.15.8`; host runtime was `.NET 10.0.10` and SDK
was `10.0.204`. No production rule, threshold, or active behavior changed from
this measurement.

## Full Release Verification

The complete Release suite was invoked once from the clean `c878328a`
checkpoint with:

```powershell
dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release --no-restore --disable-build-servers --nologo -v:minimal
```

It completed in 10m36s with 9,793 passed, 4 skipped, and 1 failed. The failed
test was
`Http3MinimalServerTests.RequestDataBeforeHeaders_ClosesConnectionWithFrameUnexpected`:
it timed out waiting for the peer HTTP/3 connection close at
`Http3MinimalServerTests.cs:2851`. This is retained as a full-suite
correctness blocker; it is not attributed to, and does not validate, the
application-send-turn policy axis. The original stdout and stderr logs remain
at `.artifacts\adaptive-runtime\verification\full-release-20260723T1933Z.stdout.log`
and `.artifacts\adaptive-runtime\verification\full-release-20260723T1933Z.stderr.log`.
No isolated rerun has been used to replace or erase this result.

## ProtocolLab Gate Status

No `application_send_turn_planning` ProtocolLab job was submitted and no
remote worker was contacted for this checkpoint. The local c4 guardrail is
`invalid_environment`, and the complete Release suite has the retained
correctness failure above; either condition blocks higher-count or
independent-host policy evidence.

A read-only review of the current ProtocolLab material found a reported
cross-worker diagnostic pair (`plab-worker-x64-02` target at `10.10.99.248`
and `plab-worker-x64-03` load generator at `10.10.99.77`) in
`protocol-lab-internal/docs/protocol-lab/raw-quic-isolated-pair-handshake-evidence-2026-07-23.md`.
That evidence is not this axis's provenance cohort, is explicitly
`diagnostic`/`publishable=false`, and cannot establish physical-host
independence for this campaign. Its controller deployment is also blocked by
an unverified changed ED25519 host fingerprint for `10.10.99.176`.

The only nearby `public-private-inventory.json` is a repository-export
classification generated on 2026-05-30, not a live physical-host registry.
Accordingly, before any reviewed ProtocolLab campaign, the current registry
must independently attest the target and generator identities, physical hosts,
architecture, hardware, operating-system/toolchain versions, health,
calibration, exact source commit, clean state, binary hashes, and network path.
This checkpoint does not infer those facts from addresses or older diagnostic
evidence.

## Remaining Gate

Repeat bounded c1/c4 local forced cells from the corrected runner on an
environment that satisfies the health/noise contract, then proceed only through
the reviewed multi-host campaign path. This record does not erase, supersede,
or pool the invalid same-host regime with a future eligible cohort.
