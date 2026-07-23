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

## Trace-Contract Verification

The application-send construction-provenance contract is closed at
measurement-only scope by `REQ-QUIC-CRT-0174`, `ARC-QUIC-CRT-0064`,
`WI-QUIC-CRT-0065`, and `VER-QUIC-CRT-0066`. On the current source checkpoint,
the focused requirement home passed 6/6 and the forced planner safety band
passed 24/24:

```powershell
dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release --no-build --no-restore --disable-build-servers --nologo -v:minimal --filter "FullyQualifiedName~REQ_QUIC_CRT_0174"
dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release --no-build --no-restore --disable-build-servers --nologo -v:minimal --filter "FullyQualifiedName~QuicApplicationSendSchedulerTests"
```

The TRX artifacts remain in
`.artifacts\adaptive-runtime\verification\send-turn-provenance-focused-20260723`.
Their SHA-256 values are
`13AFEA46D19E785CB3A593B0CD1969798B3B92E83356A7966D7803EA719AB8A4`
for the requirement home and
`0560DB779B7603194348D8F658AA28AF653F197C5E97D8DC56CE0D782FC03CAB`
for the forced-planner safety band. This closes construction provenance and
permanent local validation only; it does not turn any invalid or neutral-local
cell into an eligible policy outcome, add shadow behavior, or authorize
ProtocolLab or active policy selection.

The three touched architecture, work-item, and verification artifacts each
validate against `model/model.schema.json`. The repository-wide core SpecTrace
profile remains blocked by its standing canonical-specification backlog
(`2691` reported errors); it cannot resolve the current requirements while
`SPEC-QUIC-CRT.json` remains globally invalid. That independent repository
blocker is retained and does not alter the completed measurement-only contract
or promote this axis.

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

### Retained focused diagnostic

After the full-suite result, a fixed, predeclared 20-repetition diagnostic
probe ran from `080c74aadfd26989658e5f329248b08bd6f0f1a1` with no source or test
changes:

```powershell
dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release --no-build --no-restore --disable-build-servers --nologo -v:minimal --filter "FullyQualifiedName~Http3MinimalServerTests.RequestDataBeforeHeaders_ClosesConnectionWithFrameUnexpected"
```

All 20 isolated repetitions passed (one test per repetition). The immutable
summary and each stdout/stderr pair remain under
`.artifacts\adaptive-runtime\verification\http3-request-data-before-headers-repeat-20260723T2030Z`;
the summary SHA-256 is
`BCCC0F1EF1253E0134EE7B07DC555649A0EE800FDE2848692200F4C6361157A5`.
`QuicLoopbackNetworkTestCollection` disables parallel execution within its
shared loopback collection. This is retained nonreproduced diagnostic evidence
only: it neither clears nor reclassifies the original one-of-9,798 full-suite
failure, and no policy gate is advanced from it.

### Retained independent complete rerun

An independent complete Release rerun then executed from
`422d31de14bf683a6f096fcfeb6806dd65d19663` (documentation-only changes after
the focused diagnostic) with the same command:

```powershell
dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release --no-restore --disable-build-servers --nologo -v:minimal
```

It passed in 10m18s with 9,794 passed, 4 skipped, and 0 failed. Its command
manifest, stdout, and stderr remain at
`.artifacts\adaptive-runtime\verification\full-release-rerun-20260723T2100Z`.
The SHA-256 values are `754AC6CB3A478A42071E814E540E3FF54D776B913CE9723FA6B766478200502C`
for `command.json`,
`5811681B4BBFAFE16507F018ABC102F661FE970BFD886C6C39C4D31CA26A1723` for
stdout, and
`E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855` for
stderr.

This second complete-suite result is retained alongside, not in place of, the
original failure. It establishes that the timeout did not reproduce in this
full rerun, but does not establish cause, clear the earlier correctness
blocker, or authorize c4, ProtocolLab, or active-policy progression.

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

## ProtocolLab Live-Registry Correction and Exact-Package Preflight

The preceding ProtocolLab status was an accurate snapshot of this evidence
ledger before remote work, but its reliance on an old topology export is now
superseded by a live-controller check. On 2026-07-23 the controller at
`http://10.10.99.176:5088` was reachable and reported six ready workers. Its
current isolated-pair role/capability selection placed the SUT on
`plab-worker-x64-02` (`10.10.99.248`) and the load worker on
`plab-worker-x64-03` (`10.10.99.77`). Both workers were independently checked
through strict SSH host-key verification and reported the controller-advertised
architecture, CPU count, memory, and .NET SDK `10.0.302`. The controller labels
the pair `evidenceTier=offline-ml-two-host-vm` and records
`identityCaveat=duplicate-machine-id-user-attested-physical-separation`; that
caveat remains attached to this evidence. The earlier statement that a changed
controller SSH fingerprint blocked deployment is not current: the selected
worker identities verified against their trusted SSH keys. The controller
inventory, rather than the stale May/July export, is the source for this
checkpoint.

This correction did **not** authorize an axis comparison. It enabled one
legacy-current raw-QUIC correctness preflight so that the exact current source
could be tested before any forced-policy ABBA/BAAB campaign. The package was
built without `-AllowDirtySource` from clean commit
`2ded7f0bc5edfc4d8a75f5fc62ecab8519ed6663`:

```powershell
pwsh -NoProfile -File eng/protocol-lab/New-QuicDotNetProtocolLabPackage.ps1 `
  -PackageTarget RawQuic `
  -ProtocolLabRoot C:\shared\src\incursa\protocol-lab `
  -RuntimeIdentifier linux-x64 `
  -PackageVersion adaptive-send-turn-20260723-2ded7f0b-legacy-current `
  -AdaptiveRuntimeApplicationSendTurnPolicy legacy_current `
  -Force
```

The generated package is
`artifacts\protocol-lab\packages\quic-dotnet-raw-dev.adaptive-send-turn-20260723-2ded7f0b-legacy-current.plabpkg`,
with SHA-256
`26DC5DE2EA18C59BD27F43D6119DE57070D57EA4BF4AA7627500622766EF7840`.
Its embedded build provenance records the same clean source commit, Release,
`linux-x64`, and forced `application_send_turn_planning=legacy_current`.
Controller package admission returned HTTP 201 and validation `passed`.

Controller job `job-c9014c5dc047453db4b71394e8af1acc` then ran one isolated-pair
`quic.transport.handshake-cold` preflight with that package, the retained
component package hashes
`79d887af00cc3cb41375b7bf637a548b0efe78d196af67da10631b3904e366fc`
(`protocol-lab-quic-go-raw-load`) and
`10982941d384ffcd9ea26e92fee111ab777bb0ceaf896fad81d18d6f2f68d373`
(`protocol-lab-raw-quic-scenarios`), and the controller-owned
`raw-quic-peer-confidence` profile. The controller retained the job, result
records, provenance, and checksum-bearing package records under its job root;
the job is the permanent raw-evidence authority for this checkpoint.

Classification is `failed_correctness` (unattributed preflight), not
`invalid_environment`, `accepted`, or policy evidence. All six scheduled
cells (`c1`, `c4`, `c16`, `c32`, `c64`, and `c128`) reached a ready target and
passed endpoint validation; all six then failed the raw loader with
`load-tool-exit-nonzero`. The c1 load execution artifact
`artifact-078-c99df991e4a1` records exit code `1` and
`connection=0 dial: timeout: no recent network activity`; c1 result artifact
`artifact-087-27973a648055` records one request, zero successes, one timeout,
and `comparabilityStatus=invalid`. The SUT role completed normally and served
`quic://10.10.99.248:41261`; the failure is therefore neither worker absence
nor package-admission failure. It is deliberately not attributed to the
send-turn policy, because only legacy_current was forced and no counterfactual
candidate was run.

Dataset accounting for this remote preflight is zero raw connection epochs
eligible for normalization, curation, or analysis; the six invalid benchmark
cell records and their raw controller artifacts are retained with their reason
codes. The immediate unresolved gate is diagnosis and repair of the raw QUIC
cross-worker handshake timeout, followed by a fresh legacy-current preflight.
Only after that succeeds may the permanent, round-robin forced-policy campaign
be scheduled. Adjacent axes remain frozen at `legacy_current`.

## Raw QUIC Listener-Failure Diagnosis and Recovery Checkpoint

The failed legacy-current preflight above was preserved and investigated; it
was not replaced. A diagnostic-only package capability was added in commit
`29b70f8a6ec8605447f5448f8a94ae59c8278cb6` so that the raw QUIC server can
emit bounded handshake messages when, and only when,
`-RawQuicDebugLogging` is specified. The focused package-template gate passed
22/22. The resulting clean, explicitly forced legacy-current diagnostic
package had SHA-256
`84A0409759F11E392CD705579CCEC574DF9CB3F5E2466CA4A11032ABF38F6926` and was
admitted by the controller (HTTP 201, validation `passed`). This package is
diagnostic instrumentation, not a candidate policy implementation and not a
performance cohort.

The exact same isolated pair, scenario, component packages, and
`raw-quic-peer-confidence` profile ran as controller job
`job-00580dbcd319403c91f0c6a3d806331c`. Its c1 cell passed with 3,202/3,202
successful handshakes; c4, c16, c32, c64, and c128 each timed out during
loading. The retained server stderr for the shared target session showed
5,046 accepted handshake proposals, 5,041 accepted-and-closed connections,
and then exactly one listener failure:
`The listener connection terminated during establishment.` This proves that
the controller, both workers, UDP reachability, and the server's normal
handshake path were present. It also proves the target process could exit its
accept loop after an unrelated failed inbound establishment while the adapter
control plane remained ready. Because debug logging is an intrusive timing
change, this run remains `diagnostic_only`; it supplies zero policy-dataset
epochs and cannot be compared with the preceding non-debug c1 failure.

The failure path was then repaired in the raw ProtocolLab server only, in
commit `352939e3ff5d1bd50d2f40f1d4d6924b40e0d000`: a failed inbound
establishment is discarded (and only diagnostic-logged when enabled), while
the listener continues accepting subsequent connections. It does not alter a
policy value, controller input, safety guard, or active runtime policy. The
focused `ProtocolLabPackageTemplateTests` suite passed 22/22 and
`eng/protocol-lab/servers/IncursaRawQuicServer/IncursaRawQuicServer.csproj`
built Release with 0 warnings and 0 errors.

The recovery package was built from that clean, pushed commit without
`-AllowDirtySource`:

```powershell
pwsh -NoProfile -File eng/protocol-lab/New-QuicDotNetProtocolLabPackage.ps1 `
  -PackageTarget RawQuic `
  -ProtocolLabRoot C:\shared\src\incursa\protocol-lab `
  -RuntimeIdentifier linux-x64 `
  -PackageVersion raw-quic-listener-resilience-20260723-352939e3-legacy-current `
  -AdaptiveRuntimeApplicationSendTurnPolicy legacy_current `
  -Force
```

It has SHA-256
`A34D60B18BA3C4142BC664A4654DD843CF24EB57C72A3A6E5BC44B6AA58CBC1D`, debug
logging disabled, `application_send_turn_planning=legacy_current`, and passed
controller package admission. Controller job
`job-e3ce7ea32b9e48aca4ec76c3408c916a` used the identical x64 isolated pair
and retained component package hashes. Its permanent result artifacts show:

| Cell | Result artifact | Classification | Requests | Successes | Timeouts |
| --- | --- | --- | ---: | ---: | ---: |
| c1 | `artifact-048-472197d8455d` | comparable-with-warnings | 3,277 | 3,277 | 0 |
| c4 | `artifact-267-d2d0fd458276` | comparable-with-warnings | 7,116 | 7,116 | 0 |
| c16 | `artifact-157-467034c783ad` | comparable-with-warnings | 7,696 | 7,696 | 0 |
| c32 | `artifact-212-83ddc2978057` | comparable-with-warnings | 7,648 | 7,648 | 0 |
| c64 | `artifact-322-0085fbe3665a` | comparable-with-warnings | 5,248 | 5,248 | 0 |
| c128 | `artifact-103-6114b61b69b9` | failed_correctness | 128 | 0 | 128 |

The c128 loader returned exit code 0 but its validation correctly failed:
`Raw QUIC failed request count was 128, expected 0` and `Raw QUIC timeout
request count was 128, expected 0`. Its artifacts also retain
`load-generator-saturation-possible`; it is a separate high-concurrency
correctness/attribution blocker, not a valid throughput result and not an
excuse to relabel the row. The corrected listener mechanism is therefore
proven through c64 on the independent-worker preflight, while c128 remains a
retained failed-correctness row requiring its own diagnosis.

Dataset accounting remains zero eligible adaptive-policy epochs: all three
remote jobs in this section are legacy-current diagnostics, the controller did
not capture target process metrics for the external adapter-backed target, and
the profile has one repetition. No forced candidate, shadow recommendation,
threshold, rule table, or production behavior has been enabled. The next
authorized work is to diagnose the retained c128 high-count failure and then
repeat the baseline preflight under the existing evidence contract before
scheduling any policy counterfactual cells. Adjacent axes remain frozen at
`legacy_current`.

### Retained c128 Instrumentation Attempt and Worker-Identity Exclusion

The c128 investigation produced a new clean diagnostic package from commit
`21cb2ab65ffe456e29cc7fc543d83b9bf2a4f899`, with
`-RawQuicDebugLogging`, forced
`application_send_turn_planning=legacy_current`, and SHA-256
`8FDF39A96321D1DF2C20B5E8208987DA9D44BE83B5E2508356DA109A7737EDC2`.
Controller package admission returned HTTP 201 with validation `passed`.
Controller job `job-00fa01a5412240c7a9c2e85c8813ad84` was submitted with the
same isolated x64 pair and retained component hashes, solely to determine
whether c128 Initial packets reach and establish at the target.

No diagnostic workload began. The load role claimed normally, but the SUT
lease for `plab-worker-x64-02` remained unclaimed. A strict SSH check to the
same current registry address (`10.10.99.248`) reached TCP port 22 but timed
out during the SSH banner exchange. The job was cancelled through the normal
controller endpoint with the exact reason
`invalid_environment: plab-worker-x64-02 SUT lease remained unclaimed while strict SSH verification timed out during banner exchange; no diagnostic workload started.`
Its terminal controller status is `Cancelled`; it contributes zero benchmark
rows, connection epochs, or policy evidence and does not modify the retained
c128 failed-correctness classification above.

The live controller registry also listed the currently heartbeating Linux
same-host diagnostic pair `plab-worker-sut-01` (`10.10.99.85`) and
`plab-worker-load-01` (`10.10.99.108`), both labeled
`physicalHostId=lenovo-p620`. They are unsuitable for an independent-host
policy claim in any event. More importantly, strict SSH verification rejected
both because each presented a changed ED25519 fingerprint conflicting with the
local known-host entry (`SHA256:6tan1lwWz68XCz2xThVhGfkhGK7slY18c8ZhdsMw6Rg`
for the SUT and `SHA256:QW7ClHAP1s6bui5ZFVdtCEFY2gLp60AjUszk3P45Y60` for the
load worker). No host key was accepted, replaced, or bypassed, and neither
worker was used. This is a preserved worker-identity environment blocker, not
evidence that the multi-host ProtocolLab is absent.

### Deterministic Two-Shard Fanout Gate

Commit `f9fabfd6c0bc9cc5b69b2e72119c5b7cb487f5db` adds
`ConcurrentColdHandshakesRemainAcceptableWithTwoRuntimeShards` to
`QuicListenerHostSendResilienceTests`. It opens 128 simultaneous loopback cold
handshakes against the same two-runtime-shard topology reported by the x64
SUT, with an explicit 128-entry accept backlog. The focused gate:

```powershell
dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release `
  --no-build --no-restore --disable-build-servers --nologo `
  --logger "console;verbosity=normal" `
  --filter "FullyQualifiedName~QuicListenerHostSendResilienceTests"
```

passed 20/20 in 7.576 seconds; the new 128-handshake test passed in one
second. This is deterministic local mechanism evidence that the listener,
backlog, and two-shard runtime can accept the complete concurrent fanout. It
does not recreate the independent-worker network path, target CPU contention,
or external load-generator timing, so it neither clears nor reclassifies the
retained remote c128 `failed_correctness` row. It supplies zero adaptive-policy
dataset epochs and leaves the next remote diagnosis gated on verified worker
identity and a healthy target lease.

### Recovered Independent-Worker c128 Diagnostic

After the retained worker-identity exclusion, strict SSH verification again
succeeded for the independent `plab-worker-x64-02` SUT
(`10.10.99.248`, x86_64, two logical processors, 3,902 MiB, .NET SDK
10.0.302, PowerShell 7.6.4) and `plab-worker-x64-03` load worker
(`10.10.99.77`, x86_64, six logical processors, 32,083 MiB, .NET SDK
10.0.302, PowerShell 7.6.4). The controller registry continued to identify
them as the isolated `offline-ml-two-host-vm` SUT/load pair with distinct
physical-host labels. This re-verification is a contemporaneous readiness
check; it does not erase the earlier unclaimed-lease environment row.

A fresh diagnostic-only Raw QUIC package was built from clean commit
`3849008de439dd93aa9b0951f5c4eb8d0da99534`, Release, `linux-x64`, with
`-RawQuicDebugLogging` and only
`application_send_turn_planning=legacy_current` forced. Its immutable package
identity is
`quic-dotnet-raw-dev@raw-quic-c128-debug-20260723-3849008d-legacy-current-r002#9301b914e8e14b0e6593ae40ddb31b24228ef319d554a2e6193ea7a70339dcb0`.
The package build attestation records a clean source scope and controller
admission returned HTTP 201 with validation `passed`. It was combined only
with the retained raw component identities
`protocol-lab-quic-go-raw-load@mixed-linux-20260722-4e59507#79d887af00cc3cb41375b7bf637a548b0efe78d196af67da10631b3904e366fc`
and
`protocol-lab-raw-quic-scenarios@mixed-linux-20260722-4e59507#10982941d384ffcd9ea26e92fee111ab777bb0ceaf896fad81d18d6f2f68d373`.

Controller job `job-ee419db137a4446988331180e4416b5d` used the preserved
`raw-quic-peer-confidence` workflow profile, `isolated-pair` placement,
one repetition, and network path `10.10.99.77->10.10.99.248`. Both roles
claimed, the SUT published `quic://10.10.99.248:34227`, and every cell passed
endpoint validation. The controller retained its run root at
`/var/lib/protocol-lab/controller/artifacts/job-ee419db137a4446988331180e4416b5d/raw-quic-c128-debug-20260723-3849008d-legacy-r002-quic-transport-v1-comparison-cell-1`
with its artifact manifest, evidence bundle, package provenance, and per-cell
result/validation artifacts.

| Cell | Benchmark result | Classification consequence |
| --- | --- | --- |
| c1 | succeeded | retained diagnostic success |
| c4 | succeeded | retained diagnostic success |
| c16 | succeeded | retained diagnostic success |
| c32 | succeeded | retained diagnostic success |
| c64 | succeeded | retained diagnostic success |
| c128 | failed `load-generator-validation-failed` | retained `failed_correctness` diagnostic |

At c128, the external `quic-go-raw-load` process requested and used 128
connections for 15 seconds after a five-second warmup. Its schema-valid result
retains 1,408 total cold-handshake requests, 1,286 successes, 122 failures,
122 timeouts, a 0.08664773 timeout/failure rate, 142.4726739 requests per
second, and 177.3459417 ms mean connect time. The raw validation correctly
failed because both failed and timeout counts must be zero. The controller
therefore completed the job with `failureKind=Benchmark`,
`failureReasonCode=benchmark-command-failed`, and exit code 1. This narrows
the prior all-timeout c128 result: the current listener now accepts substantial
independent-worker fanout, but the c128 zero-timeout correctness guard remains
unmet.

This row is `diagnostic_only` and contributes zero eligible adaptive-policy
epochs to raw, normalized, curated, or analysis layers. Debug logging changes
timing; only one repetition was run; target process metrics are unavailable
for the external adapter-backed target; trace/counter capture was disabled;
and load-process CPU attribution is unavailable despite bounded root-process
telemetry (peak observed working set 50,483,200 bytes). The result also retains
`load-generator-saturation-possible`, so it cannot establish whether the
remaining c128 timeouts are target, network, or generator-limited. No earlier
failed-correctness, invalid-environment, or diagnostic row was relabeled or
deleted; no candidate policy, shadow recommendation, threshold, rule, or
production behavior was enabled. The next authorized diagnostic slice is
bounded c128 attribution with verified current worker identity and explicit
target/load telemetry capture, followed by a clean non-debug legacy-current
baseline only if that attribution is sufficient. Adjacent axes remain frozen
at `legacy_current`.

### Cross-Worker Child-Artifact Capture Gap

The recovered diagnostic also exposed a permanent-evidence transport defect.
For c128, the controller's artifact index records both
`artifact-105-75cb13805d59` (`server.stderr.txt`) and
`artifact-114-017f74a8d77e` (`target.stderr.txt`) as existing and
controller-readable, but each has `sizeBytes=0`; their stdout counterparts
are also zero bytes. Consequently, the raw server's explicitly enabled debug
messages were not available in the retained controller artifact bundle.

This is not evidence that the server produced no diagnostics. The Raw QUIC
adapter contract advertises stdout/stderr artifacts and its endpoint launcher
starts bounded child-output copy tasks. The loss occurs across the
cross-worker target/result handoff: the load-side cell record retains the
external endpoint and its own loader artifacts, while the SUT-side child
artifacts are not materialized in the controller-visible result bundle. The
same handoff leaves the external target's process identity and metrics
unresolved, which is why runtime counter capture cannot attach to the raw
server from the load worker.

Treat this as a `protocol-lab-internal` evidence-plane delivery blocker, not
as a QUIC runtime or adaptive-policy defect. The next diagnostic implementation
must preserve the SUT adapter's declared child stdout/stderr, endpoint-process
identity, and bounded process-metric snapshots through the normal cross-worker
artifact bundle, with checksums and explicit unavailable states. Until then,
debug-mode c128 output, target pressure, and failure-side establishment reasons
remain unavailable evidence. This gap preserves the current c128 row as
`failed_correctness` and `diagnostic_only`; it does not justify a rerun that
would replace or relabel it.

### Correction: Incomplete SUT Role, Not a Proven Artifact-Transfer Loss

Read-only controller reinspection at `2026-07-23T17:40:11-06:00` refines the
preceding diagnosis without removing it. The `sut` lease for
`plab-worker-x64-02` was claimed at `2026-07-23T17:25:45-06:00`, but its
`completedAt`, `result`, and artifact count remained absent after the load
role terminalized the job at `2026-07-23T17:30:00-06:00`. The controller index
contains no `sut/` role artifacts. Thus no SUT role bundle was available to
transfer or materialize for this job.

The zero-byte `server.stdout.txt`, `server.stderr.txt`, `target.stdout.txt`,
and `target.stderr.txt` files named above are load-worker external-target
placeholders. Their recorded source paths are under the load worker's
`raw-quic-c128-debug-20260723-3849008d-legacy-r002-quic-transport-v1-comparison-cell-1`
run root; they are not proof that a SUT child-artifact bundle was dropped in
transit. The original diagnostic statement is therefore retained as a
superseded hypothesis, not silently deleted or relabeled.

The target descriptor was published and the remote server did serve the
successful c1--c64 requests plus the partially successful c128 requests, so
the c128 outcome remains a retained `failed_correctness`,
`diagnostic_only` runtime row. It remains unsuitable for adaptive-policy data
because the target role did not publish its terminal observation/artifact
result. A strict SSH attempt after the job timed out during the SUT banner
exchange; this is retained as a contemporaneous environment observation, but
does not by itself identify why the role did not complete.

To prevent a non-responsive adapter control plane from withholding the target
role result indefinitely, ProtocolLab internal commit
`6e8b833cb8fcd78802d23cfcf68067f6fae53c96`
(`Bound adapter control-plane cleanup`, branch
`codex/cross-worker-artifact-capture-20260723`) bounds each adapter control
plane request to 15 seconds. It adds `PB-ARTIFACT-0003` as a partial
traceability requirement and passed its focused Release build plus 61
`RuntimeDiagnosticsTests`/`LabSchedulerTests` tests. It is pushed for review
but has not been deployed to the lab; no fresh campaign is authorized from
this code until the exact reviewed commit is deployed and the target worker
is re-verified.

The next diagnostic gate is therefore: deploy the exact reviewed ProtocolLab
commit, verify the SUT worker's current identity and role health, and run one
legacy-current c128 failure-path cell which must retain a terminal SUT role
result, adapter child artifacts (or explicit unavailable records), and target
metrics provenance. Adjacent axes remain frozen at `legacy_current`; no
candidate, shadow, or active policy behavior is authorized.

### Correction: Late SUT Finalization Materialized the Cross-Worker Bundle

The preceding correction was necessarily provisional. Read-only controller
reinspection after the SUT role completed at
`2026-07-23T17:40:38.1520591-06:00` shows that the normal late-sibling merge
did materialize the SUT bundle. The terminal SUT result has
`failureKind=None`, reports the published endpoint
`quic://10.10.99.248:34227`, and contributes 39 role artifacts; the job now
has 382 controller-indexed artifacts, including `sut/`-prefixed entries. The
SUT result root is
`/var/lib/protocol-lab/controller/artifacts/job-ee419db137a4446988331180e4416b5d/raw-quic-c128-debug-20260723-3849008d-legacy-r002-sut-lease-4bd9188d631f44a49013e8e033e2858c`.

This preserves both earlier entries as time-bound observations while changing
the conclusion: this run does **not** prove a cross-worker child-artifact
transfer loss. The now-readable SUT child stderr artifact
`artifact-013-7d05748b6c2e` is 8,538,075 bytes (132,338 lines), and the child
stdout artifact is 11,837,232 bytes. The role is a prestarted target lifecycle
anchored at `c1-s0-r1`, so those role artifacts cover the whole campaign and
are not a falsely per-c128 target-process record. The role's startup metrics
(`artifact-019-63411e0a99b4`) retain child process ID 102197, 56,049,664-byte
working set, 0.23 CPU seconds, and endpoint port 34227. This is sufficient
provenance to establish that the SUT evidence arrived through the ordinary
late role-completion path, although it is not per-cell target pressure
attribution.

The retained server log records 44,205 accepted handshake proposals and
44,056 accepted/closed connection pairs across the complete diagnostic run;
it contains no lines matching `exception`, `error`, or `timeout`. This is
supporting context, not a clearance of c128: the c128 loader result remains
the authoritative cell result with 1,408 attempted requests, 1,286 successes,
and 122 `dial: timeout: no recent network activity` failures. Its root-process
telemetry peaked at 50,483,200 bytes and sampled 0.47 CPU-seconds at most in a
one-second interval on a six-logical-processor worker. The existing
`load-generator-saturation-possible` warning is therefore retained, but the
captured root-process samples do not establish CPU saturation.

The actual evidence-plane defect is bounded finalization, not an absent SUT
artifact handoff: `sut/.../adapter-stop.json` records that the old adapter
control-plane cleanup request reached its configured 100-second
`HttpClient.Timeout`. The role only published its result roughly ten minutes
and 38 seconds after it was claimed. ProtocolLab commit
`6e8b833cb8fcd78802d23cfcf68067f6fae53c96` limits that request path to 15
seconds, but it remains review-pushed and has not been deployed; this observed
run used the prior timeout behavior and cannot validate the fix. No policy
candidate, rule, shadow behavior, or active production behavior is enabled.
The c128 row remains `failed_correctness` and `diagnostic_only`, with zero
eligible adaptive-policy epochs. Adjacent axes remain frozen at
`legacy_current`.

### c128 Repeated-Batch Failure-Shape Attribution

Read-only source inspection of the exact retained Raw QUIC executor source at
ProtocolLab commit `4e59507844e0197d6222089b4a4ae968a7fbfe1a` establishes the
meaning of the c128 count without changing the row. For `handshake-cold`, the
executor launches all requested connections concurrently in one batch, closes
successful connections, and repeats that batch until the duration expires. In
the measured phase it stops after the first batch containing an error; the
five-second warmup intentionally discards batch errors and does not add them
to the measured result.

The retained 1,408 measured requests are exactly eleven 128-connection
batches. The 122 timeout errors identify connection indexes within the final
failed batch, leaving six successful connections in that batch and ten prior
fully successful measured batches. This is therefore a repeated
high-churn/cold-handshake failure, not evidence that the initial 128-way burst
or a policy transition failed. It also means that the per-connection error
labels do not carry a batch ordinal, so the current package cannot distinguish
which earlier warmup bursts were healthy from its result document alone.

This attribution removes neither the c128 correctness failure nor the
generator/target/network uncertainty. It supplies a narrow next diagnostic
requirement after the reviewed cleanup bound is deployed: preserve the
terminal SUT role result and collect a per-batch ordinal with the load error,
plus before/after target-process metrics from the SUT role. The existing
measurement-only axis remains `application_send_turn_planning=legacy_current`;
all adjacent axes remain `legacy_current`, and no policy behavior is enabled.
