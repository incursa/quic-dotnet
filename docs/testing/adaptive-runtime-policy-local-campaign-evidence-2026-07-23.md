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

### Release-Suite Verification and Preserved Invalid-Environment Run

The initial interactive Release-suite attempt was retained as an
`environment_invalid` verification record rather than discarded. Its command
overlapped three accidentally retained duplicate `testhost.exe` processes from
earlier interactive invocations. The resulting suite failed
`REQ_QUIC_INT_0015.ServerRoleEmptyRequestsAcceptsNextConnectionWhilePreviousResponseLingers`
because the interop harness could not bind its default listener:
`SocketException (10048): Only one usage of each socket address
(protocol/network address/port) is normally permitted.` Its complete stdout
and stderr remain at
`C:\Users\Samuel\AppData\Local\Temp\quic-dotnet-release-suite-20260723.stdout.log`
and
`C:\Users\Samuel\AppData\Local\Temp\quic-dotnet-release-suite-20260723.stderr.log`.
This is not a policy result and does not alter any retained c128
classification.

After stopping only the verified duplicate test-process trees, confirming zero
remaining `testhost.exe` processes and no TCP 4433 listener, one clean rerun
of

```powershell
dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release `
  --no-build --no-restore --disable-build-servers --nologo `
  --logger "console;verbosity=minimal"
```

passed with 9,795 passed, 4 expected skips, and zero failures in 10 minutes
25 seconds. Its separately retained stdout/stderr are
`C:\Users\Samuel\AppData\Local\Temp\quic-dotnet-release-suite-20260723-clean-rerun.stdout.log`
and
`C:\Users\Samuel\AppData\Local\Temp\quic-dotnet-release-suite-20260723-clean-rerun.stderr.log`.
This confirms the current quic-dotnet Release correctness gate; it is not a
performance, fairness, policy-selection, shadow, or production-activation
claim.

ProtocolLab internal PR #10 remains independently blocked. Its CI
`build-test` run `30054822177` failed 4 Raw QUIC adapter conformance tests
with `System.Net.Quic.QuicException: The connection timed out from
inactivity` while transferring 1 MiB and 16 MiB download/slow-reader shapes
(1,374 passed, 4 failed, 1,378 total, 7 minutes 2 seconds). Those tests do
not exercise either PR #10 change, but the failed check is preserved as a
correctness blocker: no merge, deployment, package rebuild, or follow-up
ProtocolLab campaign is authorized from that branch until it is resolved or
reviewed with its own evidence. Adjacent policy axes remain
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

### c128 Diagnostic Instrumentation Review Checkpoint

ProtocolLab internal review PR [#10](https://github.com/incursa/protocol-lab-internal/pull/10)
now carries two isolated commits based on current `origin/main`:
`50f75445109b9742f701fb4ec94f1a71fab8ad0b` (`Bound adapter control-plane
cleanup`) and `52c81da0f49c7d74a72cf8105f75106d4b94ef7d` (`Record cold
handshake batch provenance`). The first bounds adapter control-plane requests
at 15 seconds; the second adds a one-based `handshake-batch` coordinate to
each Raw QUIC cold-handshake dial error while retaining the connection index.
`PB-ARTIFACT-0003` and `PB-ARTIFACT-0004` keep both changes explicitly
partial until a fresh independent-host failure-path result is retained.

The review branch's narrow verification is retained in the PR: the Release
test-project build passed with zero warnings and errors; the focused
`RuntimeDiagnosticsTests|LabSchedulerTests` filter passed 60 tests in 8.720
seconds; and `go test ./cmd/quic-go-raw-load` passed in 1.392 seconds. Read-only
PR state at `2026-07-23T23:59Z` is `OPEN`, `REVIEW_REQUIRED`, and
`mergeStateStatus=BLOCKED`; the Contributor Agreement check passed and the CI
`build-test` check is in progress. This is an implementation-ready diagnostic
checkpoint, not a deployment or campaign authorization.

The next c128 action remains deliberately ordered: complete review and CI,
deploy only the exact reviewed commit through the normal ProtocolLab workflow,
re-verify independent host identity and health, then retain one
legacy-current c128 diagnostic with terminal SUT role artifacts, bounded
cleanup evidence, and batch-coordinate output. The old and new diagnostic
rows remain separate and append-only. No policy candidate, shadow rule,
threshold, or active behavior is enabled; all adjacent axes remain
`legacy_current`.

### Raw QUIC Download Conformance: Package Baseline Versus Current Source

The `protocol-lab-internal` Raw QUIC adapter conformance fixture initially ran
without `PROTOCOL_LAB_INCURSA_QUIC_SOURCE_ROOT`. Its server therefore resolved
the declared `Incursa.Quic` package version `1.0.6`, rather than the current
source tree. The focused package-baseline command was:

```powershell
dotnet test tests/Incursa.ProtocolLab.Tests/Incursa.ProtocolLab.Tests.csproj -c Debug --no-build --no-restore --disable-build-servers --nologo --filter "FullyQualifiedName~IncursaRawQuicAdapterConformanceTests.Adapter_writes_exact_deterministic_download_payload&DisplayName~stream-download.1mb" --logger "console;verbosity=normal"
```

It retained one `failed_correctness` package-baseline row: the
`quic.transport.stream-download.1mb` server sent its first 65,536 bytes, then
its next write failed with `NotSupportedException: Writes that wait for
additional flow-control credit are not supported by this slice.` The client
then received the expected idle timeout. The complete server stderr is
preserved at
`C:\Users\Samuel\AppData\Local\Temp\protocol-lab-raw-quic-download-debug-20260723\server.stderr-package-1.0.6.log`
with SHA-256
`4bb2adb42ed51c895100879c7efcc67903d2084ada89e8ded2ab16e8a0bc3d56`.
This is retained negative package evidence only; it is not a result for the
current quic-dotnet commit and must not be silently combined with source-backed
results.

The same fixture was then run with
`PROTOCOL_LAB_INCURSA_QUIC_SOURCE_ROOT=C:\shared\src\incursa\quic-dotnet`
at quic-dotnet commit `cb276ec5e7ee46ea3f0c3c39e347579025a05aa9`. The
adapter rebuilt `Incursa.Quic` from that source tree and rebuilt
`IncursaRawQuicServer` successfully with zero warnings and errors. The
source-backed correctness command was:

```powershell
dotnet test tests/Incursa.ProtocolLab.Tests/Incursa.ProtocolLab.Tests.csproj -c Debug --no-build --no-restore --disable-build-servers --nologo --filter "FullyQualifiedName~IncursaRawQuicAdapterConformanceTests.Adapter_writes_exact_deterministic_download_payload|FullyQualifiedName~IncursaRawQuicAdapterConformanceTests.Adapter_echoes_slow_reader_stream_work_concurrently" --logger "console;verbosity=normal"
```

It passed 5/5 in 41.6380 seconds: exact deterministic download completion for
1 MiB, 4 MiB, 16 MiB with 1 KiB server writes, and 16 MiB with 64 KiB server
writes, plus concurrent slow-reader echo. The 1 MiB server summary records
`readBytes=16`, `sentBytes=1048576`, `reachedEof=True`, and
`completedWrites=True`. The retained source-backed test log is
`C:\Users\Samuel\AppData\Local\Temp\protocol-lab-raw-quic-download-debug-20260723\stdout-source-backed-download-and-slow-reader.log`
with SHA-256
`316e6745f137ad56684b174d2a1eb909f79fd1269064962f62ebca9007f24b1d`.

This clears the current-source local receive-credit/progress checkpoint only
for these deterministic Raw QUIC conformance shapes. It does not clear the
independent-host c128 handshake row, contribute adaptive-policy epochs, or
authorize a Stage 1 axis. The active measurement-only axis remains
`application_send_turn_planning=legacy_current`, and all adjacent axes remain
`legacy_current`.

### Package Provenance Resolution Gate

Read-only review of the ProtocolLab internal build contract establishes that
ordinary adapter conformance intentionally validates the released
`Incursa.Quic` package: `Directory.Build.props` pins
`IncursaQuicVersion` to `1.0.6`, and
`IncursaRawQuicServer.csproj` selects that package unless the explicit
`IncursaQuicSourceRoot` property is supplied. The source-root environment
variable is therefore a useful current-source diagnostic mode, not a valid way
to make the released-package correctness check disappear.

ProtocolLab's source/package parity machinery likewise requires one
source-backed and one package-backed cell and treats missing or failed parity
as a conservative blocker. Accordingly, the retained `1.0.6` failure and the
current-source 5/5 pass are separate evidence records. They establish a
released-artifact correctness discrepancy; they do not establish package
parity, a performance result, or an adaptive-runtime policy result.

The safe resolution is deliberately narrow: retain the package failure,
identify the approved released-package update or remediation path, and rerun
the unchanged package-backed conformance check against the resulting exact
package identity. Do not suppress the Raw QUIC conformance tests, set
`IncursaQuicSourceRoot` in ordinary CI as a bypass, merge unrelated
instrumentation based on the source-only pass, publish a package without the
normal release decision, or deploy a new ProtocolLab campaign from this
diagnostic alone. This is a package correctness and provenance gate; the
available multi-host ProtocolLab capacity remains suitable for the later,
reviewed campaign once that gate is resolved.

### Current-Source Receive-Credit And Stream-Capacity Recheck

The package provenance investigation did not change runtime source. To ensure
that the existing receive-credit and stream-capacity correctness checkpoint
remains present at the current checkout, the already-built Release test binary
was rechecked at quic-dotnet commit
`81e1338ce98b04157eb0036d906c7e68b7729129` with no restore, build, or
performance measurement.

```powershell
dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release --no-build --no-restore --disable-build-servers --nologo --filter "FullyQualifiedName~FlowControlBlockedStreamWriteResumesAfterPeerRaisesStreamCredit|FullyQualifiedName~REQ_QUIC_RFC9000_0177" --logger "console;verbosity=minimal"
```

This passed 6 of 6 flow-control blocked-write/resume tests in one second. Its
retained stdout is
`C:\Users\Samuel\AppData\Local\Temp\quic-dotnet-flow-control-checkpoint-20260723\stdout.log`
with SHA-256
`887ee8ba736f5f4caf625423cd878acf8823892e82aec3417a973f831489407e`.

```powershell
dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release --no-build --no-restore --disable-build-servers --nologo --filter "FullyQualifiedName~REQ_QUIC_API_0009|FullyQualifiedName~REQ_QUIC_API_0014|FullyQualifiedName~REQ_QUIC_RFC9000_S4P5_0001|FullyQualifiedName~REQ_QUIC_RFC9000_S4P6_0005|FullyQualifiedName~REQ_QUIC_RFC9000_S4P6_0010|FullyQualifiedName~REQ_QUIC_RFC9000_S4P6_0011" --logger "console;verbosity=minimal"
```

This passed 32 of 32 stream-capacity/MAX_STREAMS/open-pending tests in three
seconds. Its retained stdout is
`C:\Users\Samuel\AppData\Local\Temp\quic-dotnet-stream-capacity-checkpoint-20260723\stdout.log`
with SHA-256
`b3a354c0db97c82ee9364dc63724a6ba9a963632b170a4c4e982d3adbda281d2`.

These are deterministic correctness checks, not performance evidence. Together
with the retained full Release suite and prior multi-host evidence, they
confirm the prerequisite correctness checkpoint remains preserved. The
separately recorded package `1.0.6` failure remains unresolved and does not
authorize a package-backed campaign, policy transition, or active behavior.

### c128 Instrumentation Review Status Correction

Read-only PR review at `2026-07-23T18:44:00-06:00` updates the earlier
in-progress CI snapshot for ProtocolLab internal PR
[#10](https://github.com/incursa/protocol-lab-internal/pull/10). It remains
`OPEN`, `REVIEW_REQUIRED`, and `mergeStateStatus=BLOCKED`. The Contributor
Agreement check is successful; the `build-test` check is complete with
`FAILURE`.

The failing check is a correctness conformance result, not a performance job:
its Raw QUIC adapter test path resolves the released `Incursa.Quic` `1.0.6`
package unless the explicit source-root diagnostic override is supplied. The
separate package-backed failure and source-backed 5/5 pass recorded above
explain the provenance distinction but do not make the package failure
acceptable. The source-root override must not be added to ordinary CI as a
workaround, and the conformance test must not be excluded under the new
correctness-only CI policy.

Consequently, PR #10 is not a merge, deployment, or fresh-c128-campaign
authorization. Its bounded-finalization and batch-ordinal instrumentation
remain a clean implementation-ready diagnostic slice, pending normal review
and a package-correctness resolution that preserves the unchanged
package-backed conformance gate. This preserves the c128 row, the package
failure, and the source-current result as distinct append-only evidence.

### Released-Package Provenance and Remediation Boundary

Read-only package provenance establishes the exact release relationship. The
locally restored `Incursa.Quic` `1.0.6` package declares repository commit
`d604e1f1b30291589a0cbae00e9fbe73786ba0bb`, which is the signed `v1.0.6`
release tag from 2026-05-30. The current-source blocked-write retry commit is
`79e995c3ee6a373964028809cfd2c1fed0ff1401` (`Retry blocked peer stream
capacity replays`, 2026-07-23); it is an ancestor of the current checkout and
is not contained by any release tag. The source-backed conformance pass is
therefore consistent with source history, while the `1.0.6` failure is a real
released-artifact defect.

The repository release policy classifies a compatible behavioral correction as
a patch release and requires a maintainer-controlled version tag before the
NuGet publish workflow runs. No tag, package version change, publish workflow,
or NuGet upload has been created in this diagnostic slice. The next release
decision must select an exact reviewed commit and patch version, then rerun the
unchanged package-backed Raw QUIC conformance tests against the published
package identity. Until that explicit release work is approved and complete,
ProtocolLab internal's `1.0.6` correctness failure, PR #10's red check, and
the package-parity gate remain open; no test exclusion, source-root override,
or policy experiment may substitute for them.

### Unpublished Package-Candidate Conformance Diagnostic

To distinguish a current-source project reference from the bytes that a future
release would carry, a local-only prerelease package candidate was packed from
the clean current checkout at
`653381b90ae8997ca7f49a2444d587edcd24817c`. The candidate identity is
`Incursa.Quic` `1.0.8-rc.20260723.1`; its SHA-256 is
`5199e4c041e3b691c6dbbc40a2608d9237439df8ed794d46d9a4fc8986560bee`.
It was restored through an explicit local PackageSourceMapping in an isolated
ProtocolLab internal checkout at
`db96f41ec1421fc6f299283f31a5be444efbc52e`, rather than through
`PROTOCOL_LAB_INCURSA_QUIC_SOURCE_ROOT`. The built Raw QUIC server dependency
file names that exact prerelease package and has SHA-256
`a9de436ab1e8cf741484282dfdc9539719a9425deaa07d13c247c8b71fce3791`; its
copied `Incursa.Quic.dll` has SHA-256
`6226e213776c67987eaf7ed75237939794434c02f642afa06848b9efdf1edcbf`.

The first isolated invocation is retained as `environment_invalid`: the fresh
checkout did not yet contain the adapter executable, so all five selected
tests failed before a Raw QUIC server could start. Building that unchanged
adapter in the isolated checkout corrected only the test environment. The
candidate package itself, server selection, test filter, and source-root
absence were unchanged.

The subsequent deterministic package-backed command was:

```powershell
dotnet test tests/Incursa.ProtocolLab.Tests/Incursa.ProtocolLab.Tests.csproj -c Debug --no-build --no-restore --disable-build-servers --nologo --results-directory C:\shared\src\incursa\quic-dotnet\.artifacts\adaptive-runtime\package-conformance-candidate-20260723 --logger "trx;LogFileName=candidate-package-conformance.trx" --filter "FullyQualifiedName~IncursaRawQuicAdapterConformanceTests.Adapter_writes_exact_deterministic_download_payload|FullyQualifiedName~IncursaRawQuicAdapterConformanceTests.Adapter_echoes_slow_reader_stream_work_concurrently"
```

It passed 5 of 5 in 23 seconds: 1 MiB, 4 MiB, and both 16 MiB deterministic
download shapes plus concurrent slow-reader echo. The retained TRX is
`C:\shared\src\incursa\quic-dotnet\.artifacts\adaptive-runtime\package-conformance-candidate-20260723\candidate-package-conformance.trx`
with SHA-256
`5670cd574cca0efc84aad56929ab5d2df525a19c6679ff3e51d2ca552a35983d`.

This is a local release-candidate correctness diagnostic only. It strengthens
the case for a reviewed patch release but does not publish the package, alter
the internal `1.0.6` pin, clear the released-package failure, establish
source/package parity for a published artifact, enable an adaptive policy, or
authorize a ProtocolLab campaign.

### Published-Version Fix Containment Audit

The local release-candidate result was followed by a read-only audit of every
currently published repository tag newer than the failing `v1.0.6` package.
`v1.0.7` resolves to `4ae0c3bf75d6f28e2c705bd12bcf593d5343f9df`, dated
2026-05-31, and does not contain the required retry commit
`79e995c3ee6a373964028809cfd2c1fed0ff1401`. Neither `v1.0.6` nor `v1.0.7`
therefore contains the known stream-capacity replay correction. Updating the
ProtocolLab internal pin to `1.0.7` would be a relabeling workaround rather
than a correctness resolution and is not authorized.

The release prerequisite remains a new maintainer-reviewed patch version from
an exact post-`79e995c3` commit, followed by the unchanged package-backed Raw
QUIC conformance suite against that published identity. This audit changes no
package, tag, NuGet state, dependency pin, ProtocolLab deployment, controller
job, or runtime policy behavior.

### Release-Candidate Package Conformance Guard

The remediation path now has a permanent pre-publish correctness guard. The
NuGet publish workflow packs the candidate, checks out the private ProtocolLab
internal fixture through a dedicated read-only credential, and runs
`Test-IncursaQuicPackageConformance.ps1` before any NuGet push. The helper
rejects `PROTOCOL_LAB_INCURSA_QUIC_SOURCE_ROOT`, restores the exact candidate
from an isolated local feed, verifies that the Raw QUIC server resolves that
package and consumes the matching `Incursa.Quic.dll`, then retains its TRX and
JSON summary. It runs no BenchmarkDotNet or ProtocolLab performance campaign.

The guard was proven against the retained local candidate
`Incursa.Quic` `1.0.8-rc.20260723.1`: package SHA-256
`5199e4c041e3b691c6dbbc40a2608d9237439df8ed794d46d9a4fc8986560bee`,
package/server assembly SHA-256
`6226e213776c67987eaf7ed75237939794434c02f642afa06848b9efdf1edcbf`,
and source-root absence all matched. Its exact deterministic download and
slow-reader filter passed 5 of 5 with zero failures; the TRX at
`.artifacts/adaptive-runtime/release-gate-candidate-20260723/package-backed-raw-quic-conformance.trx`
has SHA-256
`727d18b6e5e0956fdab9cdbf77056ecec5dca438435591584251e293a46ce7fb`.
An attempted run with a populated source-root override failed before restore or
build, as required. This proves the pre-publish gate implementation; it does
not publish a package, clear the retained `1.0.6` failure, update an internal
pin, clear PR #10, authorize a controller job, or enable policy behavior.

### CI Checkpoint: Legacy Aggregate-Specification Backlog

The `077eca83` CI run confirmed that its two ProtocolLab package-smoke jobs
passed, but it stopped before build and correctness tests when the changed
legacy aggregate `SPEC-QUIC-INT.json` failed the published core schema. The
artifact is already structurally incompatible with that schema (string-valued
`related_artifacts` plus legacy top-level fields); the repository migration
helper only normalized ordering and did not make it valid. The release-gate
requirement wording is therefore restored to its prior text in the corrective
checkpoint. The retained architecture, work-item, and verification homes keep
the implementation and verification trace; the aggregate-specification
migration remains an explicit separate backlog item. CI validation is not
suppressed or weakened, and no performance task was executed in this run.

### Correctness-Only CI Follow-Up Diagnostics

GitHub Actions run `30060518822` at commit
`16896ae0f275f41967906617d53a0aae46d9a556` retained three correctness
failures: MAX_STREAMS recovery-arm assertion, HTTP/3 request-DATA-before-
HEADERS close, and dropped server FIN recovery observation. The build and both
package-smoke jobs passed; 9,793 tests passed, 3 skipped, and 3 failed. The
previous native System.Net HTTP/3 interop failures were absent after the
platform-support guard. This remains a failed-correctness row; it is not
reclassified by the focused reruns below.

The follow-up changes only test-side observability. HTTP/3 close waits can now
include bounded server diagnostic events on timeout. The FIN recovery test now
records a later application packet containing FIN rather than requiring the
newest application packet at every socket-send callback to contain FIN. No
runtime behavior, policy value, controller input, BenchmarkDotNet job, or
ProtocolLab campaign changed.

At the same source checkpoint, the following correctness build and focused
test command passed 4 of 4:

```powershell
dotnet build tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --configuration Release --no-restore
dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --no-build --configuration Release --filter "FullyQualifiedName~TransitionStreamCapacityRelease_ArmsRecoveryForTheMaxStreamsPacket|FullyQualifiedName~RequestDataBeforeHeaders_ClosesConnectionWithFrameUnexpected|FullyQualifiedName~RequestCancelPushFrame_ClosesConnectionWithFrameUnexpectedBeforePayloadParsing|FullyQualifiedName~DroppedServerFinIsRecoveredAndShardContinuesProcessing" --logger "console;verbosity=normal"
```

The complete correctness-only Release suite was then run with:

```powershell
dotnet test Incursa.Quic.slnx --no-build --configuration Release --filter "Category!=Performance" --logger "console;verbosity=minimal"
```

It passed 9,796 tests, skipped 3, and failed none in 10m44s. The retained
stdout is
`C:\\Users\\Samuel\\AppData\\Local\\Temp\\quic-dotnet-ci-correctness-20260723\\full-release-correctness-after-diagnostics.stdout.log`
with SHA-256
`67EC1889BEA43B487E6B028016F14D81FBA81B673C92CD1C265D1A01437A66B7`.

An additional ten sequential executions of the FIN recovery test all passed.
They are retained as `diagnostic_only` local correctness evidence, not a
replacement for the failed CI row and not a performance campaign. Raw outputs
are at
`C:\\Users\\Samuel\\AppData\\Local\\Temp\\quic-dotnet-ci-correctness-20260723\\listener-fin-recovery-diagnostic-{1..10}.log`;
their SHA-256 inventory is:

```text
1  04C71A7BFBDFAC49E93045D4D2312E7941D3D94FE1AA64AABC6E2CFBB18B7AA9
2  FC0904CA0CC736697C1D3A99271D73D348DA9E7BCD9616C0A249C0F42F0C009B
3  CF24520C26419555084A6BD1B436A01A9DCA786A3DE3A3508E75ED0D339801D7
4  1AA4B05DC8D47A9127A88DEDDEB38E439D86AE3773BC49509D30109FB8104E64
5  1A4CB4D8E814248A1A1FCDFD8CC6418FEEB038D62EA5C76A109B9E86A939876D
6  72F6E6C47C7ABDB1828A36523C5C29F1C5274EC5507C00FD3A55A67860699133
7  A33FABE69A007A711C1CC1625753089199E5D88077B68BFE13A2E42EEAAAC075
8  3BCBCB059F0025360FDA2B6F8852D52776DC1B6C35A21AFEAD1CD1A4014C0156
9  5AAFECF2E1DD0242A1A1F0C3F9D4FD435EE457E7ADFFE7EC241666CA029ACEA1
10 FBD33ABF25EF79777B76E4AADCAEA13337B51086109861B1E6C5D1CB8D3A24E1
```

The active adaptive-runtime axis remains
`application_send_turn_planning=legacy_current`; all adjacent axes remain
`legacy_current`. CI remains correctness-only and is not monitored by this
slice. The next in-scope gate is permanent-runner send-turn evidence
integration. No adaptive policy behavior is active.

## Application-Send Turn Raw-To-Epoch Export Checkpoint

Checkpoint commit `4242d98f` implements the standalone
`application_send_turn_planning` raw-to-epoch evidence boundary. It adds the
closed `adaptive-runtime-application-send-turn-raw-v1` schema, deterministic
integer timestamp and Q16 conversion, observe-only and shadow mapping,
snapshot/turn ordering checks, write-once pending output, schema-valid epoch
rows, and a checksum manifest. It also permits `legacy_current` as an explicit
controller state and permits null `hasIssuedApplicationData` where this
axis-specific observation does not capture that receive-credit signal.

The active axis remained `application_send_turn_planning`; receive-credit and
all adjacent axes remained `legacy_current`. No runtime policy consumer,
production default, threshold, BenchmarkDotNet job, CI performance job, local
campaign, ProtocolLab submission, dataset pipeline, offline model, or
active-internal behavior changed.

The exact local correctness commands were:

```powershell
dotnet build tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release --no-restore --nologo -m:1 -nodeReuse:false -p:UseSharedCompilation=false
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release --no-build --nologo --filter "FullyQualifiedName~REQ_QUIC_CRT_0169|FullyQualifiedName~REQ_QUIC_CRT_0176" --logger "console;verbosity=minimal"
```

The Release build passed with zero warnings and zero errors. The focused
schema plus active-axis run passed 33 of 33 tests with zero failures and zero
skips. Both canonical raw JSONL fixtures passed the new raw schema; the
converter passed PowerShell parsing; and `ARC-QUIC-CRT-0065`,
`WI-QUIC-CRT-0066`, and `VER-QUIC-CRT-0067` each passed the published
SpecTrace core schema independently.

Fixture conversion produced three schema-valid interval rows: one shadow row
with `analysisExclusionFlags = ["none"]` and two final rows retained with
`terminal_partial_epoch`. These are verification fixtures, not campaign rows,
so campaign inclusion/exclusion counts remain zero and no policy claim is
derived from them.

Three development failures remain classified `diagnostic_only`:

- the initial exporter draft failed PowerShell parsing at `return switch`;
- the first schema run correctly rejected a scalar
  `analysisExclusionFlags = "none"`; and
- the first two-row run exposed a valid first row before a later converter
  failure.

The last two diagnostic rows remain retained at
`.artifacts/adaptive-runtime/debug-send-turn-export-current/` and
`.artifacts/adaptive-runtime/debug-send-turn-export-current2/` with SHA-256
`4072c77f10f12af83935d05a08ef861637522f29097e7260e814f46216a5b701`
and
`9a781345716301cf02c4e97a5c88bd09a63b5cbd143d154a34575d784baedbda`,
respectively. They have no completion manifest and are not valid campaign
evidence. The corrected exporter keeps later input-validation partials under a
retained `.pending` directory and does not expose them as completed root rows.

The first incomplete gate is permanent-runner capture and result/checksum join
for the new send-turn raw stream. Local forced/shadow campaigns, multi-host
ProtocolLab work, offline analysis, and review remain downstream and
unauthorized until that join is implemented and the correctness gates pass.

## Application-Send Turn Permanent Runner Join Checkpoint

Local checkpoint commit `71206236` closes the permanent-runner capture and
result/checksum join implementation gate for shadow-only
`application_send_turn_planning`. The runner now retains the versioned raw
turn stream per sample, invokes the standalone exporter, retains completed
epoch rows and the export manifest, adds those artifacts to the cell checksum
inventory, and validates each row's result, sample, and raw-source joins. The
forced construction-provenance path remains separate. The final one-tick
exporter sentinel remains retained and excluded as
`terminal_partial_epoch`; the validator recognizes that exclusion only for the
closed exporter, transformation, and observation version tuple.

The active axis remained `application_send_turn_planning`; receive-credit and
all adjacent axes remained `legacy_current`. No runtime policy consumer,
production default, threshold, BenchmarkDotNet job, CI trigger, CI run, local
campaign, ProtocolLab submission, dataset pipeline, offline model, or
active-internal behavior changed. Commit `71206236` is local only and was not
pushed.

The exact verification commands and results were:

```powershell
dotnet build tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release --no-restore --nologo -m:1 -nodeReuse:false -p:UseSharedCompilation=false
dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release --no-build --nologo --filter "FullyQualifiedName~REQ_QUIC_CRT_0172|FullyQualifiedName~REQ_QUIC_CRT_0174|FullyQualifiedName~REQ_QUIC_CRT_0176" --logger "console;verbosity=minimal"
pwsh -NoProfile -File ./eng/adaptive-runtime/Invoke-AdaptiveRuntimePolicyLocalCell.ps1 -PolicyAxis application_send_turn_planning -ShadowOnly -PolicyA legacy_current -PolicyB conservative -DryRun -OutputRoot ./.artifacts/adaptive-runtime/send-turn-shadow-runner-dryrun-20260723
```

The Release build passed with zero warnings and zero errors. The evidence
validator, permanent-runner contract, and raw-to-epoch requirement homes passed
45 of 45 tests with zero failures and zero skips. PowerShell parsing passed for
the runner, send-turn exporter, and evidence validator. The dry run selected
one custom shadow-only sample with `legacy_current` applied and created only
the empty `protocol-lab-runs` and `samples` scaffold under
`.artifacts/adaptive-runtime/send-turn-shadow-runner-dryrun-20260723`.
`ARC-QUIC-CRT-0065`, `WI-QUIC-CRT-0066`, and `VER-QUIC-CRT-0067` each passed
`model/model.schema.json` independently.

The repository-wide command
`pwsh -NoProfile -File scripts/Validate-SpecTraceJson.ps1 -Profiles core`
remains a `diagnostic_only` blocked baseline: it reported 2,692 errors across
the pre-existing corpus, including unrelated aggregate specifications and RFC
artifact families. The changed trace artifacts pass the narrow schema gate;
this checkpoint neither repairs nor hides that broader repository condition.

No executed campaign rows were produced. Campaign inclusion and exclusion
counts therefore remain zero, and there is no policy or neutrality
classification. The next gate is an executed permanent local shadow
correctness/evidence cell, followed by disabled-versus-observe-only neutrality
and the already-planned manual or nightly BenchmarkDotNet mechanism checks.
No multi-host or active-policy work is authorized by this checkpoint.

## Application-Send Turn Executed Shadow And Validation Correction

The first two executed permanent-runner shadow cells remain append-only under:

- `.artifacts/adaptive-runtime/adaptive-send-turn-shadow-local-20260723-r001/`;
  and
- `.artifacts/adaptive-runtime/adaptive-send-turn-shadow-local-20260723-r002-diagnostic/`.

Both executed exact committed source `a4fb7f5c`. The target benchmark SHA-256
was
`ed1a1ffba26f3d4ca9ae50501fe2beba200a1797b9f35ed08e059584ac68a910`;
the runtime SHA-256 was
`f22377bd10cd3e470393a5f458de72e6c00716479a9e14f42d713edf26f0de88`.
The retained cell manifests contain the exact inner ProtocolLab commands.
Both were same-host local correctness/evidence cells, not independent-host
performance claims.

The `r001` cell captured 5,754 raw turns from two connection keys. Every turn
recommended `conservative` for `missing_signal`. The raw stream SHA-256 is
`a44961c996cf1528c5323344615115f3d891df94736531f896cfaed4c441466a`.
The exporter completed its 5,754 row files and checksum inventory, but the
runner failed while finalizing a single distinct shadow-policy value because
PowerShell unwrapped that one-element collection to a scalar. It emitted no
`local-result.json` and no evidence-validation result. This cell is retained
unchanged as `diagnostic_only`; it is not admitted to normalized or curated
data. Commit `98941aad` fixes that runner finalization defect using an explicit
string array and adds a permanent contract assertion.

The bounded `r002` diagnostic cell used one connection, sixteen streams,
64-KiB per stream, zero warmup seconds, one measurement second, and
`legacy_current` applied in shadow mode. Requested and effective workload
identity matched. It retained 6,328 raw turns and 6,328 unique epoch rows across
two connection keys. The schema-valid local result is `neutral_local`; target
and generator health are both `limited` because the topology is `same_host`.
It records 46 transitions, no missing, stale, contradictory, or out-of-domain
epochs, 2,208 `legacy_selector` reasons, and 4,120
`arithmetic_saturated` reasons. The raw stream SHA-256 is
`49efc480584ba2fe823025cbc129613e55abc8cadbd4cdfc3650f95ae13d567c`.
The local-result SHA-256 is
`1acbcd34b50ab4872196dea6d2ca7523c4f2d49e5d8bc525d569becd18e500cc`.

The originally retained `evidence-validation.json` remains invalid with 42
failures. Those failures exposed a validator defect: it treated every
legitimate one-microsecond interval as the exporter's terminal sentinel.
Commit `98941aad` instead precomputes the maximum epoch index for each exact
run/sample/connection/exporter/version tuple, requires
`terminal_partial_epoch` only on that row, and rejects the flag on any earlier
row. The original invalid validation file remains at SHA-256
`37ce833adf231657a23b03839da864192617196ae3e8aad20a628058e3985a1e`.
The append-only correction is
`evidence-validation.correction-98941aad.json`, SHA-256
`b37d39a456b0702b810bde6c75f4c92040536830730e7e1b7ca437b11a8445f0`.
It is valid with 1 local result, 6,328 rows, 6,328 unique rows, 1 checksum
inventory, 11 unique artifact hashes, and zero failures. The original
validation was not overwritten or relabeled.

The single sample's descriptive outcomes were 1,462,383.419 bytes per second,
22.314 operations per second, 662.392 ms p50, 736.322 ms p95, 161,769,248
buffer-pool rented bytes, and 475,136 peak outstanding buffer-pool bytes.
Managed allocation, peak retained memory, and true stream fairness remain
unavailable. These are one sample's same-host descriptive outcomes, not an
accepted performance claim and not 6,328 independent measurements.

The Release test build passed with zero warnings and zero errors. The focused
requirement homes for `REQ-QUIC-CRT-0169`, `0172`, `0174`, and `0176` passed
54 of 54 listed tests after the validation correction and later analysis
adapter. No CI workflow was monitored or changed, and no performance test ran
in CI.

## Application-Send Turn Normalized Dataset And Offline Analysis Checkpoint

Commit `e289bb10` admits `application_send_turn_planning` as a distinct closed
normalized-dataset axis. Commit `a092dafd` adds the closed `modelFeatures`
block containing only bounded pre-decision runtime observations. Workload,
scenario, payload, requested concurrency, peer, URL, and application identity
remain outside that production-eligible feature block.

The first materialization attempt at
`.artifacts/adaptive-runtime/datasets/send-turn-shadow-r002-98941aad/`
correctly failed because the normalized schema still required
`receive_credit_publication`. Its catalog remains retained at SHA-256
`4406580afa069baa2e53afa5146c4485862eb97d49a30a83cfcc005813258f35`;
the attempt is `diagnostic_only` and was not silently completed.

The first completed append-only materialization is
`.artifacts/adaptive-runtime/datasets/send-turn-shadow-r002-e289bb10/`.
Its four artifact hashes are:

```text
catalog     4fb01bb5da59c8ec7cff2687efea3d8abf0829504fd350028b15d3da04449895
normalized  d7dcd9858fb774fa405745c6f800a82870c645fdee61e5e35083207d677afb0c
curated     a69187f069aea72ac04843298fe996b08db4887f785bb610db31f819450f2730
split       6c9541b7cf92846734ec3876561cb06fdec15f69a68e090635bbd3a12a7c9c36
```

It joined all 6,328 rows with zero unmatched results and zero unmatched epochs.
The curated layer includes 2,206 rows and preserves 4,122 excluded rows:
4,120 carry `observation_saturated`, 41 carry
`instrumentation_mismatch`, and 2 carry `terminal_partial_epoch`; flags can
overlap. No retained-negative row is present. All 6,328 split assignments are
`holdout_blocked`; train, validation, and test each contain zero rows because
the source has only one host fingerprint and one workload family.

The model-feature materialization is
`.artifacts/adaptive-runtime/datasets/send-turn-shadow-r002-a092dafd/`.
Its hashes are:

```text
catalog     32bb5ea175b0492b4ba7a960d4ab7830b36add914b6141221dc5b15cc3b06daf
normalized  c99b7777add81fc5f00e0b3b5c8e2cefbf27977f7ff0e47b5c98c35f2da5ba8e
curated     67e6baa2569f963027d52d70f79ba7361e5af54775b24486adc128b95cb046e4
split       916ccffeb7f8f6d3c788341ec7983b34a5976e1d50576d647b0e24ead2b5bd9f
```

It preserves the same 6,328 joined, 2,206 included, 4,122 excluded, zero
unmatched, and 6,328 holdout-blocked counts. It is suitable for descriptive
offline inspection but not model training or a policy-effect claim.

Local commit `56704568` adds the versioned application-send analysis adapter
and schema. The adapter validates each source schema, the exact
normalized-to-curated-to-split IDs and checksums, complete unique row-ID
coverage, closed send-turn policy values, source summary counts, and prohibited
production inputs. It keeps sample outcomes separate from epoch feature
distributions and cannot authorize active behavior.

The exact analysis command was:

```powershell
pwsh -NoProfile -File eng/adaptive-runtime/Measure-AdaptiveRuntimeApplicationSendTurnDataset.ps1 `
  -NormalizedDatasetPath .artifacts/adaptive-runtime/datasets/send-turn-shadow-r002-a092dafd/normalized/normalized-dataset.json `
  -CuratedManifestPath .artifacts/adaptive-runtime/datasets/send-turn-shadow-r002-a092dafd/curated/curated-manifest.json `
  -SplitManifestPath .artifacts/adaptive-runtime/datasets/send-turn-shadow-r002-a092dafd/split/split-manifest.json `
  -OutputPath .artifacts/adaptive-runtime/analysis/send-turn-shadow-r002-56704568/application-send-turn-analysis.json `
  -AnalysisId application-send-turn-shadow-r002-analysis-v1
```

The report SHA-256 is
`88289cdc29011ebe3f8af498f659759623d4c1532f0b67b51c46a7fef8273801`
and its exact code commit is
`567045684c3546bb874cdeb4ac4e089bc912207f`. The leakage audit passed
with zero forbidden features found. It reports one included sample, one host
fingerprint, one workload family, 2,206 included epochs, and 4,122 excluded
epochs. Selected feature summaries over included rows are:

| Feature | Minimum | p50 | p95 | Maximum |
| --- | ---: | ---: | ---: | ---: |
| queued application writes | 1 | 4 | 12 | 14 |
| outbound backlog bytes | 9 | 22,069 | 145,700 | 165,978 |
| distinct queued streams | 1 | 4 | 12 | 12 |
| queue-delay EWMA microseconds | 8,400 | 66,794 | 100,591 | 109,327 |
| actor-service EWMA microseconds | 152 | 533 | 1,278 | 6,897 |
| queue-to-service ratio Q16 | 429,116 | 7,716,590 | 22,535,393 | 41,214,819 |
| congestion window bytes | 6,000 | 118,589 | 161,909 | 166,494 |
| bytes in flight | 167 | 98,681 | 157,258 | 164,834 |
| retained send bytes | 2,048 | 32,768 | 182,272 | 198,656 |

`oldestQueuedSendAgeMicros` is missing for all 2,206 included rows and remains
null rather than being imputed. All included rows have zero missing and stale
masks. The report status is `holdout_blocked`, the candidate rule is null, and
`activeInternalAuthorized` is false. This is the honest result of insufficient
group diversity, not a ProtocolLab availability blocker.

The analysis checkpoint verification commands were:

```powershell
dotnet build tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release --no-restore --nologo -m:1 -nodeReuse:false -p:UseSharedCompilation=false -p:BuildProjectReferences=false
dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release --no-build --no-restore --nologo -m:1 -nodeReuse:false -p:UseSharedCompilation=false -p:BuildProjectReferences=false --filter "FullyQualifiedName~REQ_QUIC_CRT_0169|FullyQualifiedName~REQ_QUIC_CRT_0172|FullyQualifiedName~REQ_QUIC_CRT_0174|FullyQualifiedName~REQ_QUIC_CRT_0176" --logger "console;verbosity=normal"
```

The build passed with zero warnings and zero errors. All 54 focused tests
passed. `ARC-QUIC-CRT-0065` and `VER-QUIC-CRT-0067` each passed
`model/model.schema.json` independently. The repository-wide SpecTrace core
baseline remains the previously retained 2,692-error `diagnostic_only`
condition; this slice did not hide or repair unrelated corpus failures.

At this checkpoint the branch is local-only and six commits ahead of
`origin/main`; no push was attempted. BenchmarkDotNet has not run in this
slice. No multi-host ProtocolLab cell has run yet, but the known lab is not
classified as unavailable. The next current-axis gate is the permanent local
disabled-versus-observe-only neutrality comparison, followed by manual or
nightly BenchmarkDotNet mechanism checks and independently hosted
counterfactual cells. `application_send_turn_planning` remains applied as
`legacy_current`, every adjacent axis remains `legacy_current`, and the next
portfolio axis remains unauthorized.

## Application-Send Observation Neutrality And Retained-Negative Dataset

Commit `3251c2c7` adds the permanent same-binary
disabled-versus-observe-only cell. Commit `35da03b8` corrects its evidence
validator by replaying the checksum-pinned raw observation conditions instead
of inferring observe-only exclusions from absent shadow reason codes. The
original invalid validation result remains retained and unchanged.

The executed cell is:

```text
campaign  adaptive-send-turn-observation-neutrality-local-20260724-r001
cell      duplex-64kb-x1-s16-neutrality
sequence  ABBA
A         disabled; application-send environment variable unset
B         observe_only; recommendation-free evidence required
applied   legacy_current for both treatments
adjacent  legacy_current
```

It used one connection, sixteen streams, 64 KiB per stream, zero warmup
seconds, and one measurement second. All four samples were exact-payload valid
with zero failed, timed-out, protocol-error, or invariant-failure operations.
The two disabled samples emitted no application-send construction or
observation record. The two observe-only samples emitted 6,983 and 6,587 raw
turns respectively, for 13,570 unique exported epochs. All 13,570 are
recommendation-free.

The append-only artifact hashes are:

```text
local result                 573aa61683c52936a15cbbe555a08e8e6c845a061c3dda1d69245048f37a3926
cell manifest                4ea278abe3ae7b5c493fc58fed3ffd457091f9e89727f4c2e9c6486a5248dd09
checksum inventory           6c0e9756fe3fa7e016f993f71c3ee7d16ec85e9378ae9ef9aa21aa7242f5c96d
original invalid validation  b269eedef9d582af5d786aa9c7c9e9f9aecaeccac677b7846dbd3c46fe19e61a
correction at 35da03b8       d98274c8289192f74dbf099154d2fc52e2d789c8b2fb488990e8ae256b83a838
```

The original validation has 8,747 failures because it expected an analysis
clean row whenever an observe-only record had no shadow reason. The runtime
and exporter correctly retained `observation_saturated` when the raw
`ArithmeticSaturated` condition was present. The correction independently
replays that raw condition stream and validates one result, 13,570 rows,
13,570 unique rows, zero construction rows, one checksum inventory, 24 unique
artifact hashes, and zero failures. The original result was not overwritten or
used as a rerun-erasure mechanism.

The cell is `negative_retained`, not neutral:

| Outcome | Disabled median | Observe-only median | Disposition |
| --- | ---: | ---: | --- |
| Throughput | 1,764,812.637 B/s | 1,681,533.670 B/s | about -4.72% |
| p95 latency | 589.771775 ms | 639.765725 ms | about +8.48%; negative gate |

Maximum within-treatment relative range was `0.042894686`, below the
five-percent environment-invalid bound. Aggregate throughput was
1,717,915.359 B/s, aggregate operation rate was 26.2133/s, p50 was
587.6055 ms, p95 was 609.889625 ms, p99 was 611.177755 ms, buffer-pool rented
bytes were 189,528,736, and peak outstanding bytes were 868,352. Target and
generator health remain `limited` because this is one same-host cell. This is a
bounded retained-negative instrumentation-cost screen, not a general
performance claim.

The completed dataset root is
`.artifacts/adaptive-runtime/datasets/send-turn-observation-neutrality-r001-35da03b8/`.
The exact transformation commit is
`35da03b8f99b37e62977ca67e2d0d69b26f42cab`. Its hashes are:

```text
catalog     b5ffaa3a2bfbf4a35f46852010845996eb0621c2ec56f6a0bf14c403acb85929
normalized  8c666c1590751d1da70a78056e0246f25fc0c4b880a039f605a03c0bb664cb09
curated     929e08c2815053f34afeacf7ed2fed4b60e4d099040580ac3d67661e3420a06f
split       cac1264826fa91d719ad21444c937454b525f548bdd5485120cc2e86e2eeed13
```

All 13,570 epochs joined with zero unmatched epochs. The two disabled sample
results are retained as unmatched source results because the disabled
treatment is required to emit no epoch rows. Curation includes 4,819
`retained_negative` rows and preserves 8,751 excluded rows. Source flags are
4,819 `none`, 8,747 `observation_saturated`, 78
`instrumentation_mismatch`, and 4 `terminal_partial_epoch`; flags can overlap.
All 13,570 split assignments remain `holdout_blocked`, with zero train,
validation, or test rows.

The ML-facing descriptive report is
`.artifacts/adaptive-runtime/analysis/send-turn-observation-neutrality-r001-f9ae565/application-send-turn-analysis.json`.
Its SHA-256 is
`26269ed93fbd70cf2b90e2bdff854cc6407565d3214a9bff54d0bf2a2ff648e9`
and its analysis commit is
`f9ae5653aca736ef1dddd7463970eecbefb3d950`. The leakage audit passed
with no forbidden workload or identity input. It reports two included samples,
one host fingerprint, one workload family, and
`ruleProposal.status = holdout_blocked`; the candidate rule is null and
`activeInternalAuthorized` is false.

Selected distributions over the 4,819 included epochs are:

| Feature | Minimum | p50 | p95 | Maximum |
| --- | ---: | ---: | ---: | ---: |
| queued application writes | 1 | 5 | 12 | 12 |
| outbound backlog bytes | 21 | 32,878 | 152,394 | 180,016 |
| distinct queued streams | 1 | 5 | 12 | 12 |
| queue-delay EWMA microseconds | 5,224 | 67,951 | 94,231 | 107,742 |
| actor-service EWMA microseconds | 132 | 492 | 1,106 | 5,064 |
| queue-to-service ratio Q16 | 547,414 | 8,228,522 | 24,163,328 | 47,389,125 |
| congestion window bytes | 6,000 | 134,516 | 178,486 | 250,580 |
| bytes in flight | 104 | 113,312 | 171,263 | 235,636 |
| retained send bytes | 512 | 49,152 | 196,608 | 196,608 |

`oldestQueuedSendAgeMicros` is absent for all included rows and remains null.
The two included sample-scoped throughput outcomes span 1.591706 to
1.615565 MiB/s and p95 spans 626.04445 to 653.487 ms. Those two values are
descriptive samples, not 4,819 independent policy outcomes.

## Application-Send Mechanism Benchmarks And Lab Package Gate

Commit `173f2269` adds manual/nightly BenchmarkDotNet cases for bounded queue
snapshot construction, deterministic nominal and guarded controller
evaluation, immutable snapshot construction, and independently forced policy
reads. It does not add a policy value, threshold, or production consumer.

The Release benchmark build passed with zero warnings and zero errors. The dry
run completed 10 of 10 cases. The committed short run used BenchmarkDotNet
0.15.8, .NET SDK 10.0.204, .NET runtime 10.0.10, Windows x64, and commit
`f9ae565`. Every case reported zero managed allocation.

| Mechanism | Short-run mean |
| --- | ---: |
| nominal controller evaluation and snapshot | 21.13 ns |
| missing-signal fallback | 21.08 ns |
| stale-signal fallback | 21.22 ns |
| arithmetic-saturated fallback | 21.10 ns |
| out-of-domain fallback | 21.87 ns |
| bounded snapshot, 1 queued write | 48.93 ns |
| bounded snapshot, 16 queued writes | 593.89 ns |
| bounded snapshot, 64 queued writes | 2,378.60 ns |

The forced legacy/current and conservative read cases completed without
allocation but measured below reliable timer resolution; no timing claim is
made from them. The three report hashes are:

```text
controller   c8c7abd9d8ff4e0038d8dd2fe593bd6713b1763ec1379714975d91b93f33ba9a
observation  541a3383ad24b1cdf57dbc7c8cd9c71cd84412f3876a384e6e77b8400ae99700
policy read  2ddee21f57d36e8af9be59300fa26f85bc967ae1893b6c7f57f221dd8e130884
```

The retained short-run console log SHA-256 is
`7a241968bd775e20f480319247bf310ee09303ab4e7686b7c105f914bf4bf966`.
These are mechanism-cost numbers only. They do not change a production rule
and do not replace the retained end-to-end neutrality result.

Commit `f9ae565` extends the existing raw QUIC package builder and submit
helper so the independently selected application-send identities
`legacy_current`, `conservative`, `observe_only`, and `shadow` can be stamped
into immutable ProtocolLab packages. HTTP/3 package use is rejected. The
focused `ProtocolLabPackageTemplateTests` home passed 23 of 23 tests after a
zero-warning Release test-project build.

A clean, non-uploaded Linux x64 shadow package was built from exact commit
`f9ae565`:

```text
identity     quic-dotnet-raw-dev@dev-20260724-f9ae565-shadow
package SHA  b142f951ae1295c631d2b455b2c66ec5fd4783e50062dfe1d460e51a816f626a
attestation  2bfd386fa1b03dbe6e77502a349b49ad720a5b497bc105bb3dd661645430048e
bytes        1,237,944
entries      22
parity       eligible
```

The archive's implementation manifest contains exactly
`PROTOCOL_LAB_INCURSA_RAW_QUIC_APPLICATION_SEND_TURN_POLICY: shadow` and no
receive-credit override. No package was uploaded and no lab job was created.

The first post-reboot read-only controller inventory probe to
`http://10.10.99.176:5088/api/lab/nodes` timed out after 20 seconds. A TCP
probe and ping both failed from source `10.10.100.130`; trace reached
`10.10.100.1`, which reported the destination unreachable. The current
workstation has no route for `10.10.99.0/24`. This is classified as a current
workstation routing diagnostic, not proof that the six- or seven-machine lab
is unavailable. The parity-eligible package remains ready for submission once
the controller registry is reachable from this host or an approved controller
path is used.

At this checkpoint no CI workflow was inspected or changed, no benchmark ran
in CI, and no push occurred. `application_send_turn_planning` remains applied
as `legacy_current`; every adjacent axis remains `legacy_current`. One
neutrality cell is retained negative, the broader neutrality matrix and
independent-host campaign remain open, and the next portfolio axis remains
unauthorized.

## Stage 2 Receive-Segment Terminal-Release Correlation

Local commit
`d964eab318dcac98e7002dd597d6cd998c29f84e` implements the
first `REQ-QUIC-CRT-0185` ownership slice:

- a compact immutable receive-buffer lifetime token containing only the
  connection-local operation sequence, closed path, construction tick,
  retained capacity, and token contract version;
- token preservation across partial reads and capacity reuse without a
  second token;
- one `Delivered` release after authoritative pool return or one `Reset`
  release after authoritative reset return;
- separate `quic-buffer-copy-raw-v2` construction and
  `quic-buffer-release-raw-v1` release records joined only by
  `connectionKey + operationSequence`;
- explicit `quic-buffer-evidence-export-failure-v1` fallback records for a
  bounded writer rejection;
- schema and semantic validation for sequence, duplicate, orphan, path,
  capacity, validity, and exact construction-to-release joins; and
- throwing or rejecting producer/sink neutrality without changing receive
  ownership, progress, reset, or delivery.

Local commit
`207cadad815c18745ffeabb477513a15efedb801` bounds future
construction export to lifetimes that promise terminal-release correlation.
Untracked operations remain in the fixed-field epoch summary with
`MissingTerminalReleaseCorrelation`; they are not duplicated into the
operation-level raw stream.

The retained diagnostic and verification sequence is:

| Invocation | Result | Classification and disposition |
| --- | --- | --- |
| First resumed test-project build | Failed because `QuicBufferCopyEpochAccumulator` did not implement the initially combined release-sink overload | `diagnostic_only`; the contract was corrected to independent copy and release sink interfaces so an epoch-only accumulator cannot silently discard release evidence. |
| Second test-project build | Failed one xUnit analyzer rule because `Assert.Single` followed a LINQ filter | `diagnostic_only`; the test now uses the predicate overload without changing coverage. |
| First `REQ-QUIC-CRT-0182` run | 14 passed and one failed because the new PowerShell validator had a missing line-continuation token | `diagnostic_only`; parser failure retained and corrected. |
| Second `REQ-QUIC-CRT-0182` run | 14 passed and one failed because PowerShell `Test-Json` could not resolve external local schema references | `diagnostic_only`; the immutable raw wrapper schemas now carry their bounded observation definitions and the companion observation schemas remain independently validated. |
| Final test-project Release build | Zero warnings and zero errors in 12.78 seconds | `accepted` focused build evidence. |
| Final receive ownership, requirement, post-service, and package band | 71 passed, zero failed, zero skipped in 16 seconds | `accepted`; includes delivery, reset, partial read, rejecting construction, throwing release observer, exact raw joins, shard receive ownership, and package contracts. |
| Final raw-host Release build before smoke | Zero warnings and zero errors in 1.64 seconds | `accepted`; proves the permanent construction, release, and failure streams compile. |
| Direct SpecTrace model validation | `SPEC-QUIC-CRT-STAGE2-ACTOR-MEMORY`, `ARC-QUIC-CRT-0067`, `WI-QUIC-CRT-0068`, and `VER-QUIC-CRT-0069` each returned `True` | `accepted` focused trace evidence for `REQ-QUIC-CRT-0185`. |
| Repository-wide core SpecTrace validation | 2,692 existing migration/schema/link errors | `diagnostic_only`; the broad baseline remains unhealthy and is not relabeled as a failure introduced by these four individually valid Stage 2 artifacts. |
| Post-smoke bounded-export raw-host build | Zero warnings and zero errors in 20.54 seconds | `accepted`; future raw construction output contains only terminal-release-tracked lifetimes. |
| Post-smoke raw package contract band | 27 passed, zero failed, zero skipped in 11 seconds | `accepted`; permanent raw-host contract strings and package surfaces remain present. |

The exact-source local correctness smoke used the clean committed source
`d964eab318dcac98e7002dd597d6cd998c29f84e`:

```powershell
pwsh -NoProfile -File .\eng\adaptive-runtime\Invoke-AdaptiveRuntimePolicyLocalCell.ps1 `
  -CampaignId adaptive-stage2-receive-release-smoke-local-20260724-r001 `
  -CellId duplex-64kb-x1-s16 `
  -PolicyAxis application_send_turn_planning `
  -SequenceProtocol ABBA `
  -PolicyA legacy_current `
  -PolicyB conservative `
  -WarmupSeconds 0 `
  -DurationSeconds 1 `
  -OutputRoot .\.artifacts\adaptive-runtime\adaptive-stage2-receive-release-smoke-local-20260724-r001 `
  -NoRestore
```

All four samples exited zero, validated the exact payload, and reported zero
failed operations, timeouts, protocol errors, cancellation failures, disposal
failures, or invariant violations. The result remains
`invalid_environment`: target and generator shared this workstation and the
protocol-lab-internal checkout was dirty. It is a correctness and evidence
contract smoke, not a performance or independent-host claim. Source and
binary identities are:

- quic-dotnet:
  `d964eab318dcac98e7002dd597d6cd998c29f84e`, clean;
- protocol-lab:
  `dd518aee19d73fb1477320644785fa070b1b62f1`, clean;
- protocol-lab-internal:
  `a61027b522a569a5e56bf07800fe4ca714e2b353`, dirty;
- raw-host binary SHA-256:
  `ed13c843345de7230f7b4e8d10d80632c9e89c1d6052a3e329d7c9a485c9906b`;
  and
- runtime binary SHA-256:
  `dc0027a026912be80e06a68a7d9bc4de0a743181e11ba0a776d8de952c38d34a`.

The runner retained 61 checksum-inventoried files under
`.artifacts/adaptive-runtime/adaptive-stage2-receive-release-smoke-local-20260724-r001`.
Its permanent records contain:

- 189 unified Stage 1 plus Stage 2 epochs and 756 Stage 1 axis records;
- zero rows with more than one non-legacy applied axis;
- `application_send_turn_planning` applied `legacy_current` in 96 epochs and
  `conservative` in 93 epochs;
- `application_send_batch_formation`, `queued_send_burst_budget`, and
  `oversized_write_admission_quantum` applied `legacy_current` in all 189
  epochs;
- 111,917 retained construction records in this pre-filter smoke, including
  15,243 terminal-release-tracked receive constructions;
- 15,243 terminal-release records and 15,243 exact joins;
- zero missing tracked releases, duplicate constructions, duplicate releases,
  orphan releases, path mismatches, capacity mismatches, or invalid release
  records; and
- 96,674 explicitly untracked construction records retained by this smoke.
  Commit `207cadad` prevents those untracked records from being repeated in
  future operation-level raw streams; the original smoke remains unchanged.

Per-sample tracked construction/release counts were 3,868, 3,592, 3,932, and
3,851. Construction raw files total 120,674,190 bytes and release raw files
total 8,181,450 bytes. The larger pre-filter construction output is retained
as `diagnostic_only`, not deleted or rewritten.

The local result, cell manifest, and checksum inventory SHA-256 values are:

- `b64918c56f0bfbf9da7f63f01316356fd8464cf12c7220d85d555f417d0a6e5d`;
- `eae8cefab0efcb0f7b3079006c1380fa92356e9d85b3f2995e2318469ce3bccd`;
  and
- `413ff19ad9449230c82ef8506e416fcba480abca0ca1f33c9eed9768e6fb1414`.

The cell contributes one retained `invalid_environment` classification, zero
policy-eligible rows, and 189 unified epochs that would remain excluded by
environment provenance. No normalized, curated, split, or analysis dataset
was created. No BenchmarkDotNet run, performance claim, large campaign,
independent-host ProtocolLab deployment, dataset transform, ML analysis, CI
run, or push occurred.

The remaining Stage 2 order is unchanged: extend exact terminal release to the
remaining observed owners; define reviewed actor work units and real
cross-stream/cross-connection fairness outcomes; prove cooperative
yield/repost safety; design `actor_work_quantum`; finish the
`buffer_copy_coalescing` conservative value and rollback contract; and review
conservative-only `adaptive_backpressure`. Only after those Stage 2 gates are
complete will another large dataset or ML-analysis pass begin. Active behavior
and production activation remain unauthorized.

### Evidence and trace synchronization verification

After synchronizing the observation, controller, seam, campaign, shadow,
acceptance/rollback, architecture, and verification summaries, the Release
test-project build completed in 64.08 seconds with zero warnings and zero
errors. The combined `REQ-QUIC-CRT-0175`, `REQ-QUIC-CRT-0176`, and
`ProtocolLabPackageTemplateTests` filter passed 61 of 61 tests in 43.4269
seconds.

The four current trace artifacts
`SPEC-QUIC-CRT-SEND-TURN-SHADOW`, `ARC-QUIC-CRT-0065`,
`WI-QUIC-CRT-0066`, and `VER-QUIC-CRT-0067` each validate independently
against `model/model.schema.json`. The repository-wide core validation remains
a retained diagnostic with 2,692 pre-existing migration errors. Its report is
`.artifacts/adaptive-runtime/spec-trace/core-after-send-turn-evidence.json`
with SHA-256
`83201597b1b498633a029612b929dfd086457a84df72e1e6e89f9c186144e2e8`.
Only one broad-validator error names the current four-artifact slice:
`SPEC-QUIC-CRT-SEND-TURN-SHADOW` cannot resolve its parent
`SPEC-QUIC-CRT` because that parent is among the legacy artifacts rejected by
the repository-wide model migration baseline. This checkpoint does not alter
or conceal that unrelated baseline.

## Permanent ProtocolLab Plans And ARM64 Package Cohort

Commit `37711c95` adds the versioned
`adaptive-runtime-protocol-lab-campaign-v1` manifest and permanent campaign
driver. Commit `fb0ccb92` fixes clean-worktree empty-array serialization found
by the first commit-pinned plan attempt. Commit `ee7cb9ef` extends the raw QUIC
implementation package to explicit Linux ARM64 and macOS ARM64 payloads while
leaving the default x64 package cohort unchanged.

The driver is plan-only unless `-Execute` is supplied. Execution requires a
clean worktree, creates distinct treatment package versions, requests
controller-owned `isolated-pair` placement, records no explicit worker ID,
retains every returned job and topology, and leaves completed cells
unclassified until ingestion. Shared physical hosts are
`environment_invalid`; repeated host pairs remain
`host_rotation_unverified`. The manifest always has
`activeInternalAuthorized = false`.

The Release test-project build passed with zero warnings and zero errors. The
focused package and campaign home passed 25 of 25 tests, including schema-valid
shadow ABBA and forced-counterfactual BAAB plans. The explicit dirty-source
execution guard also rejected execution before any controller access while
the implementation slice was uncommitted.

Two clean plans now target exact commit
`fb0ccb9257a754e382adfd1746758d855cf9b928`:

| Campaign | Sequence and treatments | Manifest SHA-256 | Inventory SHA-256 |
| --- | --- | --- | --- |
| `application-send-turn-shadow-20260724-r001` | ABBA; A `legacy_current`, B `shadow` | `d7aec0563519e0547abb83cef3f3d066604bcd1b1a5a407b92f91e46b0f7fe63` | `2611375a31161ca8cac802e52885064199836178fce3b595963ad9c5b1c1d5b0` |
| `application-send-turn-forced-20260724-r001` | BAAB; A `legacy_current`, B `conservative` | `9862fa144dadd99d9bc88962eae6318a52ff116b21d971109b899bcd558e364d` | `b8fe8c32302465ff7d3456d2e54a746e69439ed6a77ef0b3c7d30dffa0a21191` |

Both plans contain four ordered cells, apply `legacy_current`, freeze adjacent
axes at `legacy_current`, request the load-validated raw QUIC multiplex and
duplex scenarios, and remain `planned`. No package upload or controller job
occurred.

Three clean dual-ARM64 implementation packages were then materialized from
exact commit `ee7cb9efe4834bfa17ec3f574ff2660437e8fdaa`:

| Policy identity | Package SHA-256 | Attestation SHA-256 | Bytes |
| --- | --- | --- | ---: |
| `legacy_current` | `6c2dd7046a1e534ae6010131de889ae868fbd374b1b5e3571302d0b5b8d5814e` | `912b560a534225cdc615f0906b35997786e308002989e6c162a7d70e1f8bbc7d` | 2,465,323 |
| `conservative` | `48e794bcacce38996212c62ce6d803b32e7d9210d327f280299d9f7620ef7270` | `5af75b760f9040428448f2b48e10b9aa994a3c70967b99874c089922cf81dae5` | 2,465,317 |
| `shadow` | `76dc1a2393f211a9e6748179f1bd6d9ffe3b83db436024ef45e2c52770a99b76` | `0d39d55aa4b600f739aa791e48cb45026b4e6bf4298ab670ae45a551f5f91b43` | 2,465,307 |

Each package is parity-eligible, includes exactly `linux-arm64` and
`osx-arm64`, and carries `linux/arm64` and `macos/arm64` execution
environments. The policy stamp is distinct and no receive-credit override is
present. These artifacts prove cross-compilation and package materialization,
not worker readiness, platform correctness, performance, or host holdout
eligibility.

The first ARM64 command used `pwsh -File` with
`linux-arm64,osx-arm64`, which PowerShell bound as one literal runtime
identifier and rejected before any publish. The corrected direct invocation
passed a two-element array and produced the packages above. The rejected
command remains a diagnostic syntax failure; it is not measurement evidence.

The current workstation routing diagnostic remains unchanged, so neither the
new x64 plans nor ARM64 packages were uploaded. This is not a claim that the
multi-host lab is unavailable. `application_send_turn_planning` remains the
only active work axis and still applies `legacy_current`; the next portfolio
axis remains unauthorized.

## Complete Release Correctness Gate

The complete local correctness-only Release gate ran at exact commit
`1a67664753d38fa7c98b733deb10f23e9e2d519b` after a full solution Release
build:

```powershell
dotnet build Incursa.Quic.slnx -c Release --no-restore
dotnet test Incursa.Quic.slnx -c Release --no-build `
  --filter "Category!=Performance" `
  --results-directory .artifacts/adaptive-runtime/full-release/20260724-current-axis `
  --logger "trx;LogFileName=correctness.trx" `
  --logger "console;verbosity=minimal"
```

The solution build completed in 60.88 seconds with zero warnings and zero
errors. The test run completed in 7 minutes 17 seconds:

```text
total    9,840
passed   9,837
failed   0
skipped  3
```

The three skips are the existing ProtocolLab-sized live-loopback echo stress
tests whose own metadata directs default Release evidence to the package smoke
lane. They are not new failures or performance tests silently moved into CI.

The retained TRX is
`.artifacts/adaptive-runtime/full-release/20260724-current-axis/correctness.trx`,
14,166,449 bytes, with SHA-256
`c508b0c2637daa6d8008ed3993b0c2a162cdf53619e6b8690fe8e3e2da323b75`.
This closes the complete local Release correctness gate for the current
checkpoint. It does not close broader neutrality, independent-host execution,
host/workload holdouts, offline rule replay, fairness, or campaign rollback.

## Application Send Turn Counterfactual And Shadow Dataset Checkpoint

This checkpoint keeps `application_send_turn_planning` as the only active
measurement axis. The applied runtime policy remains `legacy_current`, every
adjacent axis remains frozen at `legacy_current`, and
`activeInternalAuthorized` remains false. No CI workflow or CI performance
lane was used, and no commit was pushed.

The implementation and evidence corrections are preserved in separate local
commits:

| Commit | Checkpoint |
| --- | --- |
| `2f9a1996` | Correct forced send-turn evidence materialization when PowerShell returns a scalar for a single artifact. |
| `ef5e632a` | Permit the documented send-turn `shadow` and observation-neutrality modes without validating the unused receive-axis policy value. |
| `1682a493` | Replay adjacent raw send-turn ticks so valid `instrumentation_mismatch` exclusions survive schema validation. |
| `3196a58b` | Add the permanent cell-median send-turn counterfactual analyzer and its versioned schema. |
| `ad865388` | Preserve `oldestApplicationSendAgeMicros` as the normalized `oldestQueuedSendAgeMicros` offline feature. |

The first forced c1 attempt completed its four samples and then failed during
evidence materialization because a single PowerShell result was treated as an
array. A post-fix attempt used a pre-commit frozen binary, so its first
materialized sample carried a different source revision and was classified
`invalid_contract`. Both attempts are retained as diagnostic evidence. The
first two counterfactual-analysis invocations also failed before producing an
output because `Measure-Object` was applied to ordered-dictionary keys; the
permanent analyzer uses an explicit fold instead. These failures were not
rerun away or relabeled as measurements.

An upload-direction shadow cell was also retained as `invalid_contract`:
payload correctness passed, but client-to-server traffic did not exercise the
server application-send seam. Consequently, the earlier upload forced curve
is retained for harness and environment diagnostics only and is not treated as
mechanism-sensitive evidence.

### Mechanism-sensitive forced download curve

Campaign `adaptive-send-turn-forced-download-local-20260724-r005` used exact
binary commit `1682a493`. All cells passed payload, protocol, schema, and join
validation. The permanent analyzer treats cell medians as repeated-cell
outcomes rather than independent epoch samples.

| Effective concurrency | Classification | Conservative throughput delta | Conservative p95 latency delta | Maximum within-treatment range | Construction rows |
| ---: | --- | ---: | ---: | ---: | ---: |
| 1 | `invalid_environment` | +1.801% | -3.444% | 0.0822 | 8 |
| 4 | `invalid_environment` | +5.066% | +1.464% | 0.0735 | 32 |
| 16 | `invalid_environment` | -6.081% | +1.611% | 0.0823 | 128 |
| 24 | `neutral_local` | +0.086% | -1.690% | 0.0489 | 192 |
| 32 | `neutral_local` | -1.882% | -0.177% | 0.0216 | 256 |

At c24, the legacy and conservative medians were respectively
18,807,928.64 and 18,824,126.69 bytes/second, with p95 latencies of
1,379.215 and 1,355.911 milliseconds. At c32 they were respectively
16,745,480.28 and 16,430,379.75 bytes/second, with p95 latencies of
1,842.211 and 1,838.948 milliseconds.

The final report is
`.artifacts/adaptive-runtime/analysis/application-send-turn-forced-download-20260724-r005-final/counterfactual-analysis.json`,
11,399 bytes, SHA-256
`aff5833d81312f978f96efbffb78d37d281bf913bb66a43b791a7d896b037dd9`.
It contains five cells, 616 construction rows, two analysis-eligible cells,
and three retained environment exclusions. Its recommendation is
`continue_evidence_generation`; it does not authorize active behavior.

### Shadow download observations and corrected offline dataset

Campaign `adaptive-send-turn-shadow-local-20260724-r003` used exact binary
commit `ef5e632a` and produced 19,267 connection-epoch rows:

| Effective concurrency | Classification | Epoch rows | Throughput (bytes/second) | p95 latency (milliseconds) |
| ---: | --- | ---: | ---: | ---: |
| 1 | `neutral_local` | 1,322 | 3,048,400.50 | 383.8588 |
| 4 | `neutral_local` | 3,394 | 10,695,478.96 | 459.5877 |
| 16 | `neutral_local` | 6,575 | 18,373,420.70 | 995.2280 |
| 24 | `neutral_local` | 7,976 | 17,529,303.36 | 1,372.58855 |

All rows applied `legacy_current` and recorded the `legacy_selector` reason.
No row reported missing, stale, contradictory, saturated, or out-of-domain
controller inputs. The c24 source contained two clean rows with adjacent
non-monotonic instrumentation ticks; after the replay-validation correction,
all 7,976 c24 rows validate while retaining their
`instrumentation_mismatch` exclusion. Across the cohort there are 20 such
flags, 90 `terminal_partial_epoch` flags, 9,327 `warmup` flags, and 9,863
rows with no exclusion flag. Flags can overlap.

The initial r003 normalized dataset is preserved as superseded diagnostic
evidence because its send-age feature mapping produced nulls. The corrected
append-only r004 dataset has 19,267 total rows, 9,863 included rows, 9,404
excluded rows, and zero retained-negative rows:

| Layer | Bytes | SHA-256 |
| --- | ---: | --- |
| Catalog | 11,673 | `e5798d52ab6c02542ee2c40f4bf0ecf4f5a846191d080a97b3b9f80da32943bc` |
| Normalized | 100,457,473 | `caea02f250be1b433208430810a78d7711b2de3595daf3fbf9721bb941345729` |
| Curated | 20,615,164 | `e451d1abd4509c5e208fa55df8ac0b6207fda82702bb3fcb2379ce1e39c0ef5f` |
| Split | 16,422,333 | `1d03d99bd2168249a55e6997d8e136ef2ae2af88ce5a48319b922ce78a2fc0ee` |

The r004 analysis report is
`.artifacts/adaptive-runtime/analysis/application-send-turn-shadow-download-20260724-r004/application-send-turn-analysis.json`,
6,240 bytes, SHA-256
`eb78cbf2955e9399da13c734128d76200b17bdca3061da1d9b45dfa0d9e1237d`.
All 9,863 curated rows now have a send-age feature: minimum 0, p50 3,788,
p95 33,142, and maximum 585,262 microseconds. The leakage audit passed and
found none of the forbidden scenario, payload, requested-concurrency, peer,
URL, or application-identity fields in production model features.

The split remains `insufficient_group_diversity`: it contains four workload
families but only one host fingerprint, so it creates no train, validation, or
test assignments. The deterministic rule proposal remains `holdout_blocked`,
has no candidate rule, and leaves active-internal behavior unauthorized.
Independent-host execution and honest host holdouts therefore remain required.
The current workstation still lacks a route to the controller subnet; this is
a workstation-routing diagnostic, not a claim that the multi-machine
ProtocolLab or its three physical hosts are unavailable.

## Stopped Single-Axis Neutrality Transform

At the user's direction, the long-running
`Invoke-AdaptiveRuntimeDatasetPipeline.ps1` process for
`application-send-turn-neutrality-download-20260724-r002` was stopped before
normalization completed. The transform is classified
`diagnostic_incomplete`; it must not be restarted, promoted, or used to derive
a rule.

The pre-stop process snapshot was:

```text
captured UTC       2026-07-24T13:50:03.6355993Z
PID                12824
parent PID         19228
started UTC        2026-07-24T11:23:12.5301936Z
elapsed            8,811.114 seconds
CPU                8,411.703 seconds
working set        4,293,812,224 bytes
private memory     4,220,809,216 bytes
responding         true
stop UTC           2026-07-24T13:50:18.2621649Z
stop disposition   scoped PowerShell Stop-Process; PID confirmed absent
```

The process backend could not deliver Ctrl+C to the non-interactive child.
The exact PID was therefore stopped with PowerShell `Stop-Process`; no file
was deleted or moved. The command was:

```powershell
$campaignRoot = '.artifacts\adaptive-runtime\adaptive-send-turn-neutrality-download-local-20260724-r002'
$results = @(Get-ChildItem -LiteralPath $campaignRoot -Recurse -Filter 'local-result.json' -File | Select-Object -ExpandProperty FullName)
$rows = @(Get-ChildItem -LiteralPath $campaignRoot -Recurse -Filter 'send-turn-row-*.json' -File | Select-Object -ExpandProperty FullName)
& '.\eng\adaptive-runtime\Invoke-AdaptiveRuntimeDatasetPipeline.ps1' `
  -LocalResultPath $results `
  -EpochDatasetPath $rows `
  -OutputRoot '.artifacts\adaptive-runtime\dataset\application-send-turn-neutrality-download-20260724-r002' `
  -DatasetId 'application-send-turn-neutrality-download-20260724-r002' `
  -DatasetVersion '2026-07-24-v1' `
  -SplitSeed 23
```

The five source cells remain complete and immutable: three
`invalid_environment`, one `negative_retained`, and one `neutral_local`. All
20 samples passed exact payload and protocol correctness. Their 55,658 raw
epochs, local results, cell manifests, checksum inventories, commands,
counters, and host output remain under
`.artifacts/adaptive-runtime/adaptive-send-turn-neutrality-download-local-20260724-r002`.

The partial dataset root remains at
`.artifacts/adaptive-runtime/dataset/application-send-turn-neutrality-download-20260724-r002`.
Its only completed layer is
`catalog/policy-catalog.json`, 11,673 bytes, SHA-256
`a26559bc196ad45b09176d1b966fb506c9b518998c7b01ae6b785d6325c3913c`.
No normalized, curated, or split file completed. The partial root and source
campaign were preserved in place and were not overwritten.

The corrected architecture direction is recorded in
`docs/design/adaptive-runtime-stage1-unified-execution-map.md`. No additional
single-axis transform, threshold analysis, CI work, push, or active behavior
followed this stop.

## Stage 1 Batch-Formation Runtime Checkpoint

Local commit `1713b6a8` implements the
`application_send_batch_formation` runtime seam. The closed policy set is
`legacy_current` and `single_eligible`; the default and force-legacy rollback
retain the existing scheduler. `single_eligible` can only shorten the
already-legal queued-write prefix to one. Payload, priority, same-stream
ordering, raw-write fragmentation, FIN, ownership, recovery, congestion,
pacing, anti-amplification, flow-control, packet, queue, buffer, cancellation,
disposal, and terminal guards remain runtime-authoritative.

The packet-plan record now includes versioned observation, rule, snapshot,
reason, and provenance identities; bounded missing, stale, saturated,
contradictory, and out-of-domain state; forced and shadow identities; selected
and applied values; bounded reasons and safety overrides; one-plan latch state;
legal payload and eligible-prefix observations; bounded queue, backlog,
stream-diversity, age, congestion, and retained-buffer observations; and
attributable plan outcomes. Receive-credit, send-turn, and batch observations
can run in the same connection while exactly one behavior-distinct treatment
is forced. The focused runtime test varied only batch formation and confirmed
that receive-credit and send-turn remained applied as `legacy_current`.

The verification commands were:

```powershell
dotnet build src/Incursa.Quic/Incursa.Quic.csproj -c Release --no-restore
dotnet build tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release --no-restore
dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release --no-build `
  --filter "FullyQualifiedName~REQ_QUIC_CRT_0175|FullyQualifiedName~REQ_QUIC_CRT_0176|FullyQualifiedName~REQ_QUIC_CRT_0177|FullyQualifiedName~REQ_QUIC_CRT_0178|FullyQualifiedName~QuicApplicationSendSchedulerTests|FullyQualifiedName~QuicApplicationSendQueueTests" `
  --logger "console;verbosity=minimal"
```

Both final Release builds completed with zero warnings and zero errors. The
final focused band passed 144 of 144 tests with zero skips and zero failures in
17 seconds. `VER-QUIC-CRT-0068` also validated against
`model/model.schema.json`.

Two pre-fix focused runs remain part of the diagnostic ledger:

| Run | Result | Classification | Disposition |
| --- | --- | --- | --- |
| First 30-test `REQ-QUIC-CRT-0178` run | 28 passed, 2 failed | One `failed_correctness`; one `diagnostic_only` | The real defect allowed an undefined batch enum to reach the empty-queue plan. Validation now occurs before the empty-queue return. The second failure assumed actor-service EWMA must be missing even though handshake work may already establish a valid zero-microsecond sample. |
| Second 30-test `REQ-QUIC-CRT-0178` run | 29 passed, 1 failed | `diagnostic_only` | The follow-up assertion incorrectly required a present actor-service EWMA to be positive; a valid sub-microsecond EWMA can round to zero. The test now accepts either explicit missing state or a present unsigned value. |

No failed run was relabeled as a passing measurement. No BenchmarkDotNet,
local campaign, ProtocolLab campaign, dataset transform, or unified epoch
materialization was run at this checkpoint. Unified-schema row counts,
classifications, and exclusions are therefore all zero for this slice. The
existing stopped 55,658-row single-axis source remains
`diagnostic_incomplete` and untouched.

The checkpoint was committed locally from a clean staged slice. Nothing was
pushed and no CI workflow or CI performance lane was used. The next
implementation axis is `queued_send_burst_budget`; receive-credit remains
`legacy_current`, send-turn remains `legacy_current`, batch formation returns
to `legacy_current` when another treatment is varied, and oversized-write
admission remains at its retained legacy selector. Unified raw export,
publisher-loss provenance, the batch BenchmarkDotNet cost slice, permanent
campaign inputs, the remaining two Stage 1 axes, full Release correctness, and
the small four-axis smoke remain open. `active_internal` and production
activation remain unauthorized.

## Stage 1 Queued-Send Burst Runtime Checkpoint

Local commit `fb520dd7` implements the `queued_send_burst_budget` runtime seam.
The closed policy set is `legacy_current` and `single_datagram`.
`legacy_current` retains the existing four-datagram pre-confirmation and
twelve-datagram post-confirmation cap. `single_datagram` lowers an
already-legal recovery-progress actor-turn budget to one datagram. The runtime
still recomputes congestion, pacing, anti-amplification, recovery,
retransmission, handshake, packet, endpoint, flow-control, queue, buffer, and
lifecycle authority before every datagram. A forced value cannot turn a
blocked budget into an allowed budget.

The actor-turn record contains versioned observation, rule, snapshot, reason,
and provenance identities; bounded missing, stale, saturated, contradictory,
out-of-domain, recovery, and resource state; forced and shadow identities;
selected and applied values; bounded reasons and safety overrides; a
one-actor-turn latch; legal and configured caps; queue count, logical backlog,
stream diversity, age, queue-delay and actor-service observations; congestion
and retained-send state; prior burst-limit hits; and legal, applied, emitted,
queue-before, queue-after, recovery-outcome, and blocked-reason outcomes. A
failing evidence sink is diagnostic-only and cannot escape the actor turn.

The runtime integration proof used a confirmed connection with one tracked
application packet and 48 delayed writes across four streams. In shadow
without forcing, the legacy cap drained the queue and the shadow
recommendation did not change applied behavior. With `single_datagram` forced,
the same recovery-progress boundary emitted exactly one datagram, retained
queued work, reported `burst_limit_reached`, and kept receive-credit,
application-send turn planning, and application-send batch formation applied
as `legacy_current`. The adjacent axes were observed concurrently but were not
forced.

The final verification commands were:

```powershell
dotnet build tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release `
  --no-restore --nologo -m:1 -nodeReuse:false `
  -p:UseSharedCompilation=false -v:minimal

dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release `
  --no-build --no-restore `
  --filter "FullyQualifiedName~REQ_QUIC_CRT_0175|FullyQualifiedName~REQ_QUIC_CRT_0176|FullyQualifiedName~REQ_QUIC_CRT_0177|FullyQualifiedName~REQ_QUIC_CRT_0178|FullyQualifiedName~REQ_QUIC_CRT_0179|FullyQualifiedName~QuicApplicationSendSchedulerTests|FullyQualifiedName~QuicApplicationSendQueueTests|FullyQualifiedName~QuicConnectionRuntimeWriteRequestCancellationTests|FullyQualifiedName~MetricsTests" `
  --logger "console;verbosity=minimal"

dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release `
  --no-build --no-restore `
  --filter "FullyQualifiedName~REQ_QUIC_CRT_0179" `
  --logger "console;verbosity=minimal"
```

The final Release build passed with zero warnings and zero errors in 47.92
seconds. The combined focused band passed 257 of 257 tests with zero failures
and zero skips in 20 seconds. The final `REQ-QUIC-CRT-0179` home passed 38 of
38 tests with zero failures and zero skips in 649 milliseconds. It includes a
256-turn deterministic bounded-sequence property test. The Stage 1
specification, architecture, work item, and verification JSON artifacts each
passed `model/model.schema.json`.

Five failed runtime-test iterations are retained as `diagnostic_only`; none
was relabeled as passing evidence:

| Run | Result | Classification | Disposition |
| --- | --- | --- | --- |
| Initial 36-test runtime run | 35 passed, 1 failed | `diagnostic_only` | The test used 1,000-byte writes, which correctly took the existing direct-send path and therefore did not arm the small-write timer. |
| Second 36-test runtime run | 35 passed, 1 failed | `diagnostic_only` | The test attempted 48 simultaneous bidirectional streams although the fixture's peer stream limit is four. |
| Third 36-test runtime run | 35 passed, 1 failed | `diagnostic_only` | Expiring the ordinary small-write timer exercised the single-packet flush boundary, not the multi-datagram recovery-progress burst boundary. |
| Fourth 36-test runtime run | 35 passed, 1 failed | `diagnostic_only` | A largest-only ACK over several tracked packets correctly created pending retransmission, so the recovery guard overrode the forced burst. |
| Fifth 36-test runtime run | 35 passed, 1 failed | `diagnostic_only` | Artificial congestion bytes were not associated with tracked packets and therefore remained authoritative after direct packet acknowledgement. |

A code-review correction made terminal and disposal safety overrides retain
their specific bounded reason codes instead of collapsing them into the
generic resource reason. The final requirement home covers both cases.

No BenchmarkDotNet run, permanent local campaign, ProtocolLab campaign,
dataset transform, or unified epoch materialization was performed for this
checkpoint. Unified-schema row counts, classifications, and exclusions are
zero for this slice. The stopped 55,658-row send-turn-only source remains
`diagnostic_incomplete`, append-only, and untouched.

Nothing was pushed, no CI workflow was used, and no performance work was added
to correctness CI. The next implementation axis is
`oversized_write_admission_quantum`. Receive-credit, send-turn planning, batch
formation, and burst budget return to `legacy_current` when that treatment is
varied. Unified raw export, bounded publisher-loss provenance, manual or
nightly BenchmarkDotNet cost evidence, permanent campaign inputs, full Release
correctness, and the small unified four-axis smoke remain open. After that
smoke, the roadmap proceeds to Stage 2 before any large transform or offline
ML analysis. `active_internal` and production activation remain unauthorized.

## Stage 1 Oversized-Write Admission Runtime Checkpoint

Local commit `7d41e382` implements
`oversized_write_admission_quantum` as the fourth Stage 1 force/observe/shadow
runtime seam. The closed values are `legacy_current`, `single_fragment`, and
`bounded_multi_fragment`. `legacy_current` preserves the exact retained
dispatcher-plus-16-through-24-observer selector. `single_fragment` uses the
existing conventional asynchronous fragment path. `bounded_multi_fragment`
uses the accepted two-fragment actor-turn path when the existing continuation
dispatcher is available. Explicit forcing does not use benchmark scenario,
payload label, requested concurrency, peer, URL, or application identity.

Selection occurs once at logical-write admission. The multiplexed completion
source or conventional logical-write loop retains the resolved quantum until
completion, cancellation, disposal, terminal state, or failure. Transport
ownership, FIN, retry, recovery, congestion, pacing, anti-amplification,
flow-control, packet, queue, buffer, lifecycle, and exactly-once completion
remain authoritative. A missing dispatcher overrides forced
`bounded_multi_fragment` to `single_fragment`. Missing or stale diagnostic
signals remain explicit but do not change an otherwise legal forced
mechanism, so enabling observation cannot change the counterfactual treatment.

The operation record contains versioned observation, rule, snapshot, reason,
and provenance identities; bounded missing, stale, saturated, contradictory,
out-of-domain, recovery, resource, and lifecycle state; forced and shadow
identities; selected and applied values; reason and safety override; logical
write and latch sequences; current payload and fragment limits; observed
stream and queued-write counts; queue-delay and actor-service EWMAs;
congestion and retained-send state; dispatcher and legacy-selector identity;
and terminal applied-quantum, committed-fragment, committed-byte,
continuation-post-attempt, completion-latency, and outcome fields. Evidence
sink failures are diagnostic-only and cannot affect transport completion.

The final verification commands were:

```powershell
dotnet build Incursa.Quic.slnx -c Release --no-restore

dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release `
  --no-build --no-restore `
  --filter "FullyQualifiedName~REQ_QUIC_CRT_0175|FullyQualifiedName~REQ_QUIC_CRT_0176|FullyQualifiedName~REQ_QUIC_CRT_0177|FullyQualifiedName~REQ_QUIC_CRT_0178|FullyQualifiedName~REQ_QUIC_CRT_0179|FullyQualifiedName~REQ_QUIC_CRT_0180|FullyQualifiedName~QuicApplicationSendSchedulerTests|FullyQualifiedName~QuicApplicationSendQueueTests|FullyQualifiedName~QuicConnectionRuntimeWriteRequestCancellationTests|FullyQualifiedName~MetricsTests" `
  --logger "console;verbosity=minimal"

dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release `
  --no-restore `
  --filter "FullyQualifiedName~REQ_QUIC_CRT_0180" `
  --logger "console;verbosity=minimal"
```

The exact committed source built in Release with zero warnings and zero errors
in 59.31 seconds. The final focused band passed 285 of 285 tests with zero
failures and zero skips in 19 seconds. The final `REQ-QUIC-CRT-0180` home
passed 28 of 28 tests with zero failures and zero skips in 662 milliseconds.
The retained oversized-write and write-request cancellation class passed 36
of 36 independently before the combined band. The Stage 1 specification,
architecture, work item, and verification JSON artifacts each passed the
canonical `model/model.schema.json`.

Three incomplete integration attempts remain classified and preserved:

| Run | Result | Classification | Disposition |
| --- | --- | --- | --- |
| Initial solution command | `dotnet build quic.slnx` failed because that filename does not exist | `diagnostic_only` | Corrected to the repository's `Incursa.Quic.slnx`; no source or evidence was changed by the failed command. |
| First correct solution build | Four compile/analyzer errors in the in-progress observation fast path | `diagnostic_only` | Removed impossible integer comparisons, materialized a decision before an `in` call, and removed the obsolete selector helper. The subsequent build was green. |
| First `REQ-QUIC-CRT-0180` invocation | Test project compile failed with one invalid `in` property expression | `diagnostic_only` | Materialized the latched decision in the test. No test case executed in the failed invocation; the final home is green. |

No BenchmarkDotNet run, permanent local campaign, ProtocolLab campaign,
dataset transform, or unified epoch materialization was performed for this
checkpoint. Unified-schema row counts, classifications, and exclusions are
zero for this slice. The stopped 55,658-row send-turn-only source remains
`diagnostic_incomplete`, append-only, and untouched.

Nothing was pushed, no CI workflow was used, and no performance work was added
to correctness CI. All four Stage 1 axes are now implemented, observable, and
forceable. A counterfactual still varies only one of them while receive credit
and all adjacent Stage 1 applied values remain `legacy_current`. The next
slice is unified runtime export plus the small correctness-only four-axis
smoke. After that smoke, the roadmap proceeds to Stage 2 before any large
transform or offline ML analysis. `active_internal` and production activation
remain unauthorized.

## Stage 1 Send-Turn Common-Decision Adaptation

The unified Stage 1 spine exposed an obsolete configuration restriction:
`application_send_turn_planning=conservative` could not retain observe-only or
shadow instrumentation. That restriction prevented a forced send-turn
counterfactual from reporting its actual applied value in the same common
decision contract used by the other three Stage 1 axes.

The runtime now adapts each send-turn observation into a versioned
`QuicAdaptiveRuntimeStage1AxisDecision`. Forced and applied identity are
reported independently from the shadow recommendation. A forced
`conservative` value may therefore compose with observe-only or shadow
evidence, while the shadow controller remains behavior-neutral and cannot
replace the forced planner. An independently injected planner is still
rejected because it has no closed policy identity or deterministic provenance.
Receive credit and every unforced Stage 1 axis remain `legacy_current`.

The first focused invocation compiled and ran 57 tests, of which 56 passed and
one failed. The failure was the old negative test that required forced
`conservative` plus shadow observation to throw. It is retained as
`diagnostic_only`; the approved unified contract makes that combination
necessary and legal. The test was replaced with coverage of all four
observe/shadow by forced-legacy/forced-conservative combinations.

The final command was:

```powershell
dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release `
  --no-restore `
  --filter "FullyQualifiedName~REQ_QUIC_CRT_0175|FullyQualifiedName~REQ_QUIC_CRT_0176|FullyQualifiedName~REQ_QUIC_CRT_0177"
```

The final focused band passed 58 of 58 tests with zero failures and zero
skips in 17 seconds. No BenchmarkDotNet, campaign, dataset transform,
ProtocolLab run, or unified-row export was performed in this slice. Nothing
was pushed, CI was not used, and active behavior remains unauthorized.

## Unified Stage 1 Raw-Epoch Runtime Checkpoint

Local commit `d076e807` adds the connection-local four-axis evidence
accumulator, configured-policy factory, permanent raw-host wiring, raw epoch
schema, raw semantic validator, and honest `epoch_summary` decision kind.
Whenever the permanent raw QUIC host selects any Stage 1 axis, it enables
bounded observation for all four axes on the same connection, permits at most
one forced axis, and holds receive-credit publication at `legacy_current`.
The four seam-specific sinks continue to publish their detailed evidence while
the accumulator closes one raw unified summary at the existing connection
epoch boundary.

An axis without a boundary event in an epoch remains present. Its validity is
`missing`, latch state is `unlatched`, event and completed-operation counts are
zero, and its configured forced and shadow identities remain attributable. No
prior event is carried forward as fresh and no operation or packet-plan key is
invented. The separate decision schema now accepts `epoch_summary` with null
operation and plan keys without relabeling the retained construction,
packet-plan, actor-turn, or logical-write record.

The exact verification commands were:

```powershell
dotnet build eng/protocol-lab/servers/IncursaRawQuicServer/IncursaRawQuicServer.csproj `
  -c Release --no-restore --nologo -m:1 -nodeReuse:false `
  -p:UseSharedCompilation=false -v:minimal

dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release `
  --no-restore `
  --filter "FullyQualifiedName~REQ_QUIC_CRT_0175|FullyQualifiedName~REQ_QUIC_CRT_0176|FullyQualifiedName~REQ_QUIC_CRT_0177|FullyQualifiedName~REQ_QUIC_CRT_0178|FullyQualifiedName~REQ_QUIC_CRT_0179|FullyQualifiedName~REQ_QUIC_CRT_0180" `
  --logger "console;verbosity=minimal"
```

The final raw-host Release build passed with zero warnings and zero errors in
7.03 seconds. The final focused six-requirement band passed 161 of 161 tests
with zero failures and zero skips in 19 seconds. The `REQ-QUIC-CRT-0177`
subset passed 25 of 25 during the slice, including one-connection
configuration, four-sink aggregation, empty-axis handling, epoch reset,
monotonic boundary, raw JSON serialization, schema validation, semantic
validation, and `epoch_summary` join coverage. The Stage 1 specification,
architecture, work item, and verification artifacts each passed the canonical
SpecTrace model.

The following incomplete iterations remain `diagnostic_only`:

| Invocation | Result | Preserved disposition |
| --- | --- | --- |
| First accumulator project build | Eleven compile/analyzer errors | Materialized record properties before `in` calls, removed nested ternaries, and named the missing-reason constant. |
| First accumulator-test build | Three targetless `default with` compile errors | Added explicit record-struct types; no test executed. |
| First `epoch_summary` validator test | One expected-key mismatch | The test initially changed the decision kind without also making the unified latch keys null; corrected to the honest no-operation projection. |
| First raw-host build | Nine top-level local-function overload errors | Top-level local functions cannot overload; each observation-mode helper received an axis-specific name. |
| First raw serialization test | Empty serialized policy snapshot | The internal snapshot's four properties were not serializer-visible; they are now public on an internal type and the strict raw schema passes. |
| First combined six-requirement band | 160 passed, 1 failed | A source-inspection test retained the obsolete one-observed-axis restriction; it now asserts one forced axis plus all-four observation. |

No permanent smoke campaign, canonical raw-to-curated materialization,
BenchmarkDotNet run, ProtocolLab deployment, dataset transform, or model
analysis was performed in this checkpoint. Unified runtime row count is zero;
classifications and exclusions are zero. The stopped 55,658-row send-turn-only
source remains `diagnostic_incomplete`, append-only, and untouched.

Nothing was pushed and CI was not used. The next slice is canonical
raw-to-unified materialization and permanent campaign extraction, followed by
the small four-axis correctness-only smoke. All adjacent axes remain applied
as `legacy_current`; active behavior and production activation remain
unauthorized. After the smoke, the roadmap proceeds to Stage 2 before any
large transform or offline ML analysis.

## Unified Stage 1 Smoke And Materialization Checkpoint

Local runtime commit `15191a0a` permits forced send-turn construction
provenance to remain separate from unified shadow evidence. Local
evidence-plane commit `e9d04f92` adds the permanent raw exporter, append-only
raw-export manifest, canonical unified materializer, materialization manifest,
schema validation, semantic validation, source-to-sample joins, and
deterministic tests. Nothing was pushed.

The first permanent smoke,
`adaptive-stage1-unified-smoke-local-20260724-r001`, is retained as
`invalid_contract`. All four ABBA samples reached the warmup timeout before an
accepted connection, and no unified rows were emitted. The failure exposed
the obsolete forced-construction-plus-shadow restriction fixed by
`15191a0a`. A separate one-sample diagnostic under the ProtocolLab internal
artifact root is retained as `diagnostic_only`; it reproduced the same
pre-fix warmup timeout. Neither artifact was deleted, overwritten, relabeled,
or used as passing evidence.

The post-fix correctness-only smoke used exact committed source `15191a0a`:

```powershell
pwsh -NoProfile -File .\eng\adaptive-runtime\Invoke-AdaptiveRuntimePolicyLocalCell.ps1 `
  -CampaignId adaptive-stage1-unified-smoke-local-20260724-r002 `
  -CellId duplex-64kb-x1-s16 `
  -PolicyAxis application_send_turn_planning `
  -SequenceProtocol ABBA `
  -PolicyA legacy_current `
  -PolicyB conservative `
  -WarmupSeconds 0 `
  -DurationSeconds 1 `
  -OutputRoot .\.artifacts\adaptive-runtime\adaptive-stage1-unified-smoke-local-20260724-r002 `
  -NoRestore
```

All four samples exited zero, validated the exact payload, reported zero
protocol errors, and matched requested to effective workload identity. The
campaign remains `invalid_environment`, because target and generator health
counters did not satisfy the environment gate. It is excluded from policy
acceptance and supports no performance claim. Host logs contain 189 unified
epochs, 26,011 send-turn records, 62,073 batch records, 25,168 burst records,
and zero oversized-write events.

Each unified epoch contains all four Stage 1 axes. The 189 send-turn axis
records include 185 event-bearing and four explicitly missing records, all
189 forced identities, 95 conservative applied values, 94 legacy applied
values, and 189 shadow recommendations. Batch and burst each include 185
event-bearing and four explicitly missing records, 189 shadow
recommendations, zero forced values, and zero non-legacy applied values.
Oversized-write includes 189 explicitly missing records, 189 shadow
recommendations, zero forced values, and zero non-legacy applied values.
Thus exactly one axis varied and all adjacent Stage 1 axes remained applied
as `legacy_current`. Receive-credit publication also remained
`legacy_current`.

The first export directory,
`unified-raw-export-v1`, is retained as `diagnostic_incomplete`. It contains
the partial JSONL produced before the validator recognized that
connection-local keys restart in separate sample processes. It was not
deleted or overwritten. The completed append-only export is
`unified-raw-export-v1-r002`:

- 189 raw epoch rows;
- 756 axis records;
- 201 explicitly missing-event axis records;
- six source-local connection-key resets;
- zero validation failures;
- raw JSONL SHA-256
  `eff62d0858d4271b13f669b71f55fe22139e77e1e9393e1b5e3de533d31b8780`;
- validation SHA-256
  `75343b95a0f56d6ba250ea0871ce49a91123f1ba4c7518c49d65c74454d7e87e`;
  and
- raw-export manifest SHA-256
  `7ad402a5d733aac6eb7e41fce16d0bfb23fe1e44efa77f20e239470712216e55`.

The four ordered host-log cohorts contain 47, 48, 47, and 47 rows. Their
respective source SHA-256 values are
`e55ca9c5409c96e6e0e3b94a61fcd3e0dd3aaad3fd0f7c7677ed29513973ce54`,
`4721a46afe4d7db58a1929c1673f1e79888c4f17c3b759a896920338ef6b4a05`,
`6cc9c847359796f9c1895a5feba0b56d37c2a38cfc49aa430b22611daaf10e6f`,
and
`a847c352896ff46c070673d8e7811a71ba9e91f66bbd4ca95478bdf46254cc53`.

Canonical materialization
`unified-materialized-v1-r001` produced 189 schema-valid unified epoch rows
and 756 separate `epoch_summary` decision rows. The validator reports 189
varied send-turn epochs and zero varied epochs for each adjacent axis, with
zero failures. The materialization preserves `invalid_environment` and
`excludedFromPolicyAcceptance=true`. Its hashes are:

- unified epochs:
  `ea2d5ca5c964f92e6bc1eee607d7f5139315e54b60d03256b131b14c86241017`;
- axis decisions:
  `8e839d8d4fd56a5942108b0f8e28e1473df74ee207f4c2f1dfd2d2333767604c`;
- validation:
  `5174bdb7e01d59130b89d5f276be212bcd1f66cc75f8b46138b65bc2aca90ffe`;
  and
- local-result input:
  `9f0be486a18f17fff224e19f88347de31a537c8767ecd82579d27498809b64fd`.

The final focused verification commands were:

```powershell
dotnet build tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj `
  -c Release --no-restore

dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj `
  -c Release --no-build --no-restore `
  --filter "FullyQualifiedName~REQ_QUIC_CRT_0177" `
  --logger "console;verbosity=minimal"
```

The Release build passed with zero warnings and zero errors in 46.72 seconds.
The final requirement-home run passed 29 of 29 tests with zero failures and
zero skips in 12 seconds. It covers raw schema and semantic validation,
permanent extraction, source checksums, source-to-sample joins, four-axis
canonical rows, separate axis decisions, analysis-only workload provenance,
classification preservation, and append-only rejection.

No BenchmarkDotNet run, ProtocolLab deployment, large campaign, large
normalization, split construction, or ML training was performed. The stopped
55,658-row send-turn-only transform remains `diagnostic_incomplete`,
append-only, and untouched. CI was not used and no performance work was added
to CI.

The four-axis unified instrumentation smoke gate is complete for architecture
progression. It is not policy-acceptance evidence. The next authorized work is
Stage 2 actor and memory foundations: bounded actor service, wake, follow-on,
and fairness observations first, followed by `actor_work_quantum`, buffer
ownership/copy inventory, `buffer_copy_coalescing`, and separately reviewed
conservative-only `adaptive_backpressure`. Large Stage 1 campaigns and offline
ML analysis remain deferred until that architecture work is complete.
`active_internal` and production activation remain unauthorized.

## Stage 2 Actor-Service Observation Foundation

Local commit `0d1fe4fa` adds the first behavior-neutral Stage 2 actor and
memory foundation. It does not add a forceable `actor_work_quantum` value,
change shard scheduling, or authorize active behavior.

The implemented slice contains:

- disabled and observe-only connection configuration with an exact sink pair;
- one immutable versioned record after an observed complete shard dispatch;
- connection-local monotonic service sequence, shard/wake identity, closed
  work kind, enqueue delay, complete transition-and-effect service duration,
  pending-work count, effect and existing follow-on counts, lifecycle
  disposition, and explicit validity flags;
- a fixed-field bounded epoch accumulator with saturating totals, maxima,
  integer EWMAs, closed-kind and disposition counts, wake changes, and reset;
- guarded evidence publication so a rejecting or throwing sink cannot affect
  progress or ownership;
- observation and epoch JSON schemas plus semantic validation; and
- `REQ-QUIC-CRT-0181`, `ARC-QUIC-CRT-0067`,
  `WI-QUIC-CRT-0068`, and `VER-QUIC-CRT-0069` trace homes.

The exact focused verification commands were:

```powershell
dotnet build tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj `
  -c Release --no-restore

dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj `
  -c Release --no-build `
  --filter "FullyQualifiedName~REQ_QUIC_CRT_0181|FullyQualifiedName~MetricsTests|FullyQualifiedName~QuicConnectionRuntimeShard|FullyQualifiedName~REQ_QUIC_CRT_0050|FullyQualifiedName~REQ_QUIC_CRT_0054|FullyQualifiedName~REQ_QUIC_CRT_0163"
```

The final Release build passed with zero warnings and zero errors. The focused
actor, shard, metrics, receive-credit, flow-control, ownership, and lifecycle
band passed 59 of 59 tests with zero failures and zero skips. Five of those
tests are the `REQ-QUIC-CRT-0181` requirement home and cover actual shard
emission, exact configuration, throwing-sink neutrality, fixed-field
aggregation/reset, and schema plus semantic validation.

The following incomplete or failing checks remain preserved:

| Invocation | Result | Classification and disposition |
| --- | --- | --- |
| First Stage 2 Release build | Two S109 analyzer errors for the EWMA shift literal | `diagnostic_only`; replaced by the named `EwmaShift` constant, then rebuilt cleanly. |
| `Validate-SpecTraceJson.ps1 -Profiles core` | 2,692 schema and unresolved-reference errors across the existing repository-wide QUIC corpus | `diagnostic_only`; this is an unrelated dirty-baseline gate rather than Stage 2 evidence. The four new trace artifacts passed focused model validation and the Stage 2 requirement home validates both new evidence schemas. No unrelated SpecTrace artifact was changed to hide the baseline. |

The actor record deliberately keeps
`MissingRunnableConnectionCount`,
`MissingOldestShardItemAge`,
`MissingDeadlineLateness`, and
`UsefulWorkUnitsUndefined`. Queue delay is not relabeled as oldest-item age,
pending inbox depth is not relabeled as runnable-connection count, and an
event is not relabeled as a reviewed scalar work unit. Complete fairness
outcomes, cooperative yield and exactly-once repost, a post-service permanent
epoch export boundary, `actor_work_quantum`, `buffer_copy_coalescing`, and
`adaptive_backpressure` remain open.

No campaign axis varied in this checkpoint. Receive-credit publication and
all four Stage 1 axes remain applied as `legacy_current`; actor work remains
the unchanged legacy drain. Stage 2 unified-schema row count is zero, with
zero new inclusions or exclusions. No BenchmarkDotNet run, local performance
campaign, ProtocolLab deployment, dataset transform, ML analysis, CI run, or
push occurred. The stopped 55,658-row send-turn-only transform remains
`diagnostic_incomplete`, append-only, and untouched.

The next authorized slice is the Stage 2 buffer ownership/copy inventory and
the exact post-service evidence boundary needed before designing a forceable
actor quantum. Active behavior and production activation remain unauthorized.

## Stage 2 Buffer Ownership And Copy Observation

Local inventory commit `4aa4367f` maps the current request, queue, formatting,
combination, packet-protection, sent-retention, retransmission, endpoint,
receive-pool, receive-segment, and protocol-critical ownership chains.
Follow-up commit `4bd4cd19` fixes server listener option propagation for the
actor-service mode and sink and adds its focused requirement-home proof.
Local implementation commit `086ab431` adds the first behavior-neutral
connection-local buffer-copy evidence contract. Nothing was pushed.

`REQ-QUIC-CRT-0182` covers five current send-side paths:

- flow-control retry request copies and capacity reuse;
- oversized raw queued data;
- formatted STREAM payloads;
- combined legal Stage 1 payload prefixes; and
- sent-packet plaintext retention.

Every record reports the stable `buffer_copy_coalescing` axis ID, five
contract/rule/snapshot/reason/provenance versions, a monotonic connection
operation sequence, closed path and operation values, decision boundary and
optional join sequence, logical and copied bytes, source/destination segments,
requested and retained capacity, lifecycle, validity, and a buffer-lifetime
latch. Force and shadow values are null. Selected and applied values are
`legacy_current`, selection source is `legacy_current`, safety override is
none, and fallback is false. There is no distinct conservative
implementation, selection, forcing, shadow recommendation, or active
behavior.

The fixed-field epoch accumulator retains closed path and operation counts,
logical/copied/capacity totals and maxima, monotonic first/last sequence, and
validity union. It uses no queue, dictionary, or stream scan. Disabled paths
return before record construction, and a rejecting or throwing evidence sink
cannot change copy, ownership, terminal release, or runtime progress.

The exact focused verification commands were:

```powershell
dotnet build tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj `
  -c Release --no-restore

dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj `
  -c Release --no-build `
  --filter "FullyQualifiedName~REQ_QUIC_CRT_0182|FullyQualifiedName~REQ_QUIC_CRT_0181|FullyQualifiedName~QuicApplicationSendQueue|FullyQualifiedName~QuicConnectionRuntimeShardReceiveBufferOwnership|FullyQualifiedName~QuicRetransmissionQueue|FullyQualifiedName~QuicConnectionSendRuntime"
```

The final Release build passed with zero warnings and zero errors in 60.31
seconds. The final actor, buffer-copy, application-send queue,
receive-ownership, retransmission, and send-runtime band passed 71 of 71 tests
with zero failures and zero skips in two seconds. `REQ-QUIC-CRT-0182`
contributes five tests for exact configuration, server option propagation,
legacy-only identity and aggregation, throwing-sink neutrality, and schema
plus semantic validation. The revised specification, architecture, work item,
and verification artifacts each pass direct validation against
`model/model.schema.json`. The repository-wide core profile retains its
previously recorded 2,692-error dirty baseline and was not used to hide or
weaken focused trace validation.

Terminal-release correlation, retained age, pool outstanding state,
retransmission-clone observation, receive-segment observation, platform
staging, permanent post-service export, and a distinct conservative value
remain open. Stage 2 unified row count is
zero, with zero new dataset inclusions or exclusions. No campaign axis varied;
receive credit and every Stage 1 axis remain applied as `legacy_current`, and
buffer-copy behavior remains the existing `legacy_current` implementation.

No BenchmarkDotNet run, local performance campaign, ProtocolLab deployment,
large dataset transform, split construction, ML analysis, CI run, or push
occurred. The stopped 55,658-row send-turn-only transform remains
`diagnostic_incomplete`, append-only, and untouched. The next safe slice is
bounded maintained retention and remaining ownership correlation before a
distinct `memory_conservative` value is designed. Active behavior and
production activation remain unauthorized.

## Stage 2 Maintained Send-Retention Follow-up

Local commit
`753cfb0688af16a1989762c79ec99df3ae9f8c4a` maintains total
application-send queue retained-owner count, retained capacity, and oldest
enqueue time across enqueue, replacement, removal with and without return,
ownership transfer, and clear. Its total snapshot is now O(1); the bounded
queue-cause diagnostic still scans only when explicitly requested.

Local commit
`4791605daf60173bf791e6d83006487d9f1579ce` maintains the same
total state for pending retransmissions across enqueue, packet-key removal,
packet-number-space discard, protection-level discard, 1-RTT key-phase
discard, age discard, all three stream suppression paths, and dequeue
ownership transfer. Recomputing the oldest time occurs only at a mutation
boundary when the removed plan held the current minimum. Total retention
snapshot reads no longer enumerate the retransmission queue. The same
checkpoint makes shared plaintext and packet-byte ownership return exactly
once.

Local commit
`6b60ea435a7823612181a38f179d082d26fcd59b` maintains total
sent-packet retained-owner count, retained capacity, and oldest sent time
across insert, packet-number replacement, protected-packet owner detachment,
acknowledgment, packet-space or protection discard, loss, and retransmission
ownership transfer. Its total snapshot is O(1). The combined storage-detail
snapshot still enumerates packet keys only to compute diagnostic per-space
occupancy and packet-number spans; it no longer recomputes owner totals or
oldest time.

The retained diagnostic and verification results are:

| Invocation | Result | Classification and disposition |
| --- | --- | --- |
| First application-send maintained-retention build | Two S1117 analyzer errors from local names shadowing fields | `diagnostic_only`; the obsolete scan totals were removed, bounded locals were renamed, and the next build passed. |
| `dotnet build quic-dotnet.sln -c Release --nologo` | MSB1009 because that solution filename does not exist | `diagnostic_only`; command-selection error only. No build or test evidence was produced by it. |
| `dotnet build Incursa.Quic.slnx -c Release --nologo` | Zero warnings and zero errors in 63.96 seconds | `accepted` correctness build evidence. |
| `dotnet build tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release --nologo --no-restore` | Zero warnings and zero errors in 12.91 seconds | `accepted` focused build evidence after the shared-owner release guard. |
| `REQ-QUIC-CRT-0182` plus retransmission-queue tests | 16 passed, zero failed, zero skipped in one second | `accepted` narrow mechanism and ownership evidence. |
| Stage 1 requirement homes, `REQ-QUIC-CRT-0182`, and both queue suites | 174 passed, zero failed, zero skipped in 14 seconds | `accepted` adjacent-axis and maintained-retention correctness evidence. |
| Send-runtime ownership, retransmission queue, and `REQ-QUIC-CRT-0182` | 31 passed, zero failed, zero skipped in one second | `accepted` release, discard, suppression, dequeue, and runtime ownership evidence. |
| Sent-packet focused test-project Release build | Zero warnings and zero errors in 56.67 seconds | `accepted` focused build evidence. |
| Send-runtime ownership, retransmission queue, and `REQ-QUIC-CRT-0182` after sent-packet accounting | 32 passed, zero failed, zero skipped in one second | `accepted` replacement, detachment, acknowledgment, loss-transfer, discard, and release evidence. |
| Stage 1 requirement homes, `REQ-QUIC-CRT-0182`, send runtime, and both queue suites | 190 passed, zero failed, zero skipped in 14 seconds | `accepted` adjacent-axis and complete maintained-retention correctness evidence. |
| `dotnet build Incursa.Quic.slnx -c Release --nologo --no-restore` | Zero warnings and zero errors in 57.63 seconds | `accepted` complete Release build evidence for the checkpoint. |

This follow-up adds no policy value, force seam, shadow recommendation,
selector, threshold, or active behavior. No campaign axis varied. Receive
credit, all four Stage 1 axes, and both Stage 2 candidates remain applied as
`legacy_current`. Stage 2 unified-schema row count remains zero, with zero new
dataset inclusions or exclusions. No BenchmarkDotNet run, local performance
campaign, ProtocolLab deployment, dataset transform, ML analysis, CI run, or
push occurred. The stopped 55,658-row send-turn-only transform remains
`diagnostic_incomplete`, append-only, and untouched.

The next bounded ownership slice is terminal-release correlation together
with retransmission-clone and receive-segment copy observation. The
post-service export boundary, a distinct `memory_conservative` value, forcing,
and shadow selection remain open. Active behavior and production activation
remain unauthorized.

## Stage 2 Buffer Observation V2 And Producer Coverage

Local contract commit
`a239a350009ddbe438d6085ec5becc460b604ab9` preserves the two v1
buffer schemas unchanged and adds:

- `quic-buffer-copy-observation-v2`;
- `quic-buffer-copy-epoch-v2`;
- closed `RetransmissionClone` and `ReceiveSegment` paths;
- closed `Clone` operation;
- exact `RetransmissionClone` and `ReceiveSegmentInsertion` boundaries; and
- fixed retransmission-clone, receive-segment, and clone epoch counts.

Local implementation commit
`66943c96bc1eba7de1397638380989e2ad47780c` installs one
configure-once connection-local operation observer behind the existing
observe-only sink. The path-migration retention clone reports only when it
actually creates a new owned plaintext buffer. Receive bookkeeping reports
both a new segment copy and a contiguous copy that reuses retained segment
capacity. Both producers guard the observer, and the runtime separately
guards the sink, so evidence failure cannot interrupt recovery, receive
progress, or ownership.

The retained diagnostic and verification sequence is:

| Invocation | Result | Classification and disposition |
| --- | --- | --- |
| v2 contract test-project Release build | Zero warnings and zero errors in 63.00 seconds | `accepted`; the v1 schemas had no diff and the three revised trace artifacts passed direct model validation. |
| v2 contract `REQ-QUIC-CRT-0182` | Eight passed, zero failed, zero skipped in one second | `accepted`; closed path, operation, fixed-count, schema, and semantic validation evidence. |
| First producer test-project Release build | CS1739 because the new test used `streamId` instead of the existing `streamIdValue` parameter | `diagnostic_only`; test call-site mismatch, corrected before any test evidence was accepted. |
| Producer test-project Release rebuild | Zero warnings and zero errors in 44.44 seconds | `accepted` build evidence after the call-site correction. |
| First producer ownership band | One failure and 53 passes because the receive fixture configured the local rather than peer bidirectional receive limit | `diagnostic_only`; fixture-domain error retained, with no runtime or policy failure inferred. |
| Second producer ownership band | One failure and 53 passes because the 1,000-byte first segment was below the existing 1,024-byte coalescing threshold and correctly allocated a second segment | `diagnostic_only`; the fixture was moved to the exact existing threshold. No threshold was tuned. |
| Third producer ownership band | One failure and 53 passes because the assertion still expected 1,000 copied bytes after the fixture moved to 1,024 | `diagnostic_only`; stale test expectation corrected without changing runtime behavior. |
| Final producer ownership band | 54 passed, zero failed, zero skipped in one second | `accepted`; covers v2 schema, receive allocation/reuse, receive release, path-migration clone identity, clone release, observer failure neutrality, send ownership, and retransmission behavior. |
| Final complete Release build | Zero warnings and zero errors in 59.37 seconds | `accepted` build evidence for the producer checkpoint. |
| Stage 1 requirement homes plus buffer, receive, send-runtime, retransmission, and application-send queue suites | 212 passed, zero failed, zero skipped in 14 seconds | `accepted` adjacent-axis and ownership correctness evidence. |

Terminal-release correlation, copy-scope retained age, pool-outstanding state,
and exact permanent post-service export remain explicit missing fields. This
checkpoint adds no policy value, force seam, shadow recommendation, selector,
threshold, or active behavior. No campaign axis varied. Receive credit, all
four Stage 1 axes, and both Stage 2 candidates remain applied as
`legacy_current`. Stage 2 unified-schema row count remains zero, with zero new
dataset inclusions or exclusions.

No BenchmarkDotNet run, local performance campaign, ProtocolLab deployment,
dataset transform, ML analysis, CI run, or push occurred. The stopped
55,658-row send-turn-only transform remains `diagnostic_incomplete`,
append-only, and untouched. The next bounded buffer slice is exact
terminal-release correlation; the post-service epoch export remains the next
shared evidence-boundary design. Active behavior and production activation
remain unauthorized.

## Stage 2 Post-Service Boundary And Internal Unified Join

Local commit
`357d1d3b3874813be26dcac30c0ccbfd7f044a1f` moves eligible
receive-credit epoch publication to an exact versioned post-service boundary
and adds the first internal Stage 1 plus Stage 2 joined record. Hosted-shard
publication occurs only after effect dispatch, follow-on measurement,
actor-observation publication, and work-item resource release.
Independent-consumer publication occurs only after connection-event resource
release and explicitly marks actor observation unavailable.

`adaptive-runtime-post-service-boundary-v1` repeats the connection epoch
sequence and exact end tick and records execution source, actor disposition,
actor-service sequence, actor publication, resource-release completion, and
explicit missing, incomplete-release, or fault validity.
`adaptive-runtime-unified-epoch-evidence-v1` seals receive-credit, all four
Stage 1 axes, actor-service, and buffer-copy summaries only after the
connection observation, receive-credit snapshot, and boundary share an exact,
positive, monotonic join key. Invalid joins are rejected before any
accumulator resets.

The raw QUIC host advances its receive-credit wrapper to
`adaptive-runtime-epoch-raw-v2`, adding the post-service boundary without
relabeling retained v1 evidence. The local runner accepts both retained v1 and
new v2 records. This checkpoint does not yet configure or export the complete
internal Stage 1 plus Stage 2 accumulator through the permanent raw-file
writer. Exact run, binary, host, workload, checksum, classification, and
raw-file provenance remain harness responsibilities.

Local commit
`aed0fcf5dc886d75a1ab1cb99724070c4a9c0bcb` updates the
completion-source pooling test reflection helper to supply
`Type.Missing` for optional method parameters. The production optional outcome
parameter predated this adaptive slice; this test-only compatibility fix
preserves the full-suite race coverage without changing runtime behavior.

The worktree was clean and `main` was 54 commits ahead of `origin/main` at
slice start. No relevant adaptive-runtime process was active. The stopped
single-axis transform remains preserved at:

- raw:
  `.artifacts/adaptive-runtime/adaptive-send-turn-neutrality-download-local-20260724-r002`;
- partial dataset:
  `.artifacts/adaptive-runtime/dataset/application-send-turn-neutrality-download-20260724-r002`;
- disposition: `diagnostic_incomplete`;
- preserved scope: 55,658 raw epochs and five cells, classified as three
  `invalid_environment`, one `negative_retained`, and one `neutral_local`.

The retained diagnostic and verification sequence is:

| Invocation | Result | Classification and disposition |
| --- | --- | --- |
| `dotnet build quic-dotnet.slnx -c Release` | MSB1009 because that solution filename does not exist | `diagnostic_only`; command-selection error. The correct repository solution is `Incursa.Quic.slnx`. |
| First boundary Release build | Two S1854 findings on disposition assignments consumed from `finally` during exception unwind | `diagnostic_only`; scoped suppressions and explanatory comments retain the fault disposition without weakening other analyzer coverage. |
| First schema validation with external local references | PowerShell `Test-Json` could not resolve the local schema references | `diagnostic_only`; the versioned schema now carries bounded local definitions and passed the same validation path. |
| `dotnet build Incursa.Quic.slnx -c Release --nologo --no-restore` | Zero warnings and zero errors in 46.59 seconds | `accepted` complete Release build evidence. |
| Adaptive requirement and mechanism band | 63 passed, zero failed, zero skipped | `accepted`; covers receive credit, Stage 1, actor, buffer, boundary, joining, fallback, and schema behavior. |
| Shard, ownership, queue, and metrics band | 108 passed, zero failed, zero skipped | `accepted`; covers post-service ordering, disposal, resource release, ownership, recovery, and adjacent correctness mechanisms. |
| Raw QUIC server Release build | Zero warnings and zero errors in 1.57 seconds | `accepted`; proves the raw-v2 boundary wrapper compiles against the committed runtime contract. |
| First complete Release test suite | 9,986 passed, three failed, four skipped in 7 minutes 34 seconds | `diagnostic_only` for three stale test contracts: the ProtocolLab template still expected the obsolete one-observed-axis wording; the send-turn scheduler still rejected forced identity plus same-axis shadow observation; and a reflection helper omitted a newly optional outcome argument. Each test was corrected to the already approved contracts. The four skips are explicit ProtocolLab or environment homes. |
| Exact three corrected tests plus `REQ-QUIC-CRT-0183` | Nine passed, zero failed, zero skipped | `accepted`; exact correction and boundary regression evidence. |
| Second complete Release test suite | 9,988 passed, one failed, four skipped in 7 minutes 38 seconds | `diagnostic_only` retained intermittent candidate: `Http3MinimalServerTests.PostDataRequest_WithIncompleteContentLength_ClosesConnectionWithMessageError` timed out after 10 seconds waiting for the peer H3 close. The same test passed in the first complete suite. Both outcomes are preserved; no isolated rerun is used to erase the timeout. |

The revised specification, architecture, work item, and verification artifact
each pass direct validation against `model/model.schema.json`. The
repository-wide core profile retains its previously recorded 2,692 unrelated
baseline errors and was not rerun or used to hide focused validation.

Stage 2 permanent unified-schema row count remains zero, with zero new dataset
inclusions or exclusions. No campaign axis varied. Receive credit, all four
Stage 1 axes, `actor_work_quantum`, and `buffer_copy_coalescing` remain applied
as `legacy_current`. No BenchmarkDotNet run, performance test, local campaign,
ProtocolLab deployment, large dataset transform, split construction, ML
analysis, CI run, or push occurred.

The next architecture slice is the permanent raw-file Stage 1 plus Stage 2
exporter using this exact boundary and accumulator, followed by terminal
release correlation, reviewed actor work units and fairness outcomes, and
force-readiness design. Active behavior and production activation remain
unauthorized.

## Stage 2 Permanent Unified Raw Export And Correctness Smoke

Local commit
`47d8e504f6dd509d75fc814843b065e59bc65737` configures one
connection-local unified accumulator as the receive-credit, all four Stage 1,
actor-service, and buffer-copy sink for every requested adaptive raw-host
execution. The host retains the earlier receive-credit and Stage 1
compatibility streams and adds:

- `adaptive-runtime-unified-epoch-raw-v1`;
- `QUIC_ADAPTIVE_RUNTIME_UNIFIED_EPOCH_JSON=`;
- bounded-channel export-failure records;
- an append-only raw exporter;
- raw and manifest schemas;
- semantic duplicate, ordering, join, four-axis, and one-varied-axis
  validation; and
- explicit `invalid_contract` classification when an export failure record is
  retained.

Local commit
`f399a5a67e9fa4e89f4c8947da086fb07fe0b494` scopes raw
connection identities to their hashed source-log cohort. Separate raw-host
processes restart their local `connection-0001` counters, so a multi-process
export must not silently claim that those keys are globally unique.

The retained diagnostic and verification sequence is:

| Invocation | Result | Classification and disposition |
| --- | --- | --- |
| First final raw-host Release build | Zero warnings and zero errors in 19.48 seconds | `accepted`; the permanent raw host compiled with the unified accumulator and joined writer. |
| First test-project Release build | Zero warnings and zero errors in 54.25 seconds | `accepted` build evidence. |
| First `REQ-QUIC-CRT-0183` exporter band | Seven passed, zero failed, zero skipped | `accepted` before explicit export-failure retention was added. |
| Raw package template check | One passed, zero failed, zero skipped | `accepted`; exact unified contract, actor, buffer, and boundary wiring are present. |
| Final raw-host Release build | Zero warnings and zero errors in 4.38 seconds | `accepted`; includes explicit bounded-channel failure reporting. |
| Final test-project Release build | Zero warnings and zero errors in 46.80 seconds | `accepted` focused build evidence. |
| First exporter failure-retention test | Eight passed and one failed because two native command-line values did not bind to the PowerShell array parameter as the fixture expected | `diagnostic_only`; the exporter was not reached for the second log. The fixture was corrected to one retained host log containing both the raw and failure prefixes. No runtime or schema claim was inferred from the failed invocation. |
| Final boundary, exporter, local-runner, and raw-package band | Nine passed, zero failed, zero skipped in three seconds | `accepted`; includes append-only rejection and retained failure artifact plus `invalid_contract` manifest behavior. |
| Direct SpecTrace model validation | `SPEC-QUIC-CRT-STAGE2-ACTOR-MEMORY`, `ARC-QUIC-CRT-0067`, `WI-QUIC-CRT-0068`, and `VER-QUIC-CRT-0069` each returned `True` | `accepted` focused trace evidence for `REQ-QUIC-CRT-0184`. |

The first exact-source smoke used commit
`f399a5a67e9fa4e89f4c8947da086fb07fe0b494`:

```powershell
pwsh -NoProfile -File .\eng\adaptive-runtime\Invoke-AdaptiveRuntimePolicyLocalCell.ps1 `
  -CampaignId adaptive-stage2-unified-smoke-local-20260724-r001 `
  -CellId duplex-64kb-x1-s16 `
  -PolicyAxis application_send_turn_planning `
  -SequenceProtocol ABBA `
  -PolicyA legacy_current `
  -PolicyB conservative `
  -WarmupSeconds 0 `
  -DurationSeconds 1 `
  -OutputRoot .\.artifacts\adaptive-runtime\adaptive-stage2-unified-smoke-local-20260724-r001 `
  -NoRestore
```

The smoke build passed with zero warnings and zero errors in 12.31 seconds.
All four samples exited zero, validated the exact payload, reported zero
failed operations, timeouts, protocol errors, cancellation failures,
disposal failures, or invariant violations, and matched requested to effective
workload shape. The local result is retained as `invalid_environment`, not as
policy evidence. The source identities are:

- quic-dotnet:
  `f399a5a67e9fa4e89f4c8947da086fb07fe0b494`, clean;
- protocol-lab:
  `dd518aee19d73fb1477320644785fa070b1b62f1`, clean; and
- protocol-lab-internal:
  `a61027b522a569a5e56bf07800fe4ca714e2b353`, dirty and
  therefore unsuitable for an independent-host policy claim.

The runner retained 53 checksum-inventoried files. Frozen binary SHA-256
values are:

- raw host:
  `83c801d006f17b85177c59d56bb3e5ee8b06d1f83914e8ba26e1ccff65052c5e`;
  and
- runtime:
  `dd852dc046f6cb50fce2ac2bc98edee4b43bccce0d9cd4c0bf9e113412f7b126`.

The append-only unified export
`.artifacts/adaptive-runtime/adaptive-stage2-unified-smoke-local-20260724-r001/unified-raw-export-v1`
is schema-valid and semantically valid:

- 187 raw joined epochs;
- 748 Stage 1 axis records;
- eight source-scoped connections;
- zero duplicate keys;
- zero out-of-order keys;
- zero join failures;
- zero multi-axis variation rows;
- zero export failures;
- 187 actor-observed rows;
- 183 buffer-observed rows and four explicitly empty buffer summaries;
- 187 completed resource-release boundaries; and
- 187 published actor-observation boundaries.

All 187 receive-credit snapshots applied `legacy_current`.
`application_send_turn_planning` was the only varied axis: 94 epochs applied
`conservative`, 93 applied `legacy_current`, every epoch retained forced
identity and a shadow recommendation, and 183 epochs contained send-turn
events while four were explicitly missing. Both
`application_send_batch_formation` and `queued_send_burst_budget` applied
`legacy_current` in all 187 epochs, retained 183 event-bearing plus four
missing records, and retained 187 shadow recommendations.
`oversized_write_admission_quantum` applied `legacy_current` in all 187
epochs, retained 187 shadow recommendations, and remained explicitly
event-missing in this workload. `actor_work_quantum` and
`buffer_copy_coalescing` remain observation-only candidates with applied
legacy behavior; neither is forceable.

The raw JSONL SHA-256 is
`f1cf8c3348b9ba58950b1c0c9de43244d20534302ef38ee592e5f00b49c3990e`;
the validation SHA-256 is
`a05376f27d9cf5d5b7130b4ae02644ece1d4953e9e86fe43dff1c1e68dfd97a6`;
and the raw-export manifest SHA-256 is
`9a17cdae376a27ca137f8750ac3477e23fc16612be6450b7eab4646218b3fe80`.
The local result, cell manifest, and checksum inventory SHA-256 values are
`15ba72105a57005c9dbe30f9af330a54238fe497a386b465f46d224d749af3e3`,
`f0b4870e99e682fbe71810bc605bfd55e927eaeaf59c1fa08c608b6ce15281a1`,
and
`55a271610ba44034f3429c20876052b14c3582d4f24989c231704f16ded63272`.

The raw exporter classification is `accepted` for structural completeness;
the enclosing campaign remains `invalid_environment`. Therefore 187 raw rows
are retained, zero rows are eligible for policy acceptance, and all 187 would
carry the environment exclusion into any later normalized or curated layer.
No normalized, curated, split, or analysis dataset was created.

No BenchmarkDotNet run, performance claim, large campaign, ProtocolLab
deployment, dataset transform, ML analysis, CI run, or push occurred. The
stopped 55,658-row single-axis transform remains `diagnostic_incomplete`,
append-only, and untouched. The next Stage 2 architecture slice is exact
terminal-release correlation for the remaining owner paths, followed by
reviewed useful actor work units, runnable/fairness observations, exactly-once
repost design, and only then force-readiness for `actor_work_quantum` and
`buffer_copy_coalescing`. Active behavior and production activation remain
unauthorized.

## Stage 2 Flow-Control Retry Buffer Release

Local commit
`19be4042` extends `REQ-QUIC-CRT-0185` to the
`application_write_request` owner without changing write, flow-control,
completion, cancellation, or pool behavior.

The compact token is installed only for a newly rented retry owner after its
construction record is accepted. Capacity reuse keeps the original token and
continues to mark the reuse operation as lacking its own terminal lifetime.
Replacement returns and releases the old owner before installing a new token.
Downstream copy, success, failure, cancellation, terminal completion,
disposal, and defensive completion-source recycle use a closed release reason,
clear the token exactly once, and publish only after authoritative pool
return. Release observation and raw wrapper v2 add this path and reason set;
the receive-only v1 schemas remain immutable.

The focused verification sequence is:

| Invocation | Result | Classification and disposition |
| --- | --- | --- |
| `dotnet build .\tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release --no-restore` | Zero warnings and zero errors in 46.21 seconds | `accepted` focused Release build. |
| `REQ-QUIC-CRT-0182` requirement home | 19 passed, zero failed, zero skipped | `accepted`; includes replacement/completion, cancellation, capacity reuse, downstream-copy reason, contradictory capacity/reason, out-of-domain validity, schema v2, and exact joins. |
| Completion-pool, write-cancellation, receive-buffer, and raw-package band | 85 passed, zero failed, zero skipped in 13 seconds | `accepted`; existing completion reuse, delayed task consumption, cancellation, receive ownership, and package contracts remain correct. |
| Raw-host Release build | Zero warnings and zero errors in 3.91 seconds | `accepted`; v2 release records compile in the permanent host. |
| Direct SpecTrace model validation | The Stage 2 specification, architecture, work item, and verification artifact each returned `True` | `accepted` focused trace evidence. |

No campaign axis varied and no new unified rows were generated. Receive credit,
all four Stage 1 adjacent axes, `actor_work_quantum`, and
`buffer_copy_coalescing` remain applied as `legacy_current` outside explicit
earlier Stage 1 smoke treatments. Dataset inclusion/exclusion counts are
unchanged. No BenchmarkDotNet run, performance claim, large campaign,
ProtocolLab deployment, dataset transform, ML analysis, CI run, push, or
active behavior occurred.

The next buffer-owner slice is `oversized_raw_queue`; original retry-owner
release and queued-owner construction must remain distinct records and must
not be relabeled as one lifetime. The remaining Stage 2 actor work-unit,
fairness, force-readiness, and rollback gates remain ahead of any large
dataset or ML analysis. Production activation remains unauthorized.

## Stage 2 Oversized Raw Queue Buffer Release

Local commit
`63e457855410f3c4d3fa0f76283da1cfe918ba25` extends
`REQ-QUIC-CRT-0185` to the `oversized_raw_queue` owner without changing
application-send selection, queue order, partial advancement, packet
construction, congestion, pacing, recovery, flow-control, or buffer limits.

The oversized-write construction record now requests terminal correlation and
stores the compact lifetime token beside the existing
`QueuedRawStreamData` owner in `PendingApplicationSendRequest`. Partial
advancement retains the original token and owner capacity. Successful
formatting or combination releases with `CopiedToNextOwner`; stream removal
uses `Canceled`; replacement uses `Replaced`; and connection terminal or
disposal clear uses the exact lifecycle reason. Every observation follows the
authoritative pool return, and a rejecting or throwing sink cannot block queue
mutation or send progress. Release observation and raw wrapper v3 add this
closed path while retaining v1 and v2 schemas and validator routing unchanged
for prior evidence.

The focused verification sequence is:

| Invocation | Result | Classification and disposition |
| --- | --- | --- |
| Initial `REQ-QUIC-CRT-0182` plus application-send queue band | 58 passed, zero failed, zero skipped in two seconds | `accepted`; established successful handoff after partial advancement, replacement, cancellation, terminal, disposal, and throwing-sink behavior. |
| First rebuild after adding the parameterized non-success test | Compile failed because a public xUnit theory exposed the internal `QuicBufferReleaseReason` parameter type | `diagnostic_only`; the test boundary was corrected to accept a byte and cast internally. No runtime or evidence record was produced by the failed build. |
| Final Stage 2 requirement, queue, and raw-package band | 85 passed, zero failed, zero skipped in 13 seconds | `accepted`; includes v3 schema and exact-join validation plus contradictory oversized-path reason handling. |
| Write-cancellation and CRT 0176, 0177, and 0180 band | 121 passed, zero failed, zero skipped in 25 seconds | `accepted`; cancellation, oversized-write continuation, rollback, and terminal behavior remain correct. |
| Raw-host Release build | Zero warnings and zero errors in 3.97 seconds | `accepted`; v3 release records compile in the permanent host. |
| PowerShell and JSON parse validation | Both edited scripts, both v3 schemas, and all four edited SpecTrace JSON artifacts parsed successfully | `accepted` contract syntax evidence. |
| First direct SpecTrace one-liner | PowerShell parser rejected an empty pipe element after the `foreach` statement | `diagnostic_only`; command construction only. The corrected invocation wrapped the loop result before piping. |
| Corrected direct SpecTrace model validation | The Stage 2 specification, architecture, work item, and verification artifact each returned `True` | `accepted` focused trace evidence. |

No campaign axis varied and no new raw, unified, normalized, curated, split,
or analysis rows were generated. Receive credit, all four Stage 1 axes,
`actor_work_quantum`, and `buffer_copy_coalescing` remain applied as
`legacy_current` outside earlier explicitly retained Stage 1 smoke treatments.
Dataset inclusion and exclusion counts are unchanged. No BenchmarkDotNet run,
performance claim, large campaign, ProtocolLab deployment, dataset transform,
ML analysis, CI run, push, or active behavior occurred.

Three owner paths are now correlated: `receive_segment`,
`application_write_request`, and `oversized_raw_queue`. The next owner slice
is formatted and combined application-send payload transfer, followed by
sent-plaintext retention, retransmission, and endpoint ownership. Stage 2
useful actor work units, ready-stream fairness observations, exactly-once
repost design, force-readiness, and rollback remain ahead of any large dataset
or ML analysis. Production activation remains unauthorized.

## Stage 2 Formatted Send And Retransmission Buffer Release

Local commit
`9dcb2d7f220984bfd75ce1bc5440daa16e34a140` extends
`REQ-QUIC-CRT-0185` to `formatted_stream_payload` and
`retransmission_clone` owners without changing application-send selection,
queue ordering, protection, congestion, pacing, recovery, flow-control, or
buffer limits.

Every successfully formatted STREAM payload now receives a compact lifetime
token. The token follows the same array through the application-send queue,
sent-packet retention, loss, direct retransmission, acknowledgment, reset
suppression, replacement, terminal discard, and final runtime disposal.
Rebuilds that copy into a distinct sent-retention owner close the original
token with `CopiedToNextOwner`; terminal correlation for that new owner remains
a later slice. Path migration gives each distinct retransmission clone its own
token. Release publication follows authoritative pool return, and an observer
exception cannot change recovery, acknowledgment, disposal, or queue progress.
Release observation and raw wrapper v4 add these two closed paths while
retaining v1 through v3 as immutable compatibility contracts.

The focused verification sequence is:

| Invocation | Result | Classification and disposition |
| --- | --- | --- |
| Interrupted recovery-focused band from the prior execution window | No final output was recoverable after application compaction, and no `dotnet` process remained | `diagnostic_only`; the identical command was rerun rather than inferring a result. |
| Identical retransmission-queue, outstanding-stream-index, RFC 9001 4.0.7, and CRT 0156 rerun | 28 passed, zero failed, zero skipped in 138 milliseconds | `accepted` recovery and loss-bookkeeping evidence. |
| First runtime Release build after the final-owner drain | Zero warnings and zero errors in 10.01 seconds | `accepted` focused runtime build. |
| First test-project rebuild after adding disposal and observer-failure tests | Compile failed because the fixture supplied a nonexistent `AckEliciting` retransmission-plan parameter and a nonexistent decision-boundary enum value | `diagnostic_only`; test construction only. The fixture was corrected to the existing plan contract and `PacketPlan` boundary. No runtime or evidence record was produced. |
| Final test-project Release build | Zero warnings and zero errors in 13.95 seconds | `accepted` focused build evidence. |
| Final Stage 2 requirement, sent-packet ownership, application-send queue, and raw-package band | 105 passed, zero failed, zero skipped in 13 seconds | `accepted`; includes ACK, loss/retransmission transfer, terminal discard, disposal drain, replacement, contradictory reasons, schema v4, exact joins, and throwing-observer neutrality. |
| Final retransmission-queue, outstanding-stream-index, RFC 9001 4.0.7, and CRT 0156 band | 28 passed, zero failed, zero skipped in 173 milliseconds | `accepted`; queue order, loss, retransmission, and recovery behavior remain correct after final integration. |
| Raw-host Release build | Zero warnings and zero errors in 3.88 seconds | `accepted`; v4 release records compile in the permanent host. |
| PowerShell, JSON, and focused trace-home parse validation | Both edited scripts, both v4 schemas, and the Stage 2 specification, architecture, work item, and verification JSON parsed successfully; all four trace homes exist | `accepted` focused contract syntax and trace-location evidence. |
| Repository-wide `core` SpecTrace validator | Reported the existing migration baseline of 2,692 schema and unresolved-reference errors across the repository | `diagnostic_only`; the global validator is not a clean gate for this slice. No error was deleted, relabeled, or treated as evidence that the focused artifacts passed the global profile. |

No campaign axis varied and no new raw, unified, normalized, curated, split,
or analysis rows were generated. Receive credit, all four Stage 1 axes,
`actor_work_quantum`, and `buffer_copy_coalescing` remain applied as
`legacy_current` outside earlier explicitly retained Stage 1 smoke treatments.
Dataset inclusion and exclusion counts are unchanged. No BenchmarkDotNet run,
performance claim, large campaign, ProtocolLab deployment, dataset transform,
ML analysis, CI run, push, or active behavior occurred.

Five owner paths are now terminally correlated: `receive_segment`,
`application_write_request`, `oversized_raw_queue`,
`formatted_stream_payload`, and `retransmission_clone`. Combined application
payloads, sent-plaintext retention copies, protected packet owners, and
endpoint handoff remain explicitly uncorrelated and non-forceable. Those owner
paths precede Stage 2 useful actor work units, ready-stream fairness
observations, exactly-once repost design, force-readiness, and rollback. No
large dataset or ML analysis is authorized before those architecture gates.
Production activation remains unauthorized.

## Stage 2 Sent-Plaintext Retention Buffer Release

Local commit
`d1931d02d2e29cff32ae8c1fb7783568c01fe206` extends
`REQ-QUIC-CRT-0185` to `sent_packet_plaintext_retention` without changing
retransmission selection, packet construction, congestion, pacing, recovery,
flow-control, or buffer limits.

An application retransmission rebuild rents a distinct
`SentPacketRetention` owner and now requests terminal correlation after the
copy. The new token moves into sent-packet state, survives loss and direct
retransmission with that array, and closes exactly once on acknowledgment,
reset suppression, replacement, terminal discard, final disposal, or a
construction failure. The source formatted or retransmission-clone owner
closes separately with `CopiedToNextOwner`; the two owners are never relabeled
as one lifetime. Release observation and raw wrapper v5 add only this closed
path while retaining v1 through v4 as immutable compatibility contracts.

The focused verification sequence is:

| Invocation | Result | Classification and disposition |
| --- | --- | --- |
| Initial v5 raw-schema parse checks | Three parse attempts exposed a misplaced `then` block, a missing object close, and one extra closing brace while the new file was still unstaged | `diagnostic_only`; schema-authoring diagnostics only. The invalid drafts were never committed, exported, or used to classify data. |
| Test-project Release build | Zero warnings and zero errors in 60.90 seconds | `accepted` focused build evidence. |
| Stage 2 requirement, sent-packet ownership, and raw-package band | 73 passed, zero failed, zero skipped in 13 seconds | `accepted`; includes sent-retention loss/retransmission/ACK, contradictory reason handling, v5 schema validation, exact joins, and permanent package identity. |
| First retransmission and recovery-probe filter | Nine passed, zero failed, zero skipped, but only the retransmission-queue class matched because the two requested RFC class names were incorrect | `diagnostic_only`; the invocation was green but did not establish the intended recovery-probe coverage. |
| Corrected RFC 9002 recovery-probe and RFC 9000 coalesced recovery-probe band | 23 passed, zero failed, zero skipped in one second | `accepted`; application rebuild, recovery probe, and coalescing behavior remain correct. |
| Raw-host Release build | Zero warnings and zero errors in 3.72 seconds | `accepted`; v5 release records compile in the permanent host. |
| Final PowerShell, JSON, and focused trace-home parse validation | Both edited scripts, both v5 schemas, and the Stage 2 specification, architecture, work item, and verification JSON parsed successfully | `accepted` focused contract syntax and trace-location evidence. |

No campaign axis varied and no new raw, unified, normalized, curated, split,
or analysis rows were generated. Receive credit, all four Stage 1 axes,
`actor_work_quantum`, and `buffer_copy_coalescing` remain applied as
`legacy_current` outside earlier explicitly retained Stage 1 smoke treatments.
Dataset inclusion and exclusion counts are unchanged. No BenchmarkDotNet run,
performance claim, large campaign, ProtocolLab deployment, dataset transform,
ML analysis, CI run, push, or active behavior occurred.

Six owner paths are now terminally correlated: `receive_segment`,
`application_write_request`, `oversized_raw_queue`,
`formatted_stream_payload`, `retransmission_clone`, and
`sent_packet_plaintext_retention`. Combined application payloads, protected
packet owners, and endpoint handoff remain explicitly uncorrelated and
non-forceable. Those paths remain ahead of Stage 2 actor work-unit, fairness,
exactly-once repost, force-readiness, and rollback gates. Production activation
remains unauthorized.

## Stage 2 Combined Application-Send Buffer Release

Local commit
`1747b67e3808b8fb0415f3b85294ecfd636749c0` extends
`REQ-QUIC-CRT-0185` to `combined_application_send` without changing batch
selection, queue ordering, protection, congestion, pacing, recovery,
flow-control, or buffer limits.

After the already-legal selected queue entries are copied into a distinct
`CombinedApplicationSend` owner, that owner now requests terminal correlation.
Its token moves into sent-packet state, survives loss and direct
retransmission with the same array, and closes exactly once on acknowledgment,
reset suppression, replacement, terminal discard, final disposal, or failed
protection/accounting. Each selected source queue owner closes separately with
`CopiedToNextOwner`; source and combined lifetimes are never silently merged.
Release observation and raw wrapper v6 add only this closed path while
retaining v1 through v5 as immutable compatibility contracts.

The focused verification sequence is:

| Invocation | Result | Classification and disposition |
| --- | --- | --- |
| Test-project Release build | Zero warnings and zero errors in 63.98 seconds | `accepted` focused build evidence. |
| Stage 2 requirement, sent-packet ownership, and raw-package band | 74 passed, zero failed, zero skipped in 13 seconds | `accepted`; includes combined-owner loss/retransmission/ACK, contradictory reason handling, v6 schema validation, exact joins, and permanent package identity. |
| Application-send queue, repeated queued-final-write, batch-policy mechanism, and batch-runtime band | 103 passed, zero failed, zero skipped in three seconds | `accepted`; batching, queue ownership, final-write delivery, and adjacent Stage 1 policy behavior remain correct. |
| Raw-host Release build | Zero warnings and zero errors in 4.03 seconds | `accepted`; v6 release records compile in the permanent host. |
| PowerShell, JSON, and focused trace-home parse validation | Both edited scripts, both v6 schemas, and the Stage 2 specification, architecture, work item, and verification JSON parsed successfully | `accepted` focused contract syntax and trace-location evidence. |

No campaign axis varied and no new raw, unified, normalized, curated, split,
or analysis rows were generated. Receive credit, all four Stage 1 axes,
`actor_work_quantum`, and `buffer_copy_coalescing` remain applied as
`legacy_current` outside earlier explicitly retained Stage 1 smoke treatments.
Dataset inclusion and exclusion counts are unchanged. No BenchmarkDotNet run,
performance claim, large campaign, ProtocolLab deployment, dataset transform,
ML analysis, CI run, push, or active behavior occurred.

Seven owner paths are now terminally correlated: `receive_segment`,
`application_write_request`, `oversized_raw_queue`,
`formatted_stream_payload`, `combined_application_send`,
`retransmission_clone`, and `sent_packet_plaintext_retention`. Protected packet
owners and endpoint handoff remain explicitly uncorrelated and non-forceable.
Those paths remain ahead of Stage 2 actor work-unit, fairness, exactly-once
repost, force-readiness, and rollback gates. Production activation remains
unauthorized.

## Stage 2 Protected-Packet And Hosted-Endpoint Buffer Release

Local commit
`7b2b21cf939f9e39c353a27209548f6e8b9e6a41` completes the reviewed managed
owner chain for `outbound_packet_protection` and hosted
`endpoint_datagram_handoff` without changing packet selection, packet-number
authority, protection, congestion, pacing, amplification, recovery,
flow-control, socket batching, or buffer limits.

Each non-batched pooled protection output now receives a compact lifetime
token after successful construction. Admission failure releases it as
`Failed`; an ACK-only copy releases it as `CopiedToNextOwner`; sent-packet and
retransmission state move the same token through loss, replacement, ACK,
terminal cleanup, and disposal. Hosted rebuildable sends detach both the owner
and token into `QuicConnectionSendDatagramUpdate`. A shared hosted
UDP-segmentation array emits one construction and one release for the one
shared owner, not a fabricated record per protected slice. The shard returns
the owner after synchronous endpoint-observer processing and then publishes
`Completed` or `Failed`; pending suppression cleanup publishes `Canceled`.
The reason describes host-observer completion and does not claim independently
verified kernel acceptance.

Construction observation/epoch/raw v3 adds the closed
`OutboundPacketProtection`, `Protect`, and `PacketProtection` values. Release
observation/raw v7 adds only that owner path. Unified evidence/raw and the raw
export manifest advance to v2 because the nested buffer summary is now v3.
All earlier schemas remain immutable, and the lifetime validator accepts both
retained construction v2/release v6 pairs and current v3/v7 pairs.

The focused verification sequence is:

| Invocation | Result | Classification and disposition |
| --- | --- | --- |
| First test-project Release build | Failed with one `CS8156` error because a record property was passed directly by `in` to the diagnostic release observer | `diagnostic_only`; compile-time implementation correction only. A local token copy replaced the invalid call. No runtime or evidence row was produced. |
| Final test-project Release build | Zero warnings and zero errors in 53.32 seconds | `accepted` focused build evidence. |
| Stage 2 contracts, send-runtime ownership, and raw-package band | 83 passed, zero failed, zero skipped in 16 seconds | `accepted`; includes v3/v7 schemas, v2 unified schemas, loss/retransmission transfer, hosted detachment, exact release, and permanent host contract identity. |
| Shard, listener send-resilience, UDP-segmentation, application-datagram batching, recovery, and retransmission band | 286 passed, zero failed, zero skipped in eight seconds | `accepted`; endpoint, batching, recovery, and ownership behavior remain correct. |
| Final `REQ-QUIC-CRT-0182` run after retained-contract routing was added | 34 passed, zero failed, zero skipped in two seconds | `accepted`; current v3/v7 and retained v2/v6 construction/release joins both validate. |
| Raw-host Release build | Zero warnings and zero errors in 5.01 seconds | `accepted`; v3 construction, v7 release, and unified raw v2 identities compile in the permanent host. |
| Focused SpecTrace model validation | `SPEC-QUIC-CRT-STAGE2-ACTOR-MEMORY`, `ARC-QUIC-CRT-0067`, `WI-QUIC-CRT-0068`, and `VER-QUIC-CRT-0069` each returned `True` | `accepted` focused trace evidence. |
| New-schema parse validation | Eight new construction, release, unified, and manifest schemas parsed successfully | `accepted` contract syntax evidence. |
| Initial generated-schema destination | The first apply-patch orchestration placed the eight new unstaged schema files in `C:\shared\src\incursa\schemas` because its patch paths were relative to the desktop workspace root | `diagnostic_only`; the exact files were moved into the repository with apply-patch, the verified empty accidental directory was removed, and no evidence or user-authored file was overwritten. |

No campaign axis varied and no new raw, unified, normalized, curated, split,
or analysis rows were generated. Receive credit, all four Stage 1 axes,
`actor_work_quantum`, and `buffer_copy_coalescing` remain applied as
`legacy_current` outside earlier explicitly retained Stage 1 smoke treatments.
Dataset inclusion and exclusion counts are unchanged. No BenchmarkDotNet run,
performance claim, large campaign, ProtocolLab deployment, dataset transform,
ML analysis, CI run, push, or active behavior occurred.

Eight closed managed construction paths are now terminally correlated:
`receive_segment`, `application_write_request`, `oversized_raw_queue`,
`formatted_stream_payload`, `combined_application_send`,
`retransmission_clone`, `sent_packet_plaintext_retention`, and
`outbound_packet_protection`. Hosted endpoint handoff continues the protected
owner rather than creating a second construction. Linux unmanaged `sendmmsg`
staging and independently verified kernel-send outcome remain explicit
platform/outcome gaps, not production-controller inputs.

The next architecture slice remains Stage 2 actor work-unit definition,
ready-stream and connection fairness outcomes, cooperative safe checkpoints,
and exactly-once follow-on/repost design. A distinct conservative
`buffer_copy_coalescing` implementation, force-legacy rollback, and shadow
readiness remain open. No large dataset or ML analysis is authorized before
those architecture gates, and production activation remains unauthorized.

## Stage 2 Actor Work Vector And Repost Ownership Foundation

Local commit
`ce7904bba2a6aa4f5533269003e8118ddbf04ecb` defines the first bounded actor
work and repost-ownership primitives without changing the shard drain,
transition, effect, follow-on, timer, recovery, cancellation, disposal,
terminal, or buffer-ownership paths.

`quic-actor-useful-work-vector-v1` preserves one dispatch, its closed work
kind, effect count, three follow-on counts, complete service duration, and
optional queue delay as separate components. It deliberately does not sum
unlike work into a scalar, choose a threshold, or become a production
controller input.

`QuicActorContinuationRepostGate` packs one connection-local monotonic
generation and the closed `Idle`, `Posted`, `Servicing`, `RepostRequested`,
or `Stopped` state into one atomic value. One idle requester owns enqueue of
the exact posted generation. Requests during service coalesce, safe-boundary
completion creates at most one next generation, stale or duplicate tokens
cannot act, and an abandoned post or stop fails closed. The gate has no queue,
callback, timer, protocol state, model, threshold, or policy lookup and is not
instantiated by the shard. Exact remaining-work signals, cooperative yield
sites, priority and bypass rules, and ownership across yield remain required
before integration.

The focused verification sequence is:

| Invocation | Result | Classification and disposition |
| --- | --- | --- |
| First test-project Release build | Failed with one `CS1503` error because a `Parallel.For` lambda parameter named `_` made `out _` bind as a `long` instead of a discard | `diagnostic_only`; test-source compile correction only. The parameter was renamed. No runtime behavior or evidence row was produced. |
| Final test-project Release build | Zero warnings and zero errors in 54.75 seconds | `accepted` focused build evidence. |
| Actor observation, actor work/repost requirement, and shard correctness band | 26 passed, zero failed, zero skipped in one second | `accepted`; includes vector preservation, one enqueue owner, exact generation begin and completion, concurrent request coalescing, remaining-work repost, stale and duplicate token rejection, abandoned-post and stop behavior, 16,384 deterministic reference-model transitions, existing actor observation, and existing shard correctness. |
| Focused SpecTrace model validation | `SPEC-QUIC-CRT-STAGE2-ACTOR-MEMORY`, `ARC-QUIC-CRT-0067`, `WI-QUIC-CRT-0068`, and `VER-QUIC-CRT-0069` each returned `True`; reciprocal `REQ-QUIC-CRT-0186` links and source/test homes were present | `accepted` focused contract and trace evidence. |
| Repository-wide `core` SpecTrace validator | Reported the existing migration baseline of 2,692 schema and unresolved-reference errors across the repository | `diagnostic_only`; the global validator remains an unsuitable clean gate for this slice. No error was deleted, relabeled, or treated as a focused failure. |

No campaign axis varied and no new raw, unified, normalized, curated, split,
or analysis rows were generated. Receive credit, all four Stage 1 axes,
`actor_work_quantum`, `ready_stream_fairness`,
`buffer_copy_coalescing`, and `adaptive_backpressure` remain applied as
`legacy_current` outside earlier explicitly retained Stage 1 smoke
treatments. Dataset inclusion and exclusion counts are unchanged. No
BenchmarkDotNet run, performance claim, large campaign, ProtocolLab
deployment, dataset transform, ML analysis, CI run, push, or active behavior
occurred.

The actor work vector and repost token-ownership state machine are now
checkpointed. The next actor slice must supply honest timer-lateness and
fairness observations, exact remaining-work signals, complete-shard coverage,
and reviewed cooperative yield sites. The repost gate cannot be wired until
timer, recovery, cancellation, disposal, terminal, and buffer-ownership
priority tests exist. Active behavior remains unauthorized.

## Stage 2 Actor Timer-Lateness And Service-Cadence Evidence

Local commit
`889f498d08dcf1508f3dba5b8d86f4ffdd2905b4` advances actor observation and
epoch contracts to v2 and unified evidence, raw rows, validation, export, and
manifest contracts to v3 without changing shard scheduling or any applied
policy.

Deadline-scheduler timer work now retains its exact scheduled due tick in a
storage slot that is inactive for ordinary event work. The shard work item
remains 144 bytes. At actor service start, the observation records
nonnegative deadline lateness. A timer without scheduler provenance remains
explicitly missing; non-timer work treats lateness as not applicable. Invalid
time-domain state is explicit and never changes timer order or priority.

Each observed connection also retains one previous service-start timestamp.
After the first observation, the next dispatch records the connection-local
inter-service gap. This is only a service-cadence precursor: it is not
continuous runnable time, cross-connection coverage, or starvation. Actor
epoch v2 aggregates gap and lateness counts, totals, maxima, and integer EWMAs
with saturating arithmetic. Retained actor v1 and unified v1/v2 schemas remain
immutable.

The focused verification sequence is:

| Invocation | Result | Classification and disposition |
| --- | --- | --- |
| Final test-project Release build | Zero warnings and zero errors in 64.22 seconds | `accepted` focused build evidence. |
| Actor v2, unified v3, work-item layout, repost foundation, shard, deadline scheduler, and permanent-package correctness band | 74 passed, zero failed, zero skipped in 16 seconds | `accepted`; includes exact scheduled lateness, first and later service-gap validity, bounded aggregation, unified raw export, 144-byte layout, deadline ordering, shard behavior, and current host contract identities. |
| Final actor and unified requirement rerun after numeric/string validity parsing was hardened | 15 passed, zero failed, zero skipped in four seconds | `accepted`; the actor validator accepts both schema-legal validity encodings and still rejects contradictory gap or deadline state. |
| Raw QUIC host Release build | Zero warnings and zero errors in 5.51 seconds | `accepted`; actor epoch v2 and unified raw v3 compile in the permanent evidence host. |
| New-schema and PowerShell parse validation | Five new actor, unified, raw, and manifest schemas parsed successfully; all four edited evidence scripts had zero PowerShell AST parse errors | `accepted` focused contract syntax evidence. |
| Focused SpecTrace model validation | `SPEC-QUIC-CRT-STAGE2-ACTOR-MEMORY`, `ARC-QUIC-CRT-0067`, `WI-QUIC-CRT-0068`, and `VER-QUIC-CRT-0069` each returned `True` | `accepted` focused trace evidence. |

No campaign axis varied and no new raw, unified, normalized, curated, split,
or analysis rows were generated. Receive credit, all four Stage 1 axes,
`actor_work_quantum`, `ready_stream_fairness`,
`buffer_copy_coalescing`, and `adaptive_backpressure` remain applied as
`legacy_current` outside earlier explicitly retained Stage 1 smoke
treatments. Dataset inclusion and exclusion counts are unchanged. No
BenchmarkDotNet run, performance claim, large campaign, ProtocolLab
deployment, dataset transform, ML analysis, CI run, push, or active behavior
occurred.

Timer lateness and connection-local service cadence are now available in
every observed actor epoch. Honest runnable-state, complete-shard coverage,
cross-connection fairness outcomes, exact remaining work, and reviewed
cooperative yield sites remain the next actor gates. Inter-service gap cannot
be used as a runnable or starvation label. Active behavior remains
unauthorized.

## Stage 2 Permanent Actor Dispatch Stream And Exact Epoch Join

Local commit `020a2382ff7efda58ca7325dd5586f62a3d84c99` adds one
append-only sample-scoped actor dispatch stream without changing the retained
actor observation-v2, actor epoch-v2, unified evidence-v3, or unified raw-v3
contracts. The raw host emits
`adaptive-runtime-actor-service-raw-v1` for every observed actor dispatch.
Bounded writer failure emits
`adaptive-runtime-actor-service-export-failure-v1` and remains
behavior-neutral.

The unified exporter manifest advances to v4. It writes actor dispatches to
`adaptive-runtime-actor-service-observations.jsonl` separately from unified
connection epochs and validates deterministic membership by exact
`source + connectionKey + serviceSequence`. Every inclusive actor sequence
range summarized by a unified epoch must have exactly one raw dispatch.
Missing, duplicate, out-of-order, or orphan dispatches fail semantic
validation. Actor and unified writer failures remain in the append-only
failure stream and classify the export `invalid_contract`.

The focused verification sequence is:

| Invocation | Result | Classification and disposition |
| --- | --- | --- |
| Raw QUIC host Release build | Zero warnings and zero errors in 13.93 seconds | `accepted`; the separate actor writer, source-generated records, and guarded failure path compile. |
| First `REQ-QUIC-CRT-0183` run | Six passed and one failed because `Measure-Object -Property` cannot read a field from the ordered-dictionary source records | `diagnostic_only`; manifest aggregation was corrected to project integer values before summation. No runtime behavior or accepted dataset row was inferred. |
| Immediate corrected `REQ-QUIC-CRT-0183` rerun | Seven passed, zero failed, zero skipped in 8.06 seconds | `accepted` before the explicit missing-actor and actor-writer-failure cases were added. |
| Final test-project Release build | Zero warnings and zero errors in 50.26 seconds | `accepted` focused build evidence. |
| Final `REQ-QUIC-CRT-0183` run | Seven passed, zero failed, zero skipped in 9.63 seconds | `accepted`; includes exact actor range membership, retained actor writer failure with `invalid_contract`, missing actor rejection with `actorMissing=1`, append-only output rejection, and the existing post-service boundary tests. |
| PowerShell and schema syntax | Two evidence scripts parsed with zero AST errors; actor raw v1, actor export-failure v1, and manifest v4 JSON parsed successfully | `accepted` focused syntax evidence. |
| Focused SpecTrace model validation | `SPEC-QUIC-CRT-STAGE2-ACTOR-MEMORY`, `ARC-QUIC-CRT-0067`, `WI-QUIC-CRT-0068`, and `VER-QUIC-CRT-0069` each returned `True` | `accepted` focused contract and trace evidence for the refined `REQ-QUIC-CRT-0184`. |

No campaign axis varied and no raw campaign, unified campaign, normalized,
curated, split, or analysis rows were generated. Dataset inclusion and
exclusion counts are unchanged: this slice adds zero rows and excludes zero
additional rows. Receive credit, all four Stage 1 axes,
`actor_work_quantum`, `ready_stream_fairness`,
`buffer_copy_coalescing`, and `adaptive_backpressure` remain applied as
`legacy_current` outside earlier explicitly retained Stage 1 smoke
treatments. No BenchmarkDotNet run, performance claim, large campaign,
ProtocolLab deployment, dataset transform, ML analysis, CI run, push, or
active behavior occurred.

Per-dispatch order, wake membership, and actor-to-epoch membership are now
permanently recoverable without silently treating the dispatch as an
epoch-independent row. Honest shard-wide service-contender coverage,
runnable-state intervals, exact remaining work, complete fairness outcomes,
and reviewed cooperative yield sites remain open. Active behavior remains
unauthorized.

## Stage 2 Exact Service-Contender Accounting Foundation

Local commit `4746ab0e` implements `REQ-QUIC-CRT-0187` without changing actor
observation v2, actor epoch v2, unified evidence v3, any applied policy, or
shard scheduling. Each runtime maintains an atomic outstanding shard-work
count. A shard increments its contender count only on a connection's
zero-to-one transition and decrements only on its one-to-zero transition.
Accepted tracking uses one previously unused compact work-item flag, retaining
the 144-byte layout and existing scheduled-deadline storage.

Enqueue rejection rolls back accepted tracking. Normal service closes tracking
after actor evidence, resource release, and post-service epoch publication.
Cancellation and shutdown drain close it after resource release. Disposing a
shard before its consumer starts now explicitly drains and releases its
already-accepted work rather than leaving ownership and accounting stranded.
Saturation or underflow makes the accounting invalid and fails closed.

The focused verification sequence is:

| Invocation | Result | Classification and disposition |
| --- | --- | --- |
| Initial exact two-test band | Two passed, zero failed, zero skipped in 4.60 seconds | `accepted`; two posted connections counted as two and the tracking bit preserved scheduled timer provenance and the 144-byte layout. |
| First focused SpecTrace validation after adding `REQ-QUIC-CRT-0187` | The new specification failed its model check because its first draft contained three normative modal verbs; the architecture, work item, and verification artifacts returned `True` | `diagnostic_only`; the requirement was rewritten as one atomic `MUST` clause without weakening any accounting or non-relabeling constraint. |
| Final test-project Release build | Zero warnings and zero errors in 62.38 seconds | `accepted` focused build evidence. |
| Final actor, work-item-layout, and shard band | 21 passed, zero failed, zero skipped in one second | `accepted`; covers same-connection coalescing, two-connection counting, ordinary post-service closure, pre-consumer shutdown drain, existing actor validity, compact layout, and existing shard behavior. |
| Final focused SpecTrace model validation | `SPEC-QUIC-CRT-STAGE2-ACTOR-MEMORY`, `ARC-QUIC-CRT-0067`, `WI-QUIC-CRT-0068`, and `VER-QUIC-CRT-0069` each returned `True` | `accepted`; reciprocal `REQ-QUIC-CRT-0187` trace homes are present. |

No campaign axis varied and no raw campaign, unified campaign, normalized,
curated, split, or analysis rows were generated. Dataset inclusion and
exclusion counts are unchanged: this slice adds zero rows and excludes zero
additional rows. Receive credit, all four Stage 1 axes,
`actor_work_quantum`, `ready_stream_fairness`,
`buffer_copy_coalescing`, and `adaptive_backpressure` remain applied as
`legacy_current` outside earlier explicitly retained Stage 1 smoke
treatments. No BenchmarkDotNet run, performance claim, ProtocolLab
deployment, dataset transform, ML analysis, CI run, push, or active behavior
occurred.

The exact posted-or-servicing connection count is an accounting precursor
only. It is not yet emitted by actor observation v2 and cannot be called a
runnable-connection count, continuous runnable time, starvation, fairness, or
a controller input. The next checkpoint must version the actor and unified
evidence contracts before exposing it and must keep
`MissingRunnableConnectionCount` authoritative. Active behavior remains
unauthorized.

## Stage 2 Versioned Service-Contender Evidence

Local commit `19f69274` advances the behavior-neutral actor evidence spine
without changing shard scheduling or any applied policy. Actor observation
and provenance advance to v3, actor epoch aggregation advances to v3, the
sample-scoped actor raw wrapper advances to v2, unified internal evidence and
raw wrappers advance to v4, and the append-only export manifest advances to
v5. Every retained schema remains unchanged and readable.

Each observed service turn captures the exact shard-wide count of connections
with one or more accepted posted-or-servicing work items before the current
work item completes its accounting lifetime. A valid value is at least one.
Missing, invalid, and saturated accounting produces a null value plus explicit
validity. `MissingRunnableConnectionCount` remains asserted because this count
does not establish runnable state, continuous runnable intervals, starvation,
or fairness.

The v3 epoch summary records the number of turns with a valid contender value,
the maximum valid value, and the number of valid turns whose value was greater
than one. The unified validator joins every raw dispatch by
`source + connectionKey + serviceSequence` to exactly one inclusive epoch
range, then requires these three aggregates to match that epoch exactly.
Contradictory value/validity combinations, invalid exposed values, aggregate
mismatches, missing, duplicate, orphan, and out-of-order records fail the
contract.

The exact verification sequence is:

| Invocation | Result | Classification and disposition |
| --- | --- | --- |
| Initial solution build command using the nonexistent `quic-dotnet.slnx` name | MSBuild `MSB1009`, project file does not exist | `diagnostic_only`; the repository solution was resolved as `Incursa.Quic.slnx` and no test or runtime evidence was inferred. |
| First corrected `dotnet build Incursa.Quic.slnx -c Release --no-restore` | Zero warnings and zero errors in 66.57 seconds | `accepted`; core v3 observation and epoch compilation before focused testing. |
| First PowerShell AST one-liners run through an extra nested shell | Three parser errors because the outer shell expanded the command variables | `diagnostic_only`; command construction only. Direct AST parsing was then used and all four scripts parsed successfully. |
| Interim complete Release build after schema, host, validator, and test integration | Zero warnings and zero errors in 52.65 seconds | `accepted`; the versioned evidence spine and permanent raw host compile. |
| First actor, unified, and package band | 44 passed, zero failed, zero skipped in 22.61 seconds | `accepted`; positive raw-to-epoch contender joins and host contract versions are covered. |
| Final solution Release build before the new negative aggregate test | Zero warnings and zero errors in 47.83 seconds | `accepted`; build-before-test gate. |
| First 44-test rerun with the intentional aggregate-mismatch case | 43 passed and one failed because the test expected an internal row-reason token while the validator's stable public error reported only `joinFailures=1` | `diagnostic_only`; the intentionally mismatched evidence was rejected correctly. Only the assertion was changed to the stable public error contract, and the failed result is retained. |
| Final test-project Release build | Zero warnings and zero errors in 48.17 seconds | `accepted`; build-before-rerun gate. |
| Corrected actor, unified, and package band | 44 passed, zero failed, zero skipped in 18 seconds | `accepted`; includes exact service-start values `2, 2, 1`, epoch coverage/maximum/count-above-one aggregation, value/validity semantics, raw membership, aggregate-mismatch rejection, append-only export, and retained failure classifications. |
| Stage 2 requirement-home and compact-layout band | 70 passed, zero failed, zero skipped in 9 seconds | `accepted`; `REQ-QUIC-CRT-0181` through `0186` plus work-item layout remain correct, including the retained 144-byte layout. |
| PowerShell AST and JSON syntax validation | Four edited PowerShell scripts parsed with zero AST errors; six new schemas and four edited SpecTrace artifacts parsed as JSON | `accepted`; contract syntax evidence. |
| Focused SpecTrace model validation | `SPEC-QUIC-CRT-STAGE2-ACTOR-MEMORY`, `ARC-QUIC-CRT-0067`, `WI-QUIC-CRT-0068`, and `VER-QUIC-CRT-0069` each returned `True` | `accepted`; reciprocal v3/v4/v5 schema, implementation, test, and evidence references are present. |

No campaign axis varied. Receive credit, all four Stage 1 axes,
`actor_work_quantum`, `ready_stream_fairness`,
`buffer_copy_coalescing`, and `adaptive_backpressure` remain applied as
`legacy_current` outside earlier explicitly retained Stage 1 smoke
treatments. No BenchmarkDotNet run, performance claim, ProtocolLab
deployment, raw campaign, normalized transform, curated or split dataset,
ML analysis, CI run, push, or active behavior occurred. Dataset inclusion and
exclusion counts remain unchanged: zero rows added and zero rows excluded by
this slice.

The stopped
`application-send-turn-neutrality-download-20260724-r002` normalization
remains preserved as `diagnostic_incomplete`; its 55,658 raw epochs, five
cell results, hashes, classifications, and partial output were not restarted,
deleted, overwritten, or relabeled. The next actor checkpoint remains exact
remaining-work signals and reviewed cooperative yield boundaries. Complete
runnable intervals and fairness outcomes still do not exist. Active behavior
remains unauthorized.

## Stage 2 Exact Accepted-Dispatch Backlog Evidence

Local commit `11bb8496` implements the behavior-neutral
`REQ-QUIC-CRT-0188` observation checkpoint without changing shard scheduling,
the actor service lifecycle, or any applied policy. Actor observation and
provenance advance to v4, actor epoch aggregation advances to v4, the
sample-scoped actor raw wrapper advances to v3, unified internal evidence and
raw wrappers advance to v5, and the append-only export manifest advances to
v6. All earlier versioned schemas remain retained.

Immediately before the current accepted dispatch completes its accounting
lifetime, the runtime now reports the exact number of already accepted
connection work items that remain after the current item. The value is an
O(1) connection-local accounting observation. It is not a runnable-work
count, an internal continuation-ready signal, a starvation or fairness
outcome, or a controller input. Missing, invalid, or saturated accounting
reports a null value plus explicit validity rather than substituting zero.

The v4 epoch summary records valid observation coverage, the saturating total,
the maximum, and the number of observed turns with accepted work remaining.
The unified raw validator joins every actor dispatch by
`source + connectionKey + serviceSequence` to exactly one inclusive epoch and
recomputes all four aggregates. Contradictory value and validity state,
accepted-work exposure under invalid contender accounting, aggregate
mismatch, missing, duplicate, orphan, or out-of-order records fail the
contract.

The only reviewed cooperative boundary remains after a complete work-item
lifecycle: transition, effect execution, follow-on measurement, actor
evidence publication, resource release, post-service epoch publication, and
contender completion. Transition and effect interiors remain non-preemptible.
This observation does not satisfy the still-open exact continuation-ready or
runnable-state safety gates and does not connect the repost gate.

The exact verification sequence is:

| Invocation | Result | Classification and disposition |
| --- | --- | --- |
| Initial solution Release build before schema and test integration | Zero warnings and zero errors in 65.39 seconds | `accepted`; the core v4 observation and epoch types compiled before focused testing. |
| Interim complete solution Release build after schema, host, validator, and test integration | Zero warnings and zero errors in 47.69 seconds | `accepted`; the versioned evidence spine and permanent raw host compile. |
| Interim actor, unified-export, and package band | 44 passed, zero failed, zero skipped in 19 seconds | `accepted`; positive exact accepted-work values, export versions, and joins were covered before the final negative cases. |
| Final complete solution Release build | Zero warnings and zero errors in 49.56 seconds | `accepted`; final build-before-test gate. |
| Final actor, unified-export, and package band | 45 passed, zero failed, zero skipped in 20 seconds | `accepted`; includes exact values `1, 0, 0`, missing-value semantics, value/validity rejection, exact raw-to-epoch aggregates, aggregate-mismatch rejection, append-only export, and retained failure classifications. |
| Final Stage 2 requirement-home and compact-layout band | 71 passed, zero failed, zero skipped in 11 seconds | `accepted`; `REQ-QUIC-CRT-0181` through `0186`, the new `REQ-QUIC-CRT-0188` coverage, and retained work-item layout behavior remain correct. |
| PowerShell AST and JSON syntax validation | Four edited PowerShell scripts parsed with zero AST errors; six new schemas and four edited SpecTrace artifacts parsed as JSON | `accepted`; contract syntax evidence. |
| Focused SpecTrace model validation | `SPEC-QUIC-CRT-STAGE2-ACTOR-MEMORY`, `ARC-QUIC-CRT-0067`, `WI-QUIC-CRT-0068`, and `VER-QUIC-CRT-0069` each returned `True` | `accepted`; reciprocal `REQ-QUIC-CRT-0188` schema, implementation, test, and evidence references are present. |

No campaign axis varied. Receive credit and all four implemented Stage 1 axes
remain applied as `legacy_current` outside earlier explicitly retained Stage
1 smoke treatments. `actor_work_quantum`, `ready_stream_fairness`,
`buffer_copy_coalescing`, and `adaptive_backpressure` are not forceable
policy axes yet and remain behaviorally legacy. No BenchmarkDotNet run,
performance claim, ProtocolLab deployment, raw campaign, normalized
transform, curated or split dataset, ML analysis, CI run, push, or active
behavior occurred. Dataset inclusion and exclusion counts are unchanged:
zero rows added and zero rows excluded by this slice.

The stopped
`application-send-turn-neutrality-download-20260724-r002` normalization
remains preserved as `diagnostic_incomplete`; its 55,658 raw epochs, five
cell results, hashes, classifications, and partial output were not restarted,
deleted, overwritten, or relabeled. The next actor checkpoint is a distinct
exact continuation-ready signal and reviewed cooperative-yield ownership.
Complete runnable intervals and fairness outcomes remain open. Active behavior
remains unauthorized.

## Stage 2 Continuation Assessment And Implementation-Freeze Matrix

Local implementation commit `4da502d9` closes the current behavior-neutral
continuation-assessment prerequisite without making `actor_work_quantum`
forceable or changing shard scheduling. It also adds
[`../design/adaptive-runtime-policy-axis-implementation-matrix.md`](../design/adaptive-runtime-policy-axis-implementation-matrix.md)
as the checkpoint companion to the unchanged approved roadmap.

`REQ-QUIC-CRT-0189` introduces the closed per-producer states
`NotAssessed`, `Drained`, `Scheduled`, `Blocked`,
`ReadyAfterCooperativeYield`, and `Invalid` for application-send,
flow-control, and stream-capacity follow-on work. State and bounded
remaining-count consistency is mandatory. No current producer emits
`ReadyAfterCooperativeYield`; that value is reserved for a later reviewed
cooperative-yield boundary. An unvisited producer remains `NotAssessed`, and
pending work is not silently relabeled runnable or continuation-ready.

Actor observation and provenance advance to v5, actor epoch aggregation
advances to v5, actor raw advances to v4, unified evidence and raw advance to
v6, and the append-only export manifest advances to v7. Earlier schemas remain
unchanged. The raw-to-epoch validator recomputes complete assessment coverage,
per-producer state counts, and maximum remaining counts and rejects
contradictory state/count pairs or aggregate mismatches.

The retained verification sequence is:

| Invocation | Result | Classification and disposition |
| --- | --- | --- |
| Initial `dotnet build Incursa.Quic.slnx -c Release --no-restore --nologo` | Six compile errors: five instance/static helper errors and one invalid integer-range comparison; zero warnings | `diagnostic_only`; implementation defects were corrected before any test evidence was accepted. |
| First mechanism-test attempt using the test runner's unsupported exact `Name=...` filter form | Zero tests selected | `diagnostic_only`; no pass was inferred. The filter was corrected to supported fully-qualified-name matching. |
| Corrected mechanism band | Four passed, zero failed, zero skipped in 440 milliseconds | `accepted`; state/count construction, completeness, invalidity, and reserved ready-after-yield semantics are covered. |
| Interim and final solution Release builds during schema, host, validator, and negative-test integration | Final build: zero warnings and zero errors in 45.20 seconds | `accepted`; the complete continuation-assessment evidence spine compiled. |
| Focused actor, unified-export, package, and direct-measurement band | 48 passed, zero failed, zero skipped in 23 seconds | `accepted`; includes producer capture, exact aggregates, schema versions, joins, mismatch rejection, and retained host/package contracts. |
| Broader Stage 2 requirement-home, compact-layout, and direct-measurement band | 74 passed, zero failed, zero skipped in 14 seconds | `accepted`; actor ownership, terminal accounting, retained compact layout, and adjacent behavior remain correct. |
| `dotnet build tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release --no-restore --nologo` after commit `4da502d9` | Zero warnings and zero errors in 63.98 seconds | `accepted`; focused post-commit build-before-test gate. |
| `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release --no-build --no-restore --nologo --filter "FullyQualifiedName~Incursa.Quic.Tests.RequirementHomes.CRT.REQ_QUIC_CRT_0181\|FullyQualifiedName~Incursa.Quic.Tests.RequirementHomes.CRT.REQ_QUIC_CRT_0183"` | 19 passed, zero failed, zero skipped in 12 seconds | `accepted`; the directly affected actor and unified-export requirement homes pass from the committed implementation. |
| Direct PowerShell AST and JSON parsing | Four edited PowerShell scripts parsed with zero AST errors; six new schemas parsed as JSON | `accepted`; focused script and contract syntax evidence. |
| Focused SpecTrace model validation | `SPEC-QUIC-CRT-STAGE2-ACTOR-MEMORY`, `ARC-QUIC-CRT-0067`, `WI-QUIC-CRT-0068`, and `VER-QUIC-CRT-0069` each returned `True` | `accepted`; reciprocal `REQ-QUIC-CRT-0189` trace, schema, implementation, test, and evidence references are present. |

No active build, test, campaign, or dataset transform remained after the
checkpoint. The observed `dotnet` processes were reusable MSBuild nodes, and
the observed PowerShell processes belonged to the Codex host and monitoring
path. No process was terminated.

No campaign axis varied. Receive credit and all four implemented Stage 1 axes
remain applied as `legacy_current`. Stage 2 axes remain behaviorally legacy:
`actor_work_quantum` has an observation foundation but is not shadowable or
forceable; `ready_stream_fairness` and `adaptive_backpressure` have no axis
seam; and `buffer_copy_coalescing` remains observation-only. Unified-schema
row counts, classifications, inclusions, and exclusions are unchanged because
this checkpoint generated zero campaign rows.

The exact `actor_work_quantum` blocker is now explicit: no reviewed
cooperative-yield point owns an exactly resumable work unit. A distinct forced
value would currently be behaviorally fake or could split transition/effect
ownership. Under the implementation-breadth anti-drift rule, the next work
must deliver the independent `ready_stream_fairness` force seam or, if it
shares the same unsafe boundary, record that dependency and move to
`buffer_copy_coalescing`. No further actor observation-only checkpoint is
authorized first.

The stopped
`application-send-turn-neutrality-download-20260724-r002` transform remains
`diagnostic_incomplete`. Its 55,658 raw epochs, five cell results, hashes,
classifications, and partial dataset output were not restarted, deleted,
overwritten, relabeled, or used for threshold or model derivation.

No BenchmarkDotNet run, performance number, ProtocolLab deployment, large
campaign, dataset transform, normalized/curated/split dataset, ML analysis,
CI work, push, or active behavior occurred. Performance measurement and
`active_internal` remain unauthorized.
## 2026-07-24 Buffer Copy Coalescing Implementation Checkpoint

Classification: `accepted` implementation and focused correctness checkpoint;
not performance, campaign, policy-acceptance, threshold, dataset, or ML
evidence.

Active axis: `buffer_copy_coalescing`.

Adjacent applied axes: `receive_credit_publication`,
`application_send_turn_planning`, `application_send_batch_formation`,
`queued_send_burst_budget`, and `oversized_write_admission_quantum` remain
`legacy_current`. No campaign axis varied.

Process and recovery disposition:

- no adaptive campaign, normalization, transform, build, or test process was
  active before the slice;
- the retained 55,658-epoch send-turn-only transform remains
  `diagnostic_incomplete`, unchanged, and was not restarted;
- clean prerequisite checkpoints `4da502d9` and `d358f501` remain preserved;
  and
- CI was ignored and no push was attempted.

Capability delivered:

- closed values `legacy_current` and `memory_conservative`;
- exact decision boundary after the Stage 1 legal combined-send prefix and
  before combined-owner rent/fill;
- lower-only two-source-segment conservative cap;
- disabled, observe-only, shadow, forced legacy, and forced conservative
  operation;
- distinct configured, forced, recommended, selected, applied, source,
  reason, safety, fallback, and buffer-lifetime latch state;
- invalid, missing, stale, saturated, contradictory, out-of-domain, and
  lifecycle fallback to the exact legacy prefix;
- rejection of simultaneous behavior-distinct receive-credit or Stage 1
  forcing;
- force-legacy rollback;
- buffer observation, epoch, and raw v4; unified evidence and raw v7; export
  manifest v8; and
- permanent raw-host configuration and semantic validation with five
  implemented axis records per unified row.

Correctness commands and accepted results:

| Command or check | Result |
| --- | --- |
| `dotnet build src/Incursa.Quic/Incursa.Quic.csproj -c Release --no-restore --nologo` | zero warnings, zero errors |
| `dotnet build tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release --no-restore --nologo` | zero warnings, zero errors |
| `dotnet build eng/protocol-lab/servers/IncursaRawQuicServer/IncursaRawQuicServer.csproj -c Release --no-restore --nologo` | zero warnings, zero errors |
| `dotnet test ... --filter "FullyQualifiedName~REQ_QUIC_CRT_0190"` | 18 passed, zero failed, zero skipped |
| `dotnet test ... --filter "FullyQualifiedName~REQ_QUIC_CRT_0190\|FullyQualifiedName~REQ_QUIC_CRT_0183\|FullyQualifiedName~REQ_QUIC_CRT_0182\|FullyQualifiedName~ProtocolLabPackageTemplateTests"` | 86 passed, zero failed, zero skipped |
| `dotnet test ... --filter "FullyQualifiedName~REQ_QUIC_CRT_0175\|FullyQualifiedName~REQ_QUIC_CRT_0176\|FullyQualifiedName~REQ_QUIC_CRT_0177\|FullyQualifiedName~REQ_QUIC_CRT_0178\|FullyQualifiedName~REQ_QUIC_CRT_0179\|FullyQualifiedName~REQ_QUIC_CRT_0180"` | 164 passed, zero failed, zero skipped |
| PowerShell AST parse for the five changed adaptive-runtime scripts | zero parse errors |
| JSON parse for six new schemas | six of six clean |
| direct `model/model.schema.json` validation | four of four Stage 2 SpecTrace homes returned `True` |
| `git diff --check` | clean |

Retained diagnostic results:

- the first core build reported one S3358 nested-conditional analyzer error;
- the first two test builds exposed an internal enum through a public xUnit
  theory and used a nonexistent receive-credit enum member;
- the first retained-schema reruns exposed missing v2 reason and reason-version
  rewrites in the compatibility fixture;
- the first raw-host source assertions still named the Stage 1-only
  single-axis message after the guard broadened to Stage 2; and
- one empty-object schema probe correctly failed the required-property check
  after all schema JSON parsed successfully.

Each diagnostic was corrected without deleting, relabeling, or overwriting the
failed result. No runtime or performance evidence was produced by those
commands.

Evidence counts:

- performance rows: 0;
- new raw, normalized, curated, split, or analysis rows: 0;
- dataset inclusions: unchanged;
- dataset exclusions and retained negatives: unchanged;
- campaigns: 0; and
- BenchmarkDotNet invocations: 0.

Local implementation commit: `df8ee570` (`Implement bounded buffer coalescing
axis`). Nothing was pushed.

Next implementation decision: review the conservative application-visible
contract for `adaptive_backpressure`. `actor_work_quantum` and
`ready_stream_fairness` retain their exact safety blockers. Performance
measurement and `active_internal` remain unauthorized.

## 2026-07-24 Adaptive Backpressure Implementation Checkpoint

Classification: `accepted` implementation and focused correctness checkpoint;
not performance, campaign, policy-acceptance, threshold, dataset, or ML
evidence.

Active axis: `adaptive_backpressure`.

Adjacent applied axes: `receive_credit_publication`,
`application_send_turn_planning`, `application_send_batch_formation`,
`queued_send_burst_budget`, `oversized_write_admission_quantum`, and
`buffer_copy_coalescing` remain `legacy_current`. No campaign axis varied.

Process and recovery disposition:

- no adaptive campaign, normalization, transform, build, or test process was
  active before the slice;
- the retained 55,658-epoch send-turn-only transform remains
  `diagnostic_incomplete`, unchanged, and was not restarted;
- clean prerequisite commits `df8ee570` and `2fd61735` remain preserved;
- the user-approved policy-axis roadmap remains unchanged; and
- CI was ignored, no performance command ran, and no push was attempted.

Capability delivered:

- closed values `legacy_current` and `early_delay`;
- exact decision boundary before stream reservation or owner admission for one
  new application admission;
- one-admission latch and at most one immediately posted dispatcher/actor turn
  when an earlier admitted application-send operation remains queued;
- no rejection, policy failure, raised hard limit, network-progress wait, or
  change to already-admitted ownership;
- disabled, observe-only, shadow, forced legacy, and forced conservative
  operation;
- distinct forced, recommended, selected, applied, source, reason, safety,
  fallback, validity, latch, and version state;
- missing, stale, saturated, contradictory, invalid, out-of-domain,
  lifecycle, and continuation-unavailable fallback to `legacy_current`;
- authoritative cancellation, disposal, terminal, queue, buffer, stream,
  flow-control, congestion, pacing, recovery, ownership, and exactly-once
  completion guards;
- independently tested force-legacy rollback and throwing-sink neutrality;
- adaptive-backpressure observation, epoch, and raw v1; unified evidence and
  raw v8; export manifest v9; and
- a separate append-only sample stream with exact source-scoped
  `connectionKey + operationSequence` membership and distinct epoch/sample
  counts.

Correctness commands and accepted results:

| Command or check | Result |
| --- | --- |
| `dotnet build tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release --nologo` | zero warnings, zero errors; final build completed in 47.10 seconds |
| `dotnet build eng/protocol-lab/servers/IncursaRawQuicServer/IncursaRawQuicServer.csproj -c Release --nologo` | zero warnings, zero errors in 5.41 seconds |
| `dotnet test ... --filter "FullyQualifiedName~REQ_QUIC_CRT_0191"` | 20 passed, zero failed, zero skipped in 1 second |
| affected requirement, host-template, queue, and cancellation band | 141 passed, zero failed, zero skipped in 24 seconds |
| PowerShell AST parse | three changed adaptive-runtime scripts parsed with zero errors |
| JSON parse | six schemas and four SpecTrace artifacts parsed cleanly |
| focused SpecTrace model, uniqueness, and reciprocal trace validation | four of four artifacts passed; `REQ-QUIC-CRT-0191 -> ARC-QUIC-CRT-0068 -> WI-QUIC-CRT-0069 -> VER-QUIC-CRT-0070` is unique and reciprocal |
| `git diff --check` and cached diff check | clean |

Retained diagnostic results:

- the first implementation build used obsolete retention snapshot property
  names; the compile failure was preserved and corrected to
  `RetainedBufferCount` and `RetainedByteCount`;
- the first test build exposed internal enum values through a public xUnit
  theory; the compile failure was preserved and the parameters were changed
  to bytes;
- the first runtime delay assertion expected only the delayed admission to be
  observed; the deterministic failure was preserved and the assertion was
  corrected because unified observation intentionally records both
  admissions;
- the first unified-fixture build after adding backpressure raw export lacked
  the new local observation variable and failed with one `CS0103` after 55.03
  seconds; the fixture was corrected;
- the first raw-wrapper test rejected the external relative JSON-schema
  reference and produced one failure with 23 passes; the raw wrapper now uses
  an internal definition compatible with PowerShell `Test-Json`;
- the first direct schema-fixture build lacked `System.Text.Json` imports and
  failed with six compile errors after 45.01 seconds; the imports were added;
  and
- the repository-wide canonical SpecTrace validator retained 2,698 existing
  corpus/schema/reference errors. The changed four-artifact slice passes the
  canonical model and focused trace checks; no repo-wide cleanup was
  attempted or claimed.

Evidence counts:

- implemented unified axis records per epoch: 6;
- focused axis tests: 20 passed;
- affected correctness band: 141 passed;
- performance rows: 0;
- new raw, normalized, curated, split, or analysis rows: 0;
- dataset inclusions: unchanged;
- dataset exclusions and retained negatives: unchanged;
- campaigns and ProtocolLab deployments: 0;
- BenchmarkDotNet invocations: 0; and
- ML or threshold derivations: 0.

Local implementation commit: `25fa33cc` (`Implement bounded adaptive
backpressure axis`). Nothing was pushed.

Stage 2 disposition: `buffer_copy_coalescing` and `adaptive_backpressure` are
implementation-ready. `actor_work_quantum` retains the exact
cooperative-yield/resumable-work blocker, and `ready_stream_fairness` retains
the exact bounded-runnable/fairness-outcome blocker. Under the breadth-first
rule, the next independent axis is Stage 3 `packet_flush_cadence`.
Performance measurement, active behavior, CI work, and push remain
unauthorized.
