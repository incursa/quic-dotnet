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
