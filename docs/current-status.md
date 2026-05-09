# Current Repository Status

Last verified: 2026-05-09 for INT resumption runner proof with managed SSLKEYLOGFILE export,
CRT server-side resumption PSK acceptance proof, CRT server NewSessionTicket issuance proof,
INT non-HTTP/3 inventory dry-run proof,
RFC 9000 S5 disable-active-migration proof topoff, S6 reserved-version ignore
proof topoff, S2 concurrent-stream proof topoff, S2 stream-cancellation proof
topoff, S13 ECN
continuation-after-success proof
topoff, S13 ECN disable-on-validation-failure proof topoff, S13 ECT(1)+CE
too-small validation proof topoff, S13 ECT(0)+CE too-small validation proof
topoff, S13 ECN validation-before-use proof topoff, S13 ECT(1) validation count
topoff, S13 ECN packet-number-space separation, S13 ACK frame largest-packet
delay boundary closure, S13 CRYPTO retransmission acknowledgment-boundary
closure, S13 packet-number-space ACK separation, S13 multiple-packet
ACK-decision closure, S13 max-ack-delay and non-ack inclusion closure, S13
ACK-only feedback-loop edge proof, S13 periodic ACK-probe closure, RFC9001 tail
proof closure, trace substrate repair, metadata xref burn-down, SpecTrace core
validation, and regenerated QUIC requirement coverage triage. Earlier
runtime/proof-tail and hosted executive-read evidence remains pinned to the
individual dated closure notes below unless otherwise noted.

This page is an operator snapshot. It records the current repo state and the
next recommended work lane, but it does not replace the canonical requirements,
architecture, work items, or verification artifacts under `specs/`.

## 2026-05-09 INT Resumption Runner Closure Note

The `resumption` interop inventory cell is now supported/executed for the
checked QUIC interop-runner TLS session-resumption cell. The harness emits
opt-in NSS-style `SSLKEYLOGFILE` traffic-secret lines from the managed TLS key
schedule, while unsupported testcases still refuse to create a fake keylog file.
This closes the previous external runner blocker without changing the official
requirement statements.

The live command `pwsh -File scripts\interop\Invoke-QuicInteropRunner.ps1
-RepoRoot . -TestCases resumption` exited 0 on 2026-05-09 and preserved
evidence under
`artifacts\interop-runner\20260509-001723585-both-quic-go\`. The runner JSON
report records testcase `resumption` with `result: succeeded`.

This support claim stays limited to the runner's TLS session-resumption cell. It
does not claim HTTP/3, 0-RTT, anti-replay, external ticket persistence, public
API widening, or broader resumption support. `chacha20` remains blocked on
runner/platform cipher-suite policy support. The next source-level unresolved
runtime cell is `zerortt`, which requires server-side 0-RTT admission and
anti-replay ownership.

## 2026-05-08 CRT Server Resumption PSK Acceptance Closure Note

`REQ-QUIC-CRT-0151` now owns the internal managed server-side resumption
acceptance slice. When server resumption is explicitly enabled, the managed
listener keeps issued ticket material in a listener-local in-memory store, checks
later ClientHello `pre_shared_key` identities against live tickets from that
store, validates the binder from the stored resumption master secret and ticket
nonce, emits ServerHello `pre_shared_key` selection only for validated offers,
and derives matching PSK-DHE handshake protection on the accepted server/client
branches.

Focused negative proof covers unknown, expired, binder-invalid, malformed, and
duplicate PSK offers failing closed without pre-shared-key selection. The slice
does not open early_data or server-side 0-RTT admission, does not add anti-replay
or external ticket persistence, does not widen the public API/support promise,
and does not bring HTTP/3 into scope.

This closes the previous source-level `resumption` prerequisites named in the
2026-05-08 inventory note: shared server ticket state, binder validation,
resumed ServerHello selection, and PSK-DHE resumed handshake-secret derivation.
The live 2026-05-08 external runner attempt now progresses past the earlier
server-dispatch failure and PSK-rejection boundary, but quic-interop-runner
reports the testcase as `unsupported` with `Can't check test result. SSLKEYLOG
required.` The interop inventory therefore remains conservative until an honest
SSLKEYLOGFILE-backed proof path exists; the next source-level unresolved cell
after this slice is `zerortt`, which remains blocked on server-side 0-RTT
admission and anti-replay ownership.

Local verification passed: focused
`REQ_QUIC_CRT_0151|REQ_QUIC_INT_0002|InteropRunnerScriptDryRunTests`
reported 17/17 passing, SpecTrace core validation reported 526 artifacts,
Release build completed with 0 warnings and 0 errors, full Release no-build
test rerun reported 4,877/4,877 passing, and `git diff --check` exited 0
with only generated-triage CRLF normalization warnings. The live runner command
`pwsh -File scripts\interop\Invoke-QuicInteropRunner.ps1 -RepoRoot .
-TestCases resumption` produced runner report
`artifacts\interop-runner\20260508-231043525-both-quic-go\runner-report.json`
with `resumption` classified `unsupported` because SSLKEYLOG output is
required.

## 2026-05-08 CRT Server NewSessionTicket Issuance Closure Note

`REQ-QUIC-CRT-0150` now owns the first managed server-side resumption ticket
issuance slice. When the internal server issuance switch is explicitly enabled,
the managed TLS key schedule emits a bounded TLS 1.3 `NewSessionTicket` only
after peer `Finished` verification and 1-RTT packet-protection availability.
The ticket is published over the QUIC 1-RTT CRYPTO seam and can be flushed as a
protected application-data packet when an active path exists. The default server
path remains ticket-free.

This did not by itself make the `resumption` interop cell green. The follow-on
server-side acceptance source gap is now owned and closed by `REQ-QUIC-CRT-0151`.
The emitted ticket carries no `early_data` extension and does not claim 0-RTT
acceptance, anti-replay, public API widening, HTTP/3, or broader interop
readiness.

Local focused verification passed:
`dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release
-m:1 --filter "FullyQualifiedName~REQ_QUIC_CRT_0150"` reported 4/4 passing.
SpecTrace validation and regenerated triage are recorded in the slice
verification artifact.

## 2026-05-08 INT Inventory Boundary And Resumption Blocker Note

`REQ-QUIC-INT-0018` remains the owning inventory/profile requirement for the
non-HTTP/3 interop testcase list. The current helper inventory keeps
`versionnegotiation`, `keyupdate`, and `resumption` in the supported/executed
class, keeps `http3` out of scope, and classifies `chacha20`, `zerortt`, `v2`,
`rebind-port`, `rebind-addr`, and `connectionmigration` as prerequisite-blocked.

`chacha20` is not green on this runner: it remains blocked on end-to-end runner
platform support for the required cipher-suite selection. The source-level
server resumption prerequisites named here are now closed under
`REQ-QUIC-CRT-0151`, and a later 2026-05-08 runner attempt made the external
`resumption` cell green with SSLKEYLOGFILE-backed proof. The next source-level
unresolved runtime cell after this slice is `zerortt`, which requires
server-side 0-RTT admission and anti-replay ownership.

Current regenerated RFC requirement triage still reports 1,498 of 1,771
requirements `trace_clean`, leaving 273 non-clean: 55 metadata-only
missing-xref items, 42 partially covered items, 54 blocked items, and 122
uncovered-unblocked items.

Local verification for this inventory/blocker refresh passed: focused
`REQ_QUIC_CRT_0150|InteropRunnerScriptDryRunTests|REQ_QUIC_INT_0013` filter
40/40, captured-HRR/key-update regression filter 16/16, regenerated QUIC
requirement coverage triage, SpecTrace core validation 523 artifacts,
`dotnet build Incursa.Quic.slnx -c Release` with 0 warnings and 0 errors,
full `dotnet test Incursa.Quic.slnx -c Release --no-build -m:1` with
4,872/4,872 passing, and `git diff --check` with only generated-triage CRLF
normalization warnings.

## 2026-05-08 S5 Preferred-Address Migration Topoff Closure Note

`REQ-QUIC-RFC9000-S5P2P3-0002` is now `trace_clean` under the baseline RFC
9000 artifact family `ARC-QUIC-RFC9000-0001`, `WI-QUIC-RFC9000-0001`, and
`VER-QUIC-RFC9000-0001`. The closure adds direct focused positive proof that a
server-prepared preferred-address value round-trips through client parsing with
the dedicated address, ports, connection ID, and stateless reset token intact.
Regenerated coverage triage marks the requirement `trace_clean` and reports
1,495 of 1,771 QUIC requirements trace-clean overall. This remains bounded to
preferred-address codec/proof coverage and does not claim runtime migration
policy, public migration APIs, multipath, or interop-runner success.

Local verification for this closure passed: focused S5P2P3-0002 requirement-
home filter 1/1, SpecTrace core validation 520 artifacts, Release build 0
warnings/errors, and `git diff --check` with only generated-triage CRLF
normalization warnings. The full Release no-build suite still reports 9
failing tests in existing interop preflight/helper coverage, so the branch is
not yet fully green.

## 2026-05-08 S5 Disable-Active-Migration Topoff Closure Note

`REQ-QUIC-RFC9000-S5P2P3-0004` is now `trace_clean` under the baseline RFC
9000 artifact family `ARC-QUIC-RFC9000-0001`, `WI-QUIC-RFC9000-0001`, and
`VER-QUIC-RFC9000-0001`. The closure adds direct focused positive proof that a
server with `disable_active_migration` set encodes the empty transport
parameter and that a client parses it back as migration-disabled.

Current generated RFC requirement triage reports 1,494 of 1,771 requirements
`trace_clean`, leaving 277 non-clean: 55 metadata-only missing-xref items, 1
proof-too-broad item, 45 partially covered items, 54 blocked items, and 122
uncovered-unblocked items. RFC 8999, RFC 9001, and RFC 9002 are fully
trace-clean; remaining non-clean requirements are all in RFC 9000.

Local verification for this closure passed: focused S5P2P3-0004 requirement-home
filter 1/1, SpecTrace core validation 517 artifacts, Release build 0
warnings/errors, full Release no-build suite 4,856/4,856, regenerated QUIC
requirement coverage triage, and `git diff --check` with only
generated-triage CRLF normalization warnings.

## 2026-05-08 S6 Reserved-Version Ignore Topoff Closure Note

`REQ-QUIC-RFC9000-S6P3-0001` is now `trace_clean` under the baseline RFC 9000
artifact family `ARC-QUIC-RFC9000-0001`, `WI-QUIC-RFC9000-0001`, and
`VER-QUIC-RFC9000-0001`. The closure adds direct focused negative proof that
client-side Version Negotiation processing ignores a reserved-version
advertisement instead of treating it as the selected version, while preserving
the existing focused positive proof for the reserved-version pattern.

Current generated RFC requirement triage reports 1,493 of 1,771 requirements
`trace_clean`, leaving 278 non-clean: 55 metadata-only missing-xref items, 2
proof-too-broad items, 45 partially covered items, 54 blocked items, and 122
uncovered-unblocked items. RFC 8999, RFC 9001, and RFC 9002 are fully
trace-clean; remaining non-clean requirements are all in RFC 9000.

Local verification for this closure passed: focused S6P3-0001 requirement-home
filter 2/2, SpecTrace core validation 517 artifacts, Release build 0
warnings/errors, full Release no-build suite 4,855/4,855, regenerated QUIC
requirement coverage triage, and `git diff --check` with only
generated-triage CRLF normalization warnings.

## 2026-05-08 S2 Concurrent-Streams Topoff Closure Note

`REQ-QUIC-RFC9000-S2-0008` is now `trace_clean` under the baseline RFC 9000
artifact family `ARC-QUIC-RFC9000-0001`, `WI-QUIC-RFC9000-0001`, and
`VER-QUIC-RFC9000-0001`. The closure adds direct focused positive proof that
the stream-state helper can keep multiple local bidirectional and
unidirectional streams open together and can keep multiple peer bidirectional
and unidirectional receive streams open together under configured stream
limits.

Current generated RFC requirement triage reports 1,492 of 1,771 requirements
`trace_clean`, leaving 279 non-clean: 55 metadata-only missing-xref items, 2
proof-too-broad items, 46 partially covered items, 54 blocked items, and 122
uncovered-unblocked items. RFC 8999, RFC 9001, and RFC 9002 are fully
trace-clean; remaining non-clean requirements are all in RFC 9000.

Local verification for this closure passed: focused S2-0008 requirement-home
filter 2/2, SpecTrace core validation 517 artifacts, Release build 0
warnings/errors, full Release no-build suite 4,854/4,854, regenerated QUIC
requirement coverage triage, and `git diff --check`.

## 2026-05-08 S2 Stream-Cancellation Topoff Closure Note

`REQ-QUIC-RFC9000-S2-0006` is now `trace_clean` under the baseline RFC 9000
artifact family `ARC-QUIC-RFC9000-0001`, `WI-QUIC-RFC9000-0001`, and
`VER-QUIC-RFC9000-0001`. The closure adds direct focused positive proof that
the stream-cancellation frame paths round-trip both `RESET_STREAM` and
`STOP_SENDING`.

Current generated RFC requirement triage reports 1,491 of 1,771 requirements
`trace_clean`, leaving 280 non-clean: 55 metadata-only missing-xref items, 3
proof-too-broad items, 46 partially covered items, 54 blocked items, and 122
uncovered-unblocked items. RFC 8999, RFC 9001, and RFC 9002 are fully
trace-clean; remaining non-clean requirements are all in RFC 9000.

Local verification for this closure passed: focused S2-0006 requirement-home
filter 1/1, SpecTrace core validation 517 artifacts, Release build 0
warnings/errors, full Release no-build suite 4,852/4,852, regenerated QUIC
requirement coverage triage, and `git diff --check` with only generated-triage
CRLF normalization warnings.

## 2026-05-08 S13 ECN Continuation-After-Success Topoff Closure Note

`REQ-QUIC-RFC9000-S13P4P2P2-0004` is now `trace_clean` under the existing
ECN validation artifact family `ARC-QUIC-RFC9000-0011`,
`WI-QUIC-RFC9000-0011`, and `VER-QUIC-RFC9000-0011`, alongside the baseline
ownership. The closure adds direct focused positive proof that successful
validation keeps the helper ECN-enabled and accepts a subsequent ECT-marked
packet acknowledgment on the same path.

Current generated RFC requirement triage reports 1,490 of 1,771 requirements
`trace_clean`, leaving 281 non-clean: 55 metadata-only missing-xref items, 4
proof-too-broad items, 46 partially covered items, 54 blocked items, and 122
uncovered-unblocked items. RFC 8999, RFC 9001, and RFC 9002 are fully
trace-clean; remaining non-clean requirements are all in RFC 9000.

Local verification for this closure passed: focused S13P4P2P2-0004
requirement-home filter 1/1, SpecTrace core validation 517 artifacts, Release
build 0 warnings/errors, full Release no-build suite 4,851/4,851, regenerated
QUIC requirement coverage triage, and `git diff --check` with only
generated-triage CRLF normalization warnings.

## 2026-05-08 S13 ECN Disable-On-Failure Topoff Closure Note

`REQ-QUIC-RFC9000-S13P4P2P2-0001` is now `trace_clean` under the existing
ECN validation artifact family `ARC-QUIC-RFC9000-0011`,
`WI-QUIC-RFC9000-0011`, and `VER-QUIC-RFC9000-0011`, alongside the baseline
ownership. The closure adds direct focused positive proof that a validation
failure disables ECN on the helper state, complementing the existing focused
negative evidence across missing, zeroed, too-small, exceed-sent,
never-applied, and later-failure validation paths.

Current generated RFC requirement triage reports 1,489 of 1,771 requirements
`trace_clean`, leaving 282 non-clean: 55 metadata-only missing-xref items, 5
proof-too-broad items, 46 partially covered items, 54 blocked items, and 122
uncovered-unblocked items. RFC 8999, RFC 9001, and RFC 9002 are fully
trace-clean; remaining non-clean requirements are all in RFC 9000.

Local verification for this closure passed: focused S13P4P2P2-0001
requirement-home filter 2/2, SpecTrace core validation 517 artifacts, Release
build 0 warnings/errors, full Release no-build suite 4,850/4,850, regenerated
QUIC requirement coverage triage, and `git diff --check` with only
generated-triage CRLF normalization warnings.

## 2026-05-08 S13 ECT(1)+CE Too-Small Validation Topoff Closure Note

`REQ-QUIC-RFC9000-S13P4P2P1-0005` is now `trace_clean` under the existing
ECN validation artifact family `ARC-QUIC-RFC9000-0011`,
`WI-QUIC-RFC9000-0011`, and `VER-QUIC-RFC9000-0011`, alongside the baseline
ownership. The closure adds direct focused positive proof that an ECT(1)
reported-count increase covering the newly acknowledged ECT(1) packets is
accepted, complementing the existing negative too-small proof and CE-substitute
edge proof.

Current generated RFC requirement triage reports 1,488 of 1,771 requirements
`trace_clean`, leaving 283 non-clean: 55 metadata-only missing-xref items, 5
proof-too-broad items, 47 partially covered items, 54 blocked items, and 122
uncovered-unblocked items. RFC 8999, RFC 9001, and RFC 9002 are fully
trace-clean; remaining non-clean requirements are all in RFC 9000.

Local verification for this closure passed: focused S13P4P2P1-0005
requirement-home filter 3/3, SpecTrace core validation 517 artifacts, Release
build 0 warnings/errors, full Release no-build suite 4,849/4,849, regenerated
QUIC requirement coverage triage, and `git diff --check` with only
generated-triage CRLF normalization warnings.

## 2026-05-08 S13 ECT(0)+CE Too-Small Validation Topoff Closure Note

`REQ-QUIC-RFC9000-S13P4P2P1-0004` is now `trace_clean` under the existing
ECN validation artifact family `ARC-QUIC-RFC9000-0011`,
`WI-QUIC-RFC9000-0011`, and `VER-QUIC-RFC9000-0011`, alongside the baseline
ownership. The closure adds direct focused positive proof that an ECT(0)
reported-count increase covering the newly acknowledged ECT(0) packets is
accepted, complementing the existing negative too-small proof and CE-substitute
edge proof.

Current generated RFC requirement triage reports 1,487 of 1,771 requirements
`trace_clean`, leaving 284 non-clean: 55 metadata-only missing-xref items, 5
proof-too-broad items, 48 partially covered items, 54 blocked items, and 122
uncovered-unblocked items. RFC 8999, RFC 9001, and RFC 9002 are fully
trace-clean; remaining non-clean requirements are all in RFC 9000.

Local verification for this closure passed: focused S13P4P2P1-0004
requirement-home filter 3/3, SpecTrace core validation 517 artifacts, Release
build 0 warnings/errors, full Release no-build suite 4,848/4,848, regenerated
QUIC requirement coverage triage, and `git diff --check` with only
generated-triage CRLF normalization warnings.

## 2026-05-08 S13 ECN Validation-Before-Use Topoff Closure Note

`REQ-QUIC-RFC9000-S13P4P2P1-0001` is now `trace_clean` under the existing
ECN validation artifact family `ARC-QUIC-RFC9000-0011`,
`WI-QUIC-RFC9000-0011`, and `VER-QUIC-RFC9000-0011`, alongside the baseline
ownership. The closure adds direct focused positive, negative, and edge proof
that valid ACK ECN counts are accepted before state use, impossible reported
counts are rejected before state use, and stale ACK counts are ignored when the
largest acknowledged packet number does not advance.

Current generated RFC requirement triage reports 1,486 of 1,771 requirements
`trace_clean`, leaving 285 non-clean: 55 metadata-only missing-xref items, 5
proof-too-broad items, 49 partially covered items, 54 blocked items, and 122
uncovered-unblocked items. RFC 8999, RFC 9001, and RFC 9002 are fully
trace-clean; remaining non-clean requirements are all in RFC 9000.

Local verification for this closure passed: focused S13P4P2P1-0001
requirement-home filter 5/5, SpecTrace core validation 517 artifacts, Release
build 0 warnings/errors, full Release no-build suite 4,847/4,847, regenerated
QUIC requirement coverage triage, and `git diff --check` with only
generated-triage CRLF normalization warnings.

## 2026-05-08 S13 ECT(1) Validation Count Topoff Closure Note

`REQ-QUIC-RFC9000-S13P4P2-0006` is now `trace_clean` under the existing
ECN validation artifact family `ARC-QUIC-RFC9000-0011`,
`WI-QUIC-RFC9000-0011`, and `VER-QUIC-RFC9000-0011`, alongside the baseline
ownership. The closure adds direct focused proof that ECT(1)-marked packets
validate against reported ECT(1) counts and that reported ECT(0) increases do
not satisfy newly acknowledged ECT(1) packets.

Current generated RFC requirement triage reports 1,485 of 1,771 requirements
`trace_clean`, leaving 286 non-clean: 55 metadata-only missing-xref items, 5
proof-too-broad items, 50 partially covered items, 54 blocked items, and 122
uncovered-unblocked items. RFC 8999, RFC 9001, and RFC 9002 are fully
trace-clean; remaining non-clean requirements are all in RFC 9000.

Local verification for this closure passed: focused S13P4P2-0006
requirement-home filter 1/1, SpecTrace core validation 517 artifacts, Release
build 0 warnings/errors, full Release no-build suite 4,844/4,844, regenerated
QUIC requirement coverage triage, and `git diff --check` with only
generated-triage CRLF normalization warnings.

## 2026-05-08 S13 ECN Packet-Number-Space Separation Closure Note

`REQ-QUIC-RFC9000-S13P4P1-0006` is now `trace_clean` under
`ARC-QUIC-RFC9000-0091`, `WI-QUIC-RFC9000-0091`, and
`VER-QUIC-RFC9000-0091`, alongside the existing baseline ownership. The
closure adds direct positive, negative, and edge proof that ACK-generation
state keeps ECN counts separate by packet number space, does not borrow
ECN-marked acknowledgment state into an empty space, and keeps identical
numeric packet numbers independent across Initial, Handshake, and Application
Data spaces.

Current generated RFC requirement triage reports 1,484 of 1,771 requirements
`trace_clean`, leaving 287 non-clean: 55 metadata-only missing-xref items, 6
proof-too-broad items, 50 partially covered items, 54 blocked items, and 122
uncovered-unblocked items. RFC 8999, RFC 9001, and RFC 9002 are fully
trace-clean; remaining non-clean requirements are all in RFC 9000.

Local verification for this closure passed: focused S13P4P1-0006
requirement-home filter 3/3, SpecTrace core validation 517 artifacts, Release
build 0 warnings/errors, full Release no-build suite 4,843/4,843, regenerated
QUIC requirement coverage triage, and `git diff --check` with only
generated-triage CRLF normalization warnings.

## 2026-05-08 S13 ACK Frame Largest-Packet Delay Boundary Closure Note

`REQ-QUIC-RFC9000-S13P3-0010` is now `trace_clean` under
`ARC-QUIC-RFC9000-0090`, `WI-QUIC-RFC9000-0090`, and
`VER-QUIC-RFC9000-0090`, alongside the existing baseline ownership. The
closure adds direct edge proof that ACK frame construction carries the current
acknowledgment set and computes ACK Delay from the largest acknowledged packet
even when a smaller packet arrives later.

Current generated RFC requirement triage reports 1,483 of 1,771 requirements
`trace_clean`, leaving 288 non-clean: 55 metadata-only missing-xref items, 6
proof-too-broad items, 51 partially covered items, 54 blocked items, and 122
uncovered-unblocked items. RFC 8999, RFC 9001, and RFC 9002 are fully
trace-clean; remaining non-clean requirements are all in RFC 9000.

Local verification for this closure passed: focused S13P3-0010
requirement-home filter 4/4, SpecTrace core validation 514 artifacts, Release
build 0 warnings/errors, full Release no-build suite 4,841/4,841, regenerated
QUIC requirement coverage triage, and `git diff --check` with only
generated-triage CRLF normalization warnings.

## 2026-05-08 S13 CRYPTO Retransmission Acknowledgment Boundary Closure Note

`REQ-QUIC-RFC9000-S13P3-0006` is now `trace_clean` under
`ARC-QUIC-RFC9000-0089`, `WI-QUIC-RFC9000-0089`, and
`VER-QUIC-RFC9000-0089`, alongside the existing runtime and ACK-piggyback
ownership. The closure adds direct positive, negative, and edge proof that a
lost Handshake CRYPTO packet is rebuilt in a fresh packet, a queued repair is
cleared when the original packet is acknowledged before retransmission flush,
and a later contiguous Handshake CRYPTO frame preserves its nonzero CRYPTO
stream offset and bytes when retransmitted.

Current generated RFC requirement triage reports 1,482 of 1,771 requirements
`trace_clean`, leaving 289 non-clean: 55 metadata-only missing-xref items, 6
proof-too-broad items, 52 partially covered items, 54 blocked items, and 122
uncovered-unblocked items. RFC 8999, RFC 9001, and RFC 9002 are fully
trace-clean; remaining non-clean requirements are all in RFC 9000.

Local verification for this closure passed: focused S13P3-0006
requirement-home filter 3/3, SpecTrace core validation 511 artifacts, Release
build 0 warnings/errors, full Release no-build suite 4,840/4,840, regenerated
QUIC requirement coverage triage, and `git diff --check` with only
generated-triage CRLF normalization warnings.

## 2026-05-08 S13 Packet-Number-Space ACK Separation Closure Note

`REQ-QUIC-RFC9000-S13P2P6-0001` is now `trace_clean` under the existing
`ARC-QUIC-RFC9000-0001`, `WI-QUIC-RFC9000-0001`, and
`VER-QUIC-RFC9000-0001` ownership. The closure adds direct positive,
negative, and edge proof that ACK-generation state builds ACK frames from only
the requested packet number space, does not borrow receipts from another
packet number space, and keeps the same numeric packet number distinct across
Initial and Application Data spaces.

Current generated RFC requirement triage reports 1,481 of 1,771 requirements
`trace_clean`, leaving 290 non-clean: 55 metadata-only missing-xref items, 6
restructure-needed proof items, 53 partially covered items, 54 blocked items,
and 122 uncovered-unblocked items. RFC 8999, RFC 9001, and RFC 9002 are fully
trace-clean; remaining non-clean requirements are all in RFC 9000.

Local verification for this closure passed: focused S13P2P6 requirement-home
filter 3/3, `QuicAckPiggybackPolicyBenchmarks` Dry run 5/5, SpecTrace core
validation 508 artifacts, Release build 0 warnings/errors, full Release
no-build suite 4,838/4,838, regenerated QUIC requirement coverage triage, and
`git diff --check` with only generated-triage CRLF normalization warnings.

## 2026-05-08 S13 Multiple-Packet ACK-Decision Closure Note

`REQ-QUIC-RFC9000-S13P2P2-0003` is now `trace_clean` under the existing
`ARC-QUIC-RFC9000-0001`, `WI-QUIC-RFC9000-0001`,
`VER-QUIC-RFC9000-0001`, `ARC-QUIC-RFC9000-0024`,
`WI-QUIC-RFC9000-0024`, and `VER-QUIC-RFC9000-0024` ownership. The closure
adds direct negative proof that multiple processed non-ack-eliciting packets do
not force an ACK decision, plus edge proof that a later gapped ack-eliciting
packet can trigger the decision while the ACK frame preserves the earlier
processed packet range.

Current generated RFC requirement triage reports 1,480 of 1,771 requirements
`trace_clean`, leaving 291 non-clean: 55 metadata-only missing-xref items, 6
restructure-needed proof items, 54 partially covered items, 54 blocked items,
and 122 uncovered-unblocked items. RFC 8999, RFC 9001, and RFC 9002 are fully
trace-clean; remaining non-clean requirements are all in RFC 9000.

Local verification for this closure passed: focused S13P2P2 requirement-home
filter 3/3, `QuicAckPiggybackPolicyBenchmarks` Dry run 5/5, SpecTrace core
validation 508 artifacts, Release build 0 warnings/errors, full Release
no-build suite 4,835/4,835, regenerated QUIC requirement coverage triage, and
`git diff --check` with only generated-triage CRLF normalization warnings.

## 2026-05-08 S13 Max-Ack-Delay And Non-Ack Inclusion Closure Note

`REQ-QUIC-RFC9000-S13P2-0002` and `REQ-QUIC-RFC9000-S13P2-0003` are now
`trace_clean` under the existing `ARC-QUIC-RFC9000-0017`,
`WI-QUIC-RFC9000-0017`, `VER-QUIC-RFC9000-0017`,
`ARC-QUIC-RFC9000-0024`, `WI-QUIC-RFC9000-0024`, and
`VER-QUIC-RFC9000-0024` ownership. The closure proves that an ack-eliciting
Application Data packet schedules a delayed ACK at the advertised
`max_ack_delay`, emits an ACK-only response when that timer expires, and that
non-ack-eliciting packet numbers are included in ACK ranges only after an
ack-eliciting packet creates an ACK reason.

Current generated RFC requirement triage reports 1,479 of 1,771 requirements
`trace_clean`, leaving 292 non-clean: 55 metadata-only missing-xref items, 6
restructure-needed proof items, 55 partially covered items, 54 blocked items,
and 122 uncovered-unblocked items. RFC 8999, RFC 9001, and RFC 9002 are fully
trace-clean; remaining non-clean requirements are all in RFC 9000.

Local verification for this closure passed: focused S13P2/S13P2P1
requirement-home filter 7/7, `QuicAckPiggybackPolicyBenchmarks` Dry run 5/5,
SpecTrace core validation 508 artifacts, Release build 0 warnings/errors, full
Release no-build suite 4,833/4,833, regenerated QUIC requirement coverage
triage, and `git diff --check` with only generated-triage CRLF normalization
warnings.

## 2026-05-08 S13 ACK-Only Feedback-Loop Edge Closure Note

`REQ-QUIC-RFC9000-S13P2P1-0009` is now `trace_clean` under the existing
`ARC-QUIC-RFC9000-0018`, `WI-QUIC-RFC9000-0018`, and
`VER-QUIC-RFC9000-0018` ownership. The edge-proof topoff shows that a local
ACK-only packet remains non-ack-eliciting and non-retransmittable, and that a
peer ACK-only packet acknowledging that local ACK-only packet does not trigger
another ACK-only response, does not re-arm the ACK-delay timer, and does not
reopen piggyback eligibility for the same ack-eliciting receipt.

Current generated RFC requirement triage reports 1,477 of 1,771 requirements
`trace_clean`, leaving 294 non-clean: 55 metadata-only missing-xref items, 6
restructure-needed proof items, 57 partially covered items, 54 blocked items,
and 122 uncovered-unblocked items. RFC 8999, RFC 9001, and RFC 9002 are fully
trace-clean; remaining non-clean requirements are all in RFC 9000.

Local verification for this closure passed: focused S13P2P1 requirement-home
filter 30/30, `QuicAckPiggybackPolicyBenchmarks` Dry run 5/5, SpecTrace core
validation 508 artifacts, Release build 0 warnings/errors, full Release
no-build suite 4,831/4,831, regenerated QUIC requirement coverage triage, and
`git diff --check` with only generated-triage CRLF normalization warnings.

## 2026-05-08 S13 Periodic ACK-Probe Closure Note

`REQ-QUIC-RFC9000-S13P2P7-0001` and `REQ-QUIC-RFC9000-S13-0002` are now
`trace_clean` under `ARC-QUIC-RFC9000-0088`, `WI-QUIC-RFC9000-0088`, and
`VER-QUIC-RFC9000-0088`. The closure proves that an active 1-RTT path can send
a non-retransmittable, ack-eliciting PING probe when no retransmittable payload
is available, does not emit a padding-only probe before an active path and 1-RTT
keys exist, and does not delay application data at the small-packet threshold.
`REQ-QUIC-RFC9000-S13P2P1-0009` remains the adjacent explicit edge-proof gap for
ACK-only feedback-loop behavior.

Current generated RFC requirement triage reports 1,476 of 1,771 requirements
`trace_clean`, leaving 295 non-clean: 55 metadata-only missing-xref items, 6
restructure-needed proof items, 58 partially covered items, 54 blocked items,
and 122 uncovered-unblocked items. RFC 8999, RFC 9001, and RFC 9002 are fully
trace-clean; remaining non-clean requirements are all in RFC 9000.

Local verification for this closure passed: focused S13 requirement-home filter
9/9, `QuicAckPiggybackPolicyBenchmarks` Dry and Short runs 5/5 each, SpecTrace
core validation 508 artifacts, Release build 0 warnings/errors, full Release
no-build suite 4,830/4,830, regenerated QUIC requirement coverage triage, and
`git diff --check` with only generated-triage CRLF normalization warnings.

## 2026-05-08 RFC9001 Tail Proof Closure Note

RFC9001 is now fully trace-clean in the generated requirement coverage triage:
96 of 96 requirements are `trace_clean`. The closure added focused
requirement-home proof and canonical `trace.x_test_refs` for the remaining
S3/S4/S7/S9 tail, including behavioral proof for `REQ-QUIC-RFC9001-S3-0011`
and `REQ-QUIC-RFC9001-S4-0008` through `REQ-QUIC-RFC9001-S4-0010`, plus
canonical-ownership proof for policy/document-scope clauses such as
`REQ-QUIC-RFC9001-S7-0001` and `REQ-QUIC-RFC9001-S9-0001`.

Current generated RFC requirement triage reports 1,474 of 1,771 requirements
`trace_clean`, leaving 297 non-clean: 55 metadata-only missing-xref items, 13
restructure-needed proof items, 59 partially covered items, 54 blocked items,
and 123 uncovered-unblocked items. RFC 8999, RFC 9001, and RFC 9002 are fully
trace-clean; remaining non-clean requirements are all in RFC 9000.

Local verification for this closure passed: Release build 0 warnings/errors,
focused RFC9001 S3/S4/S7/S9 tail requirement-home filter 15/15, SpecTrace core
validation 505 artifacts, full Release no-build suite 4,827/4,827, and
regenerated QUIC requirement coverage triage. This closure does not claim broad
endpoint handshake completeness, public early-data support, general repeated
key-update support, or expanded interop readiness beyond separately traced
hosted supported-subset evidence.

## 2026-05-08 Metadata Xref Burn-down Note

Follow-on S13/S17 metadata cleanup moved fourteen already-proved requirements
from `covered_but_missing_xrefs` to `trace_clean` by attaching focused
requirement-home evidence under `trace.x_test_refs`:
`REQ-QUIC-RFC9000-S13P2-0001`, `REQ-QUIC-RFC9000-S13P2P3-0003`,
`REQ-QUIC-RFC9000-S13P2P3-0004`, `REQ-QUIC-RFC9000-S13P2P3-0007`,
`REQ-QUIC-RFC9000-S13P2P3-0008`, `REQ-QUIC-RFC9000-S13P2P3-0013`,
`REQ-QUIC-RFC9000-S17P2P4-0003`, `REQ-QUIC-RFC9000-S17P2P4-0016`,
`REQ-QUIC-RFC9000-S17P2P4-0017`, `REQ-QUIC-RFC9000-S17P2P4-0018`,
`REQ-QUIC-RFC9000-S17P2P4-0019`, `REQ-QUIC-RFC9000-S17P2P4-0020`,
`REQ-QUIC-RFC9000-S17P2P4-0021`, and `REQ-QUIC-RFC9000-S17P2P5-0002`.
The S17P2P4 requirements also gained reciprocal ownership under
`ARC-QUIC-RFC9000-0087`, `WI-QUIC-RFC9000-0087`, and
`VER-QUIC-RFC9000-0087`.

Current generated RFC requirement triage reports 1,459 of 1,771 requirements
`trace_clean`, leaving 312 non-clean: 55 metadata-only missing-xref items, 13
restructure-needed proof items, 59 partially covered items, 69 blocked items,
and 123 uncovered-unblocked items. RFC 8999 and RFC 9002 remain fully
trace-clean; RFC 9000 is 1,146 of 1,443 trace-clean, and RFC 9001 is 81 of 96
trace-clean.

Follow-on metadata cleanup moved nine already-proved requirements from
`covered_but_missing_xrefs` to `trace_clean` by attaching focused
requirement-home evidence under `trace.x_test_refs`: `REQ-QUIC-RFC9000-S10P2P1-0004`,
`REQ-QUIC-RFC9000-S11-0003`, `REQ-QUIC-RFC9000-S11-0004`,
`REQ-QUIC-RFC9000-S11P1-0003`, `REQ-QUIC-RFC9000-S12P1-0006`,
`REQ-QUIC-RFC9000-S12P1-0007`, `REQ-QUIC-RFC9000-S12P2-0008`,
`REQ-QUIC-RFC9000-S12P3-0009`, and `REQ-QUIC-RFC9000-S12P3-0010`.
Adjacent stale refs for `REQ-QUIC-RFC9000-S11-0001`,
`REQ-QUIC-RFC9000-S11P1-0001`, and `REQ-QUIC-RFC9000-S11P1-0002` were
corrected to their direct requirement homes without changing their clean
state.

The immediate post-batch generated RFC requirement triage reported 1,445 of
1,771 requirements `trace_clean`, leaving 326 non-clean. Later same-day
metadata cleanup supersedes this count.

## 2026-05-08 Trace Repair Note

A malformed RFC 9000 requirement trace entry for
`REQ-QUIC-RFC9000-S13P2P3-0013` was repaired by closing its
`trace.upstream_refs` array. The canonical QUIC requirement JSON files now
parse cleanly, `pwsh -NoProfile -File scripts\Validate-SpecTraceJson.ps1
-Profiles core` validates 505 SpecTrace JSON artifacts, and
`scripts\spec-trace\Generate-QuicRequirementCoverageTriage.ps1 -RepoRoot .`
regenerates the coverage triage.

The immediate post-repair generated RFC requirement triage reported 1,436 of
1,771 requirements `trace_clean`, leaving 335 non-clean. Treat that and older
per-slice count snapshots below as historical closure evidence, not the current
global count.

## 2026-05-06 Restart Note

Follow-on S19P20 HANDSHAKE_DONE proof-tail closure on 2026-05-06 closes
`REQ-QUIC-RFC9000-S19P20-0003`, `REQ-QUIC-RFC9000-S19P20-0004`,
`REQ-QUIC-RFC9000-S19P20-0005`, and `REQ-QUIC-RFC9000-S19P20-0006`
under `ARC-QUIC-RFC9000-0086`, `WI-QUIC-RFC9000-0086`, and
`VER-QUIC-RFC9000-0086`. The proof covers HANDSHAKE_DONE single-byte
varint type encoding as `0x1e`, adjacent and non-minimal type rejection,
one-byte consumption before a following frame, active-client send
suppression, server send only after peer handshake transcript completion,
pre-completion suppression with 1-RTT send material present, one-shot server
send behavior, server receipt closure with `PROTOCOL_VIOLATION`, and a
protected non-HANDSHAKE_DONE receive negative control. Regenerated coverage
triage marks all four requirements as `trace_clean` and reports 1,330 of
1,771 QUIC requirements trace-clean overall, leaving 441 non-clean.
`S19P20` has no remaining non-clean requirements in generated triage. Local
verification passed: focused S19P20 requirement-home filter 13/13, Release
build 0 warnings/errors, SpecTrace core validation 502 artifacts, full
Release no-build suite 4,609/4,609, and `git diff --check` exited 0 with
only generated-triage CRLF normalization warnings. This closure does not
claim broad S19 frame-family closure, public API widening, hosted interop
readiness, or closure of unrelated deferred fuzz obligations.

Follow-on S8P1P4 Retry token source binding and lifetime closure on
2026-05-06 closes `REQ-QUIC-RFC9000-S8P1P4-0003`,
`REQ-QUIC-RFC9000-S8P1P4-0007`, and
`REQ-QUIC-RFC9000-S8P1P4-0011` under `ARC-QUIC-RFC9000-0085`,
`WI-QUIC-RFC9000-0085`, and `VER-QUIC-RFC9000-0085`. The proof
covers listener Retry replay admission from the issuing source address and
port, rejection of the same Retry token from a fresh UDP source port before
admission, deterministic source-port mutation fuzzing for port-bound tokens,
short-lifetime token acceptance through the expiration boundary and rejection
after it, and unchanged three-times anti-amplification budget enforcement for
an unvalidated changed address. Regenerated coverage triage marks all three
requirements as `trace_clean` and reports 1,326 of 1,771 QUIC requirements
trace-clean overall, leaving 445 non-clean. `S8P1P4` is now down to one
remaining non-clean requirement: `REQ-QUIC-RFC9000-S8P1P4-0005`, a
metadata-only xref cleanup duplicate of the anti-amplification changed-address
clause. Local verification passed: focused S8P1P4 requirement-home filter 7/7,
Release build 0 warnings/errors, SpecTrace core validation 499 artifacts, full
Release no-build suite 4,598/4,598, and `git diff --check` exited 0 with only
generated-triage CRLF normalization warnings. This closure does not claim
cluster-wide Retry token state, persistent token secrets across listener
restarts, public token-management APIs, hosted interop readiness, or closure of
unrelated deferred fuzz obligations.

Follow-on S17P1 packet-number encoding completion on 2026-05-06 closes
`REQ-QUIC-RFC9000-S17P1-0002`, `REQ-QUIC-RFC9000-S17P1-0003`,
and `REQ-QUIC-RFC9000-S17P1-0004` under
`ARC-QUIC-RFC9000-0084`, `WI-QUIC-RFC9000-0084`, and
`VER-QUIC-RFC9000-0084`. The proof covers protected packet behavior for
full four-byte Initial and Handshake packet numbers before acknowledgment,
the maximum four-byte Initial packet-number boundary without truncation, the
largest post-ack Application Data packet-number difference that remains safe
with a four-byte field, rejecting a late packet that is missing a
packet-number byte, and recovering out-of-order Application Data packets at
the four-byte boundary. Regenerated coverage triage marks all three
requirements as `trace_clean` and reports 1,323 of 1,771 QUIC requirements
trace-clean overall, leaving 448 non-clean. `S17P1` has no remaining
non-clean requirements in generated triage. This closure does not claim
adaptive packet-number length selection, full packet-number reconstruction for
arbitrary reordered receive windows, hosted interop readiness, or closure of
deferred fuzz obligations.

Follow-on S17P4 spin-bit per-path state closure on 2026-05-06 closes
`REQ-QUIC-RFC9000-S17P4-0008`, `REQ-QUIC-RFC9000-S17P4-0009`,
and `REQ-QUIC-RFC9000-S17P4-0010` under `ARC-QUIC-RFC9000-0083`,
`WI-QUIC-RFC9000-0083`, and `VER-QUIC-RFC9000-0083`. The proof covers
protected 1-RTT runtime/wire behavior for emitting the stored path spin
value, server receive-side storage of the received spin bit when the packet
number advances, and client receive-side storage of the inverse spin bit when
the packet number advances. `REQ-QUIC-RFC9000-S17P4-0005` also gained the
missing zero-length connection-ID randomized-disablement edge proof.
Regenerated coverage triage marks all four requirements as `trace_clean` and
reports 1,320 of 1,771 QUIC requirements trace-clean overall, leaving 451
non-clean. `S17P4` has no remaining non-clean requirements in generated
triage. This closure does not claim public spin-bit administration API
widening, observer RTT estimation completeness, hosted interop readiness, or
closure of deferred fuzz obligations.

Follow-on S9P6P1 preferred-address conveyance and per-family selection closure
on 2026-05-06 closes `REQ-QUIC-RFC9000-S9P6P1-0001`,
`REQ-QUIC-RFC9000-S9P6P1-0006`, and
`REQ-QUIC-RFC9000-S9P6P1-0007` under `ARC-QUIC-RFC9000-0082`,
`WI-QUIC-RFC9000-0082`, and `VER-QUIC-RFC9000-0082`. The proof covers
server `preferred_address` conveyance through the TLS `EncryptedExtensions`
transport-parameters extension, both IPv4 and IPv6 preferred-address families
surviving server encoding and client parsing, and the client selecting the
preferred address family matching the original server path family. Regenerated
coverage triage marks the requirements as `trace_clean` and reports 1,316 of
1,771 QUIC requirements trace-clean overall, leaving 455 non-clean. `S9P6P1`
has no remaining non-clean requirements in generated triage. This closure does
not claim public preferred-address configuration APIs, public migration APIs,
multipath support, hosted interop readiness, or closure of deferred fuzz
obligations.

Follow-on S9P6P1 preferred-address validation-failure policy closure on
2026-05-06 closes `REQ-QUIC-RFC9000-S9P6P1-0005` under
`ARC-QUIC-RFC9000-0081`, `WI-QUIC-RFC9000-0081`, and
`VER-QUIC-RFC9000-0081`. The proof covers preferred-address validation
failure abandoning the failed preferred path without promotion, not recording
that path as recently validated, preserving the original server address as the
active path, and sending future packets to the original server address for
both IPv4 and IPv6 preferred-address failure cases. Regenerated coverage
triage marks the requirement as `trace_clean` and reports 1,313 of 1,771 QUIC
requirements trace-clean overall, leaving 458 non-clean. `S9P6P1` still has
three remaining non-clean requirements: `REQ-QUIC-RFC9000-S9P6P1-0001`,
`REQ-QUIC-RFC9000-S9P6P1-0006`, and
`REQ-QUIC-RFC9000-S9P6P1-0007`. This closure does not claim complete S9P6P1
closure, server preferred_address emission proof, per-family
preferred-address metadata cleanup, public migration APIs, multipath support,
hosted interop readiness, or closure of deferred fuzz obligations.

Follow-on S9P6P1 preferred-address handshake-confirmed transition closure on
2026-05-06 closes `REQ-QUIC-RFC9000-S9P6P1-0002`,
`REQ-QUIC-RFC9000-S9P6P1-0003`,
`REQ-QUIC-RFC9000-S9P6P1-0004`, and
`REQ-QUIC-RFC9000-S9P6P1-0008` under `ARC-QUIC-RFC9000-0080`,
`WI-QUIC-RFC9000-0080`, and `VER-QUIC-RFC9000-0080`. The proof covers
client HANDSHAKE_DONE starting preferred_address validation, no validation
candidate when no preferred_address exists, same-family IPv4 or IPv6
selection when usable, IPv6 fallback when IPv4 is unused, original-address use
while validation is pending, preferred-address promotion only after validation
succeeds, and discontinuing the old server address after successful preferred
address validation. Regenerated coverage triage marks all four requirements
as `trace_clean` and reports 1,312 of 1,771 QUIC requirements trace-clean
overall, leaving 459 non-clean. `S9P6P1` still has four remaining non-clean
requirements: `REQ-QUIC-RFC9000-S9P6P1-0001`,
`REQ-QUIC-RFC9000-S9P6P1-0005`,
`REQ-QUIC-RFC9000-S9P6P1-0006`, and
`REQ-QUIC-RFC9000-S9P6P1-0007`. This closure does not claim complete
S9P6P1 closure, preferred-address validation-failure policy proof, server
preferred_address emission proof, public migration APIs, multipath support,
hosted interop readiness, or closure of deferred fuzz obligations.

Follow-on S4P6 stream-limit metadata xref cleanup on 2026-05-06 closes
`REQ-QUIC-RFC9000-S4P6-0002` through
`REQ-QUIC-RFC9000-S4P6-0005` without production code changes. The existing
focused requirement-home proof for advertised stream-ID limits, initial
transport-parameter stream limits, later `MAX_STREAMS` limit advertisement,
and separate bidirectional/unidirectional stream limits now has resolving
canonical `x_test_refs`. Regenerated coverage triage marks all four
requirements as `trace_clean` and reports 1,308 of 1,771 QUIC requirements
trace-clean overall, leaving 463 non-clean. `S4P6` has no remaining non-clean
requirements in generated triage. This cleanup does not claim new stream-limit
behavior, automatic stream-limit autotuning, public stream API widening,
broader stream-management parity, or hosted interop readiness.

Follow-on S4P6 max_streams oversized close-policy tail closure on 2026-05-06
closes `REQ-QUIC-RFC9000-S4P6-0006` and
`REQ-QUIC-RFC9000-S4P6-0007` under `ARC-QUIC-RFC9000-0078`,
`WI-QUIC-RFC9000-0078`, and `VER-QUIC-RFC9000-0078`. The proof covers valid
`2^60` initial max_streams transport-parameter values committing without
closing, typed oversized initial max_streams inputs closing with
`TRANSPORT_PARAMETER_ERROR` before stream-limit mutation, valid `2^60`
MAX_STREAMS frames parsing and formatting for both stream directions, and
protected oversized MAX_STREAMS application frames closing with
`FRAME_ENCODING_ERROR` while preserving the triggering frame type. Regenerated
coverage triage marks both requirements as `trace_clean` and reports 1,304 of
1,771 QUIC requirements trace-clean overall, leaving 467 non-clean. This
closure does not claim automatic stream-limit autotuning, public stream API
widening, hosted interop readiness, or closure of the deferred S4P6-0006 and
S4P6-0007 fuzz expectations.

Follow-on S4P6 cumulative incoming stream-limit tail closure on 2026-05-06
closes `REQ-QUIC-RFC9000-S4P6-0001` under `ARC-QUIC-RFC9000-0079`,
`WI-QUIC-RFC9000-0079`, and `VER-QUIC-RFC9000-0079`. The proof covers
peer-initiated bidirectional and unidirectional STREAM frames within the
advertised cumulative stream-count limit being accepted, lower-numbered
streams of the same type being created before admitting the target stream, and
the existing over-limit negative proof continuing to reject stream IDs outside
the advertised limit with `STREAM_LIMIT_ERROR`. Regenerated coverage triage
marks the requirement as `trace_clean` and reports 1,304 of 1,771 QUIC
requirements trace-clean overall, leaving 467 non-clean. At that point,
`S4P6` had four remaining non-clean requirements, all metadata-only xref
cleanup for `REQ-QUIC-RFC9000-S4P6-0002` through
`REQ-QUIC-RFC9000-S4P6-0005`; the later stream-limit metadata xref cleanup
now closes that generated tail. This
closure does not claim automatic stream-limit autotuning, public stream API
widening, broader stream-management parity, or hosted interop readiness.

Follow-on S4P6 MAX_STREAMS monotonic limit update tail closure on 2026-05-06
closes `REQ-QUIC-RFC9000-S4P6-0010` and
`REQ-QUIC-RFC9000-S4P6-0011` under `ARC-QUIC-RFC9000-0077`,
`WI-QUIC-RFC9000-0077`, and `VER-QUIC-RFC9000-0077`. The proof covers larger
`MAX_STREAMS` frames increasing only the matching bidirectional or
unidirectional peer stream limit, smaller frames after a larger value having no
effect, stale smaller frames after multiple increases having no effect, and
equal non-increasing values being ignored for both stream directions.
Regenerated coverage triage marks both requirements as `trace_clean` and
reports 1,301 of 1,771 QUIC requirements trace-clean overall, leaving 470
non-clean. `S4P6` now has seven remaining non-clean requirements:
metadata-only xref cleanup for `REQ-QUIC-RFC9000-S4P6-0002` through
`REQ-QUIC-RFC9000-S4P6-0005`, and missing-proof work for
`REQ-QUIC-RFC9000-S4P6-0001`, `REQ-QUIC-RFC9000-S4P6-0006`, and
`REQ-QUIC-RFC9000-S4P6-0007`. This closure does not claim automatic
stream-limit autotuning, public stream API widening, broader stream-credit
policy, hosted interop readiness, or closure of the deferred S4P6-0010 fuzz
expectation.

Follow-on S4P6 stream-limit enforcement and blocked-open tail closure on
2026-05-06 closes `REQ-QUIC-RFC9000-S4P6-0008`,
`REQ-QUIC-RFC9000-S4P6-0009`, and
`REQ-QUIC-RFC9000-S4P6-0012` under `ARC-QUIC-RFC9000-0076`,
`WI-QUIC-RFC9000-0076`, and `VER-QUIC-RFC9000-0076`. The proof covers local
bidirectional and unidirectional opens staying within the peer's current stream
limit, inbound STREAM frames at the advertised limit being accepted, zero
advertised incoming stream limits rejecting the first peer stream with
`STREAM_LIMIT_ERROR`, and blocked local opens returning correctly shaped
`STREAMS_BLOCKED` frames while the active-runtime protected emission proof
remains linked through the existing S19P14 path. Regenerated coverage triage
marks those three requirements as `trace_clean` and reports 1,299 of 1,771
QUIC requirements trace-clean overall, leaving 472 non-clean. `S4P6` now has
nine remaining non-clean requirements: metadata-only xref cleanup for
`REQ-QUIC-RFC9000-S4P6-0002` through `REQ-QUIC-RFC9000-S4P6-0005`, and
missing-proof work for `REQ-QUIC-RFC9000-S4P6-0001`,
`REQ-QUIC-RFC9000-S4P6-0006`, `REQ-QUIC-RFC9000-S4P6-0007`,
`REQ-QUIC-RFC9000-S4P6-0010`, and `REQ-QUIC-RFC9000-S4P6-0011`. This closure
does not claim automatic stream-limit autotuning, public stream API widening,
broader stream-management parity, hosted interop readiness, or closure of the
deferred S4P6-0009 fuzz expectation.

Follow-on S5P1P1 Retry sequencing and migration pool tail closure on
2026-05-06 closes `REQ-QUIC-RFC9000-S5P1P1-0007` and
`REQ-QUIC-RFC9000-S5P1P1-0019` under `ARC-QUIC-RFC9000-0075`,
`WI-QUIC-RFC9000-0075`, and `VER-QUIC-RFC9000-0075`. The proof covers
first client-selected Destination Connection IDs and Retry Source Connection
IDs not consuming peer CID sequence numbers, the observed peer Initial Source
CID remaining the implicit sequence-0 input, later explicit preferred_address
issuance of a Retry Source CID as sequence 1 including the maximum-length
boundary, and migrated-path use of a previously unused locally issued CID
replenishing the peer-usable pool only when the peer active limit and local
issuance budget allow it. Regenerated coverage triage marks both requirements
as `trace_clean` and reports 1,296 of 1,771 QUIC requirements trace-clean
overall, leaving 475 non-clean. `S5P1P1` has no remaining non-clean
requirements in generated triage. This closure does not claim multipath,
public local migration controls, Retry integrity validation changes, public API
widening, or hosted interop readiness.

Follow-on S5P1P1 connection-ID sequence and active-set floor closure on
2026-05-06 closes `REQ-QUIC-RFC9000-S5P1P1-0003`,
`REQ-QUIC-RFC9000-S5P1P1-0004`, `REQ-QUIC-RFC9000-S5P1P1-0006`,
`REQ-QUIC-RFC9000-S5P1P1-0008`, `REQ-QUIC-RFC9000-S5P1P1-0009`,
`REQ-QUIC-RFC9000-S5P1P1-0011`, `REQ-QUIC-RFC9000-S5P1P1-0013`,
and `REQ-QUIC-RFC9000-S5P1P1-0015` under `ARC-QUIC-RFC9000-0074`,
`WI-QUIC-RFC9000-0074`, and `VER-QUIC-RFC9000-0074`. The proof covers
initial CID sequence 0 retirement, preferred-address CID sequence 1 retirement,
local replacement CID sequence increment and max-varint non-wrap behavior,
temporary active-set excess only with immediate `Retire Prior To` retirement,
issued-CID route lifetime until retirement, active issued-CID routing for short
and long headers, `active_connection_id_limit` advertisement, and replacement
CID supply after peer retirement. Regenerated coverage triage marks those eight
requirements as `trace_clean` and reports 1,294 of 1,771 QUIC requirements
trace-clean overall, leaving 477 non-clean. `S5P1P1` then had two remaining
non-clean requirements: `REQ-QUIC-RFC9000-S5P1P1-0007` and
`REQ-QUIC-RFC9000-S5P1P1-0019`; the later S5P1P1 tail closure under
`ARC-QUIC-RFC9000-0075` now closes that generated triage tail. This closure
does not claim Retry integrity validation changes, public API widening, or
hosted interop readiness.

Follow-on S5P2 weakly protected packet failure policy closure on 2026-05-06
closes `REQ-QUIC-RFC9000-S5P2-0010`,
`REQ-QUIC-RFC9000-S5P2-0012`, and
`REQ-QUIC-RFC9000-S5P2-0013` under `ARC-QUIC-RFC9000-0073`,
`WI-QUIC-RFC9000-0073`, and `VER-QUIC-RFC9000-0073`. The proof covers
Initial and Handshake packet-protection open failure discard once expected keys
are available, no deferred retry for Handshake open failure with current keys,
`PROTOCOL_VIOLATION` for forbidden weakly protected payload frames after
processable prefixes, discard-only treatment for immediate invalid Initial
payloads under the S11 allowance, and pre-validation that prevents
crypto-buffer or transcript side effects from surviving invalid Initial or
Handshake packets. Regenerated coverage triage marks those three requirements
as `trace_clean` and reports 1,286 of 1,771 QUIC requirements trace-clean
overall, leaving 485 non-clean. `S5P2` has no remaining non-clean requirements
in generated triage. This closure does not claim broader packet-protection
cryptographic correctness, Retry integrity validation changes, Version
Negotiation behavior changes, public API widening, or hosted interop readiness.

Follow-on S5P2 packet classification and connection association floor closure
on 2026-05-06 closes `REQ-QUIC-RFC9000-S5P2-0001` through
`REQ-QUIC-RFC9000-S5P2-0006`, `REQ-QUIC-RFC9000-S5P2-0008`,
`REQ-QUIC-RFC9000-S5P2-0009`, and `REQ-QUIC-RFC9000-S5P2-0011`
under `ARC-QUIC-RFC9000-0072`, `WI-QUIC-RFC9000-0072`, and
`VER-QUIC-RFC9000-0072`. The proof covers packet classification on receipt,
existing connection association before unroutable handling, conforming Initial
server connection creation, non-zero Destination Connection ID exact routing
including maximum-length IDs, zero-length connection ID local-address matching
across remote-address changes, version-mismatch discard, and discard of invalid
weakly protected packet forms without runtime packet-space processing.
At that closure point, regenerated coverage triage marked those nine
requirements as `trace_clean` and reported 1,283 of 1,771 QUIC requirements
trace-clean overall, leaving 488 non-clean. `S5P2` then had three remaining
non-clean requirements:
`REQ-QUIC-RFC9000-S5P2-0010`, `REQ-QUIC-RFC9000-S5P2-0012`, and
`REQ-QUIC-RFC9000-S5P2-0013`; the later S5P2 weakly protected packet failure
policy closure now closes that tail. This closure does not claim public API
widening or hosted interop readiness.

Follow-on S7P4P1 updated-value packet-use policy closure on 2026-05-06 closes
`REQ-QUIC-RFC9000-S7P4P1-0010` through
`REQ-QUIC-RFC9000-S7P4P1-0013` under
`ARC-QUIC-RFC9000-0071`, `WI-QUIC-RFC9000-0071`, and
`VER-QUIC-RFC9000-0071`. The proof covers an internal packet-use policy that
allows 0-RTT packet use only with remembered transport-parameter values,
rejects updated handshake and 1-RTT-frame values for 0-RTT use with
`PROTOCOL_VIOLATION` semantics, applies updated values only to 1-RTT packets,
fails closed for unknown provenance, and exposes a server-side optional
violation helper for detected updated-value use in 0-RTT. Regenerated coverage
triage marks those four requirements as `trace_clean` and reports 1,274 of
1,771 QUIC requirements trace-clean overall, leaving 497 non-clean. `S7P4P1`
has no remaining non-clean requirements in generated triage. This closure does
not claim public early-data APIs, TLS `early_data` extension admission wiring,
anti-replay behavior, 0-RTT decryption, application-data delivery, or hosted
interop readiness.

Follow-on S7P4P1 client 0-RTT handshake-value supersession policy closure on
2026-05-06 closes `REQ-QUIC-RFC9000-S7P4P1-0003` under
`ARC-QUIC-RFC9000-0070`, `WI-QUIC-RFC9000-0070`, and
`VER-QUIC-RFC9000-0070`. The proof covers ignoring prohibited remembered
transport-parameter values in favor of the server's new handshake values and
resolving absent server values to defaults or absence rather than remembered
values. At that closure point, regenerated coverage triage marked the
requirement as `trace_clean` and reported 1,270 of 1,771 QUIC requirements
trace-clean overall, leaving 501 non-clean. `S7P4P1` then had four remaining non-clean requirements:
`REQ-QUIC-RFC9000-S7P4P1-0010` through
`REQ-QUIC-RFC9000-S7P4P1-0013`. This closure does not claim updated-value use
in 0-RTT packets, server protocol-violation handling, public early-data APIs,
TLS `early_data` extension admission wiring, anti-replay behavior, or
application-data delivery. Later S7P4P1 tail closure under
`ARC-QUIC-RFC9000-0071` closes the remaining S7P4P1 generated triage gap.

Follow-on S7P4P1 server 0-RTT transport-parameter acceptance policy closure
on 2026-05-06 closes `REQ-QUIC-RFC9000-S7P4P1-0005` through
`REQ-QUIC-RFC9000-S7P4P1-0009` under `ARC-QUIC-RFC9000-0069`,
`WI-QUIC-RFC9000-0069`, and `VER-QUIC-RFC9000-0069`. The proof covers an
internal server acceptance decision over remembered and current transport
parameters, reductions to required Section 18.2 0-RTT limits, non-zero
application-data allowance, restored optional `max_idle_timeout`,
`max_udp_payload_size`, and `disable_active_migration` reductions, and
missing current server-parameter rejection. At that closure point, regenerated
coverage triage marked those five requirements as `trace_clean` and reported
1,269 of 1,771 QUIC requirements trace-clean overall, leaving 502 non-clean.
`S7P4P1` then had five
remaining non-clean requirements: `REQ-QUIC-RFC9000-S7P4P1-0003` and
`REQ-QUIC-RFC9000-S7P4P1-0010` through
`REQ-QUIC-RFC9000-S7P4P1-0013`. This closure does not claim public early-data
APIs, TLS `early_data` extension admission wiring, server anti-replay behavior,
application-data delivery, or updated-value-in-0-RTT protocol-violation
enforcement.

Follow-on S7P4P1 client 0-RTT remembered transport-parameter policy closure
on 2026-05-06 closes `REQ-QUIC-RFC9000-S7P4P1-0001`,
`REQ-QUIC-RFC9000-S7P4P1-0002`, and
`REQ-QUIC-RFC9000-S7P4P1-0004` under `ARC-QUIC-RFC9000-0068`,
`WI-QUIC-RFC9000-0068`, and `VER-QUIC-RFC9000-0068`. The proof covers an
internal 0-RTT transport-parameter storage classification table, exclusion of
prohibited remembered values, retention of processable peer transport
parameters in the detached-ticket 0-RTT subset, and failure to enable dormant
0-RTT readiness when a ticket carries only prohibited remembered values. At
that closure point, regenerated coverage triage marked those three requirements
as `trace_clean` and reported 1,264 of 1,771 QUIC requirements trace-clean
overall, leaving 507 non-clean. `S7P4P1` then had ten remaining non-clean requirements:
`REQ-QUIC-RFC9000-S7P4P1-0003` and `REQ-QUIC-RFC9000-S7P4P1-0005` through
`REQ-QUIC-RFC9000-S7P4P1-0013`. This closure does not claim server 0-RTT
acceptance or rejection policy, restored transport-parameter support checks,
updated transport-parameter violation handling, TLS `early_data` extension
support, public early-data APIs, anti-replay behavior, or application-data
delivery.

Follow-on S18P2 max_ack_delay alarm-slack policy closure on 2026-05-06 closes
`REQ-QUIC-RFC9000-S18P2-0015` under
`ARC-QUIC-RFC9000-0067`, `WI-QUIC-RFC9000-0067`, and
`VER-QUIC-RFC9000-0067`. The proof covers a centralized runtime
`max_ack_delay` default composed from intentional ACK-delay budget plus expected
alarm-firing delay, preservation of the existing 25 millisecond behavior,
absent-local-parameter ACK timer scheduling at that composed default, explicit
composed-value ACK timer scheduling, and saturating composition. Regenerated
coverage triage marks `REQ-QUIC-RFC9000-S18P2-0015` as `trace_clean` and
reports 1,261 of 1,771 QUIC requirements trace-clean overall, leaving 510
non-clean. `S18P2` has no remaining non-clean requirements in generated triage.
This closure does not claim public `max_ack_delay` configuration APIs,
transport-parameter wire serialization changes, ACK delay exponent or PTO
policy changes, broader Section 18.2 closure outside the now-clean generated
requirement set, or hosted interop readiness.

Follow-on S18P2 max_udp_payload_size receiver-limit closure on 2026-05-06
closes `REQ-QUIC-RFC9000-S18P2-0007` under
`ARC-QUIC-RFC9000-0066`, `WI-QUIC-RFC9000-0066`, and
`VER-QUIC-RFC9000-0066`. The proof covers local transport-parameter commit
publishing a max-UDP-payload-size endpoint effect, per-connection receive-limit
state in the endpoint, exact-limit routed datagrams being posted to the
runtime, over-limit routed datagrams being dropped before `PacketReceived`, and
host shells treating those drops as terminal local handling rather than
stateless-reset or listener pre-acceptance route misses. Regenerated coverage
triage marks `REQ-QUIC-RFC9000-S18P2-0007` as `trace_clean` and reports 1,260
of 1,771 QUIC requirements trace-clean overall, leaving 511 non-clean. `S18P2`
is now down to one remaining non-clean requirement:
`REQ-QUIC-RFC9000-S18P2-0015` for `max_ack_delay` alarm-delay policy. This
closure does not claim UDP socket receive-buffer sizing, path MTU discovery,
peer send-size enforcement, public `max_udp_payload_size` configuration APIs,
broader Section 18.2 closure, or hosted interop readiness.

Follow-on S18P2 initial_max_data runtime commit on 2026-05-06 closes
`REQ-QUIC-RFC9000-S18P2-0008` under `ARC-QUIC-RFC9000-0065`,
`WI-QUIC-RFC9000-0065`, and `VER-QUIC-RFC9000-0065`. The proof covers peer
transport-parameter commit installing `initial_max_data` as the runtime
connection-level send credit, hosted client and server runtimes starting with
zero outbound connection send credit until peer parameters arrive, `MAX_DATA`
frame handling staying on its separate monotonic update path, and stale
speculative send credit being replaced by the exact peer value. Regenerated
coverage triage marks `REQ-QUIC-RFC9000-S18P2-0008` as `trace_clean` and
reports 1,259 of 1,771 QUIC requirements trace-clean overall, leaving 512
non-clean. `S18P2` is now down to two remaining non-clean requirements:
`REQ-QUIC-RFC9000-S18P2-0007` and `REQ-QUIC-RFC9000-S18P2-0015`. This closure
does not claim `max_udp_payload_size` receiver processing, `max_ack_delay`
alarm-delay policy, broader Section 18.2 closure, public flow-control APIs,
0-RTT remembered transport-parameter validation, or hosted interop readiness.

Follow-on S18P2 max_idle_timeout trace cleanup on 2026-05-05 closes
`REQ-QUIC-RFC9000-S18P2-0002` as a metadata-only cleanup under the existing
focused requirement-home proof. The cleanup removed stale broad transport
parameter test refs so the canonical `x_test_refs` point only at the
requirement-owned max_idle_timeout tests. It did not add new runtime behavior.

Follow-on S22P1P1 closure on 2026-05-05 closes
`REQ-QUIC-RFC9000-S22P1P1-0001` through
`REQ-QUIC-RFC9000-S22P1P1-0014` under
`ARC-QUIC-RFC9000-0064`, `WI-QUIC-RFC9000-0064`, and
`VER-QUIC-RFC9000-0064`. The proof covers the bounded RFC 9000 IANA
provisional-registration policy model, including request minimum fields,
Expert Review, Date handling, common support fields, optional Specification and
Notes for provisional registrations, and the corrected `0001` request-minimum
wording. This is registry-process metadata only.

For the current S18P2 tail, generated triage now has no remaining non-clean
`S18P2` requirements. Pick the next hard lane from generated triage rather than
reopening the Section 18.2 tail without new evidence.

## 2026-05-05 Restart Note

Follow-on S17P2P5P2/P3 closure on 2026-05-05 closes
`REQ-QUIC-RFC9000-S17P2P5P2-0001` through
`REQ-QUIC-RFC9000-S17P2P5P2-0009` and
`REQ-QUIC-RFC9000-S17P2P5P3-0001` through
`REQ-QUIC-RFC9000-S17P2P5P3-0007` under
`ARC-QUIC-RFC9000-0060`, `WI-QUIC-RFC9000-0060`, and
`VER-QUIC-RFC9000-0060`. The proof covers first valid Retry acceptance,
malformed Retry metadata rejection, duplicate Retry discard, Retry-selected
Initial replay token and destination connection ID use, original client Source
Connection ID and ClientHello preservation, no explicit Retry acknowledgment,
post-Retry 0-RTT destination connection ID selection, packet-number continuity,
and protected 0-RTT payload confidentiality. Regenerated coverage triage marks
those claimed S17P2P5P2/P3 requirements as `trace_clean` and reports 1,226 of
1,771 QUIC requirements trace-clean overall, leaving 545 non-clean.
`REQ-QUIC-RFC9000-S17P2P5P3-0008` remains optional server abort behavior and
is deliberately not claimed by this closure.

Follow-on S7P3 closure on 2026-05-05 closes
`REQ-QUIC-RFC9000-S7P3-0001` through
`REQ-QUIC-RFC9000-S7P3-0009` under
`ARC-QUIC-RFC9000-0059`, `WI-QUIC-RFC9000-0059`, and
`VER-QUIC-RFC9000-0059`. The proof covers codec preservation of
`original_destination_connection_id`, `initial_source_connection_id`, and
`retry_source_connection_id`, server-only parameter rejection from client
emission, missing and mismatched binding rejection, matching binding
acceptance, and zero-length selected connection IDs as present empty transport
parameters rather than absent parameters. The runtime commit path now validates
expected empty peer Initial Source Connection IDs instead of skipping the
connection-ID binding check. Regenerated coverage triage marks all S7P3
requirements as `trace_clean`. Keep the boundary narrow: this S7P3 closure
does not claim Section 7.4 invalid-value policy, remembered 0-RTT
transport-parameter checks, preferred-address migration, public connection-ID
policy APIs, hosted interop readiness, or broader connection-ID lifecycle parity
outside Section 7.3.

Follow-on S18P2 stream-count closure on 2026-05-05 closes
`REQ-QUIC-RFC9000-S18P2-0010` through
`REQ-QUIC-RFC9000-S18P2-0014` under
`ARC-QUIC-RFC9000-0061`, `WI-QUIC-RFC9000-0061`, and
`VER-QUIC-RFC9000-0061`. The proof covers
`initial_max_streams_bidi` and `initial_max_streams_uni` transport-parameter
encoding and parsing as variable-length integer fields, 2^60 boundary
acceptance, above-boundary rejection, advertised bidirectional and
unidirectional stream-open limits, and absent or explicit-zero stream-count
limits blocking local stream opens until a later matching `MAX_STREAMS` frame
raises the limit. Regenerated coverage triage marks these five requirements as
`trace_clean` and reports 1,230 of 1,771 QUIC requirements trace-clean overall,
leaving 541 non-clean. This closure does not claim initial data-limit
parameters, `max_ack_delay` policy, `disable_active_migration`,
`preferred_address` fields, public stream APIs, or hosted interop readiness.

Follow-on S18P2 disable-active-migration closure on 2026-05-05 closes
`REQ-QUIC-RFC9000-S18P2-0016` through
`REQ-QUIC-RFC9000-S18P2-0018` under
`ARC-QUIC-RFC9000-0062`, `WI-QUIC-RFC9000-0062`, and
`VER-QUIC-RFC9000-0062`. The proof covers `disable_active_migration`
empty-value encoding, non-empty-value rejection, runtime commit of the
disable-active-migration transport flag, ordinary validated migration
candidates staying unpromoted, preferred-address candidates waiting for
validation, and validated dedicated or port-only preferred-address candidates
promoting despite `disable_active_migration`. Regenerated coverage triage marks
these three requirements as `trace_clean` and reports 1,233 of 1,771 QUIC
requirements trace-clean overall, leaving 538 non-clean. This closure does not
claim `max_ack_delay` policy, initial data-limit parameters, the broader
preferred-address field-shape family, public migration APIs, multipath, or
hosted interop readiness.

Follow-on S18P2 preferred-address field-shape closure on 2026-05-05 closes
`REQ-QUIC-RFC9000-S18P2-0019`, `REQ-QUIC-RFC9000-S18P2-0020` through
`REQ-QUIC-RFC9000-S18P2-0023`, `REQ-QUIC-RFC9000-S18P2-0028` through
`REQ-QUIC-RFC9000-S18P2-0031`, and `REQ-QUIC-RFC9000-S18P2-0033` under
`ARC-QUIC-RFC9000-0063`, `WI-QUIC-RFC9000-0063`, and
`VER-QUIC-RFC9000-0063`. The proof covers preferred_address IPv4 and IPv6
address/port field presence, all-zero unused-family handling, network-byte-order
IP address bytes, two-byte port fields, the final 16-byte stateless reset token
field associated with the preferred connection ID, truncated-value rejection,
original server-address retention before preferred-address validation, and
preferred server-address promotion after validation succeeds. Regenerated
coverage triage marks these ten requirements as `trace_clean` and reports
1,243 of 1,771 QUIC requirements trace-clean overall, leaving 528 non-clean.
Later max_idle_timeout and initial_max_data closures supersede this entry's
S18P2 tail count. This closure does not claim preferred_address connection-ID
sequence/accounting constraints beyond the existing `0031` lane,
disable_active_migration beyond the existing `0062` lane, public migration
APIs, multipath, or hosted interop readiness.

Follow-on S5P2P2 closure on 2026-05-05 closes
`REQ-QUIC-RFC9000-S5P2P2-0007` and
`REQ-QUIC-RFC9000-S5P2P2-0008` under
`ARC-QUIC-RFC9000-0056`, `WI-QUIC-RFC9000-0056`, and
`VER-QUIC-RFC9000-0056`. The proof covers protected Initial
`CONNECTION_REFUSED` emission when the listener application deliberately
refuses an otherwise valid new connection, no refusal close for accepted
connections, short client Source Connection ID preservation, bounded 0-RTT
pre-Initial buffering, disabled-buffer drops, and cap enforcement before
draining for the matching late Initial. This does not claim 0-RTT decryption,
early-data acceptance, anti-replay behavior, application delivery, public API
widening, client-side Version Negotiation, preferred-address behavior, or
hosted interop readiness.

This note is intentionally narrow for handoff. The just-finished slices close
the RFC 9000 S19P13 STREAM_DATA_BLOCKED parser/field-shape topoff for
`REQ-QUIC-RFC9000-S19P13-0003` through
`REQ-QUIC-RFC9000-S19P13-0008`, and the receiver-side send-only closeout for
`REQ-QUIC-RFC9000-S19P13-0002`. The S19P13 proof now covers type `0x15`,
Stream ID and Maximum Stream Data varint encoding, truncation/out-of-range
rejection, frame-boundary consumption, blocked-stream identity preservation,
blocked-offset preservation, receive-capable stream acceptance, and protected
runtime close with `STREAM_STATE_ERROR` for opened or uncreated send-only
stream IDs.

The S19P14 STREAMS_BLOCKED focused proof closure now has two bounded parts.
The frame-focused slice closes
`REQ-QUIC-RFC9000-S19P14-0002` and `REQ-QUIC-RFC9000-S19P14-0004`
through `REQ-QUIC-RFC9000-S19P14-0009` under
`ARC-QUIC-RFC9000-0054`, `WI-QUIC-RFC9000-0054`, and
`VER-QUIC-RFC9000-0054`. The proof covers type `0x16`/`0x17` mapping,
Type and Maximum Streams varint boundaries, required-field presence, exact
frame consumption, advertised stream-count preservation, 2^60 limit
enforcement, valid protected receive acceptance, protected
`FRAME_ENCODING_ERROR` close behavior for larger encoded values, and permanent
STREAMS_BLOCKED parse/format benchmark coverage. It does not claim outbound
STREAMS_BLOCKED emission scheduling, pending stream-open retry behavior, public
flow-control APIs, or complete S19P14 sender-side SHOULD/no-open closure.

The sender-tail slice closes `REQ-QUIC-RFC9000-S19P14-0001` and
`REQ-QUIC-RFC9000-S19P14-0003` under the existing runtime-emission artifacts
`ARC-QUIC-RFC9000-0007`, `WI-QUIC-RFC9000-0007`, and
`VER-QUIC-RFC9000-0007`. The proof covers the zero peer-stream-limit edge,
protected STREAMS_BLOCKED emission for blocked outbound opens, no stream-state
creation, and keeping the blocked open pending until cancellation or real
`MAX_STREAMS` growth. Regenerated coverage triage now marks
`REQ-QUIC-RFC9000-S19P14-0001` through
`REQ-QUIC-RFC9000-S19P14-0009` as `trace_clean`.

Current triage reminders after the S17P2P5P2/P3 closure:

1. Start in `docs/requirements-workflow.md`, then check
   `specs/requirements/quic/REQUIREMENT-GAPS.md` and the nearest owning
   `SPEC-QUIC-RFC9000.json` section before choosing the next non-clean group.
2. Regenerated coverage triage marks `REQ-QUIC-RFC9000-S7P3-0001` through
   `REQ-QUIC-RFC9000-S7P3-0009` as `trace_clean`; S7P3 no longer needs to be
   the next local lane.
3. Regenerated coverage triage marks `REQ-QUIC-RFC9000-S17P2P5P2-0001`
   through `REQ-QUIC-RFC9000-S17P2P5P2-0009` and
   `REQ-QUIC-RFC9000-S17P2P5P3-0001` through
   `REQ-QUIC-RFC9000-S17P2P5P3-0007` as `trace_clean`.
4. `REQ-QUIC-RFC9000-S17P2P5P3-0008` remains optional, unclaimed server abort
   behavior and should not be treated as proven by the Retry client-processing
   closure.
5. Do not describe S19P13 closure as new STREAM_DATA_BLOCKED emission
   scheduling, flow-control autotuning, asynchronous credit waiting,
   sender/recovery behavior, public flow-control APIs, S19P14 STREAMS_BLOCKED
   behavior, or interop readiness.
6. Regenerated coverage triage marks `REQ-QUIC-RFC9000-S19P13-0001` through
   `REQ-QUIC-RFC9000-S19P13-0008` as `trace_clean`.
7. Regenerated coverage triage marks `REQ-QUIC-RFC9000-S19P14-0002` and
   `REQ-QUIC-RFC9000-S19P14-0004` through
   `REQ-QUIC-RFC9000-S19P14-0009` as `trace_clean`.
8. Regenerated coverage triage marks `REQ-QUIC-RFC9000-S19P14-0001` and
   `REQ-QUIC-RFC9000-S19P14-0003` as `trace_clean`; S19P14 no longer needs to
   be the next local lane.
9. Regenerated coverage triage marks `REQ-QUIC-RFC9000-S5P2P2-0001` through
   `REQ-QUIC-RFC9000-S5P2P2-0010` as `trace_clean`; S5P2P2 no longer needs to
   be the next local lane.

Focused triage command:

```powershell
$triage = Get-Content specs\generated\quic\quic-requirement-coverage-triage.json -Raw | ConvertFrom-Json -Depth 100
@($triage.requirements) |
  Where-Object { $_.state -ne 'trace_clean' } |
  Select-Object -First 25 requirement_id,state,primary_issue,@{Name='missing';Expression={$_.evidence_summary.missing_required_kinds -join ','}}
@($triage.requirements) |
  Where-Object { $_.state -ne 'trace_clean' } |
  Group-Object { if ($_.requirement_id -match 'REQ-QUIC-RFC9000-(S[^-]+)-') { $Matches[1] } else { 'other' } } |
  Sort-Object Count -Descending |
  Select-Object -First 12 Name,Count
@($triage.requirements) |
  Where-Object { $_.requirement_id -like 'REQ-QUIC-RFC9000-S19P14-*' } |
  Select-Object requirement_id,state,primary_issue,@{Name='missing';Expression={$_.evidence_summary.missing_required_kinds -join ','}}
```

## Executive Read

The repository now has a green local executable and SpecTrace baseline. The
Release build passes, the full requirement-linked test suite passes, the
repo-local SpecTrace validator passes, Workbench core validation passes, and
the repo-defined Dry and Short benchmark baseline jobs complete in the
2026-04-30 final-evidence refresh. The local trace/gap closure train through
commit `cbe8d8d1` closes the stale RFC 9002, migration-core,
handshake-orchestration, and ACK-piggyback proof-tail ledger items, and commit
`dd73ac26` refreshes the public API boundary notes without widening the public
support promise. Hosted CI and CodeQL workflows also passed for the latest
hosted-validated runtime/trace commit `ee86bb13`.
A manual hosted interop-runner workflow is configured as an advisory artifact
collection lane. The default profile keeps the narrow server-role handshake
dispatch, which passed on GitHub Actions run `25145021654` for commit
`e6dcbb80` after the workflow moved its repo-controlled Python setup and
artifact upload actions to Node 24-compatible majors. The workflow now also
has an opt-in `supported-subset` profile for already-supported helper cells
covering retry, split-role transfer, and client-role multiconnect planning;
that profile has local dry-run and requirement-home proof, but it has not yet
been refreshed as hosted GitHub Actions evidence.

This is not a broad QUIC-complete claim and should not be described as
interop-ready. The supported boundary remains narrow: managed loopback,
selected stream/control behavior, selected TLS/trust floors, and local harness
contracts that are backed by requirement-home proof. Broader hosted runner
matrices beyond the explicit supported-subset profile, hosted execution of that
profile, and any public-surface widening remain separate work.

## Verified Commands

Run from the repository root.

```powershell
dotnet tool restore
dotnet build Incursa.Quic.slnx -c Release
dotnet test Incursa.Quic.slnx -c Release --no-build -m:1
pwsh -NoProfile -File scripts\Validate-SpecTraceJson.ps1 -Profiles core
dotnet tool run workbench -- --format json validate --profile core
.\scripts\benchmarks\Invoke-QuicBaseline.ps1 -Job Dry
.\scripts\benchmarks\Invoke-QuicBaseline.ps1 -Job Short
pwsh -NoProfile -File scripts\interop\Invoke-QuicInteropRunner.ps1 -DryRun -LocalRole server -PeerImplementationSlots quic-go -TestCases handshake
pwsh -NoProfile -File scripts\interop\Invoke-QuicInteropRunner.ps1 -DryRun -LocalRole both -PeerImplementationSlots quic-go -TestCases handshake,retry,transfer,multiconnect
pwsh -NoProfile -File scripts\interop\Invoke-QuicInteropRunner.ps1 -DryRun -LocalRole both -ImplementationSlot quic-go -PeerImplementationSlots quic-go -TestCases retry
pwsh -NoProfile -File scripts\interop\Invoke-QuicInteropRunner.ps1 -DryRun -LocalRole client -ImplementationSlot chrome -PeerImplementationSlots quic-go -TestCases transfer
pwsh -NoProfile -File scripts\interop\Invoke-QuicInteropRunner.ps1 -DryRun -LocalRole server -ImplementationSlot nginx -PeerImplementationSlots quic-go -TestCases transfer
pwsh -NoProfile -File scripts\interop\Invoke-QuicInteropRunner.ps1 -DryRun -LocalRole client -ImplementationSlot chrome -PeerImplementationSlots quic-go -TestCases multiconnect
pwsh -NoProfile -File scripts\interop\Invoke-QuicInteropRunner.ps1 -LocalRole server -PeerImplementationSlots quic-go -TestCases handshake
gh workflow run interop-runner-handshake.yml --repo incursa/quic-dotnet --ref main -f coverage_profile=hosted-handshake
gh workflow run interop-runner-handshake.yml --repo incursa/quic-dotnet --ref main -f coverage_profile=supported-subset
gh run watch 25145021654 --repo incursa/quic-dotnet --exit-status
gh run watch 25145022368 --repo incursa/quic-dotnet --exit-status
gh run watch 25146253564 --repo incursa/quic-dotnet --exit-status
gh run watch 25146253205 --repo incursa/quic-dotnet --exit-status
gh run watch 25147850307 --repo incursa/quic-dotnet --exit-status
gh run watch 25147850047 --repo incursa/quic-dotnet --exit-status
gh run watch 25147993693 --repo incursa/quic-dotnet --exit-status
gh run watch 25147993402 --repo incursa/quic-dotnet --exit-status
gh run watch 25149446012 --repo incursa/quic-dotnet --exit-status
gh run watch 25149445624 --repo incursa/quic-dotnet --exit-status
gh run watch 25149650001 --repo incursa/quic-dotnet --exit-status
gh run watch 25149649726 --repo incursa/quic-dotnet --exit-status
gh run watch 25149821476 --repo incursa/quic-dotnet --exit-status
gh run watch 25149821187 --repo incursa/quic-dotnet --exit-status
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release --no-build -m:1 --filter "FullyQualifiedName~REQ_QUIC_API_0001|FullyQualifiedName~REQ_QUIC_API_0005|FullyQualifiedName~REQ_QUIC_API_0008|FullyQualifiedName~REQ_QUIC_API_0009"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release --no-build -m:1 --filter "FullyQualifiedName~REQ_QUIC_API_0012|FullyQualifiedName~REQ_QUIC_API_0005|FullyQualifiedName~REQ_QUIC_CRT_0123"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release -m:1 --filter "FullyQualifiedName~REQ_QUIC_API_0001|FullyQualifiedName~REQ_QUIC_API_0002|FullyQualifiedName~REQ_QUIC_API_0003|FullyQualifiedName~REQ_QUIC_API_0004|FullyQualifiedName~REQ_QUIC_API_0005|FullyQualifiedName~REQ_QUIC_API_0006|FullyQualifiedName~REQ_QUIC_API_0007|FullyQualifiedName~REQ_QUIC_API_0008|FullyQualifiedName~REQ_QUIC_API_0009|FullyQualifiedName~REQ_QUIC_API_0010|FullyQualifiedName~REQ_QUIC_API_0011"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release --no-build -m:1 --filter "FullyQualifiedName~REQ_QUIC_API|FullyQualifiedName~REQ_QUIC_CRT_0124|FullyQualifiedName~REQ_QUIC_CRT_0125|FullyQualifiedName~REQ_QUIC_CRT_0126"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release --no-build -m:1 --filter "FullyQualifiedName~REQ_QUIC_CRT_"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release --no-build -m:1 --filter "FullyQualifiedName~REQ_QUIC_INT"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release -m:1 --filter "FullyQualifiedName~REQ_QUIC_CRT_0134|FullyQualifiedName~REQ_QUIC_CRT_0135"
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicDiagnosticsBenchmarks*"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release --no-build -m:1 --filter "FullyQualifiedName~REQ_QUIC_INT_0008"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release -m:1 --filter "FullyQualifiedName~REQ_QUIC_INT_0001|FullyQualifiedName~REQ_QUIC_INT_0002|FullyQualifiedName~REQ_QUIC_INT_0003|FullyQualifiedName~REQ_QUIC_INT_0004|FullyQualifiedName~REQ_QUIC_INT_0005"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release -m:1 --filter "FullyQualifiedName~REQ_QUIC_CRT_0045|FullyQualifiedName~REQ_QUIC_CRT_0047|FullyQualifiedName~REQ_QUIC_CRT_0048|FullyQualifiedName~REQ_QUIC_CRT_0049|FullyQualifiedName~REQ_QUIC_CRT_0050|FullyQualifiedName~REQ_QUIC_CRT_0051|FullyQualifiedName~REQ_QUIC_CRT_0052|FullyQualifiedName~REQ_QUIC_CRT_0053|FullyQualifiedName~REQ_QUIC_CRT_0054|FullyQualifiedName~REQ_QUIC_CRT_0057"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release -m:1 --filter "FullyQualifiedName~REQ_QUIC_CRT_0002|FullyQualifiedName~REQ_QUIC_CRT_0012|FullyQualifiedName~REQ_QUIC_CRT_0013|FullyQualifiedName~REQ_QUIC_CRT_0014|FullyQualifiedName~REQ_QUIC_CRT_0015|FullyQualifiedName~REQ_QUIC_CRT_0016|FullyQualifiedName~REQ_QUIC_CRT_0080|FullyQualifiedName~REQ_QUIC_CRT_0082|FullyQualifiedName~REQ_QUIC_CRT_0083|FullyQualifiedName~REQ_QUIC_CRT_0085|FullyQualifiedName~REQ_QUIC_CRT_0086"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release -m:1 --filter "FullyQualifiedName~REQ_QUIC_CRT_0001|FullyQualifiedName~REQ_QUIC_CRT_0004|FullyQualifiedName~REQ_QUIC_CRT_0005|FullyQualifiedName~REQ_QUIC_CRT_0006|FullyQualifiedName~REQ_QUIC_CRT_0008|FullyQualifiedName~REQ_QUIC_CRT_0009|FullyQualifiedName~REQ_QUIC_CRT_0010|FullyQualifiedName~REQ_QUIC_CRT_0014|FullyQualifiedName~REQ_QUIC_CRT_0017|FullyQualifiedName~REQ_QUIC_CRT_0018|FullyQualifiedName~REQ_QUIC_CRT_0020|FullyQualifiedName~REQ_QUIC_CRT_0093|FullyQualifiedName~REQ_QUIC_CRT_0094|FullyQualifiedName~REQ_QUIC_CRT_0095|FullyQualifiedName~REQ_QUIC_CRT_0096"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release --no-build -m:1 --filter "FullyQualifiedName~REQ_QUIC_RFC8999_S5P1"
dotnet build fuzz\Incursa.Quic.Fuzz.csproj -c Release
dotnet tool run sharpfuzz -- fuzz\bin\Release\net10.0\Incursa.Quic.dll
"abc" | dotnet fuzz\bin\Release\net10.0\Incursa.Quic.Fuzz.dll
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicHeaderParsingBenchmarks*"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release --no-build -m:1 --filter "FullyQualifiedName~RFC9000|FullyQualifiedName~QuicFrameCodec|FullyQualifiedName~QuicHeaderFuzzTests|FullyQualifiedName~QuicHeaderPropertyTests|FullyQualifiedName~QuicPacketParserTests|FullyQualifiedName~QuicStreamFrameTests|FullyQualifiedName~QuicStreamIdTests|FullyQualifiedName~QuicTransportParameters|FullyQualifiedName~QuicVersionNegotiation|FullyQualifiedName~QuicConnectionStreamState"
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicFrameCodecBenchmarks*"
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicStreamParsingBenchmarks*"
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicVariableLengthIntegerBenchmarks*"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release --no-build -m:1 --filter "FullyQualifiedName~RFC9001|FullyQualifiedName~QuicInitialPacketProtection|FullyQualifiedName~QuicHandshakePacketProtection|FullyQualifiedName~QuicRetryIntegrity|FullyQualifiedName~QuicTls|FullyQualifiedName~QuicAeadUsageLimitCalculator"
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicInitialPacketProtectionBenchmarks*"
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicHandshakePacketProtectionBenchmarks*"
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicRetryIntegrityBenchmarks*"
dotnet run -c Release --project benchmarks\Incursa.Quic.Benchmarks.csproj -- --job Dry --filter "*QuicAeadUsageLimitCalculatorBenchmarks*"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release --no-build -m:1 --filter "FullyQualifiedName~RFC9002"
```

Observed results through 2026-04-30:

| Command | Result |
|---|---|
| `dotnet tool restore` | Passed; restored `dotnet-stryker` 4.14.0, `sharpfuzz.commandline` 2.2.0, and `incursa.workbench` 2026.4.15.1172 |
| `dotnet build Incursa.Quic.slnx -c Release` | Passed on 2026-04-30 in the interop coverage refresh: 0 warnings, 0 errors |
| `dotnet test Incursa.Quic.slnx -c Release --no-build -m:1` | Passed on 2026-04-30 in the interop coverage refresh: 3,304 passed, 0 failed, 0 skipped, 3,304 total |
| `pwsh -NoProfile -File scripts\Validate-SpecTraceJson.ps1 -Profiles core` | Passed on 2026-04-30 in the interop coverage refresh: validated 316 SpecTrace JSON artifacts |
| `dotnet tool run workbench -- --format json validate --profile core` | Passed on 2026-04-30 in the interop coverage refresh: 0 errors, 0 warnings, 103 work items, 320 markdown files |
| `.\scripts\benchmarks\Invoke-QuicBaseline.ps1 -Job Dry` | Passed on 2026-04-30 after local commit `dd73ac26`: built the benchmark project and executed the congestion-control, RTT-estimator, and connection stream-state Dry slices |
| `.\scripts\benchmarks\Invoke-QuicBaseline.ps1 -Job Short` | Passed on 2026-04-30 after local commit `dd73ac26`: built the benchmark project and executed the congestion-control, RTT-estimator, and connection stream-state Short slices |
| `pwsh -NoProfile -File scripts\interop\Invoke-QuicInteropRunner.ps1 -DryRun -LocalRole server -PeerImplementationSlots quic-go -TestCases handshake` | Passed on 2026-04-30: resolved the hosted-corresponding plan to server-role `nginx` replacement against quic-go for `handshake` |
| `pwsh -NoProfile -File scripts\interop\Invoke-QuicInteropRunner.ps1 -DryRun -LocalRole both -PeerImplementationSlots quic-go -TestCases handshake,retry,transfer,multiconnect` | Passed on 2026-04-30: resolved the supported local helper subset and translated local `multiconnect` to the runner `handshakeloss` testcase |
| supported-subset per-cell dry-run plans | Passed on 2026-04-30: resolved same-slot `retry`, split-role client `transfer`, split-role server `transfer`, and client-role `multiconnect` plans with distinct role, slot, peer, and testcase mappings |
| focused interop coverage workflow filter | Passed on 2026-04-30: 46 passed, 0 failed, 0 skipped across `REQ_QUIC_INT_0017`, `REQ_QUIC_INT_0013`, and interop helper dry-run/failure-summary tests |
| focused interop helper preflight/filter | Passed on 2026-04-30: 52 passed, 0 failed, 0 skipped across preflight, artifact-validation, failure-summary, and `REQ_QUIC_INT_0013` helper tests |
| local non-DryRun `retry` interop-runner attempt | Reached managed client/server Retry success on 2026-04-30, then the external runner failed its packet-analysis post-check because local `tshark` was not installed; evidence was preserved under `artifacts/interop-runner/local-supported-subset/both-retry-quic-go/20260430-091716463-both-quic-go/` |
| local non-DryRun packet-tool preflight | Passed as an honest blocker on 2026-04-30: the helper now fails before Docker build or runner launch when `tshark`/`editcap` packet-analysis tools are missing |
| `pwsh -NoProfile -File scripts\interop\Invoke-QuicInteropRunner.ps1 -LocalRole server -PeerImplementationSlots quic-go -TestCases handshake` | Passed through the helper's advisory path: harness image build was cached, the runner exited `1`, the helper exited `0`, and artifacts were preserved under `artifacts/interop-runner/20260429-170106187-server-nginx/` after the upstream post-check failed |
| `gh run watch 25145021654 --repo incursa/quic-dotnet --exit-status` | Passed on 2026-04-30: hosted workflow `Interop Runner Handshake` completed in 1m53s on commit `e6dcbb80`; the run used Node 24-compatible Python setup and artifact upload actions, uploaded the runner bundle, and had no Node.js deprecation log hits |
| `gh run watch 25145022368 --repo incursa/quic-dotnet --exit-status` | Passed on 2026-04-30: hosted `Library Fast Quality` workflow completed in 1m13s on commit `e6dcbb80` after its artifact upload action moved to the Node 24-compatible major |
| `gh run watch 25146253564 --repo incursa/quic-dotnet --exit-status` | Passed on 2026-04-30: hosted `CI` workflow completed `build-test-pack` in 2m28s on commit `c26008e7` |
| `gh run watch 25146253205 --repo incursa/quic-dotnet --exit-status` | Passed on 2026-04-30: hosted `CodeQL` workflow completed `actions` and `csharp` analysis jobs on commit `c26008e7` |
| `gh run watch 25147850307 --repo incursa/quic-dotnet --exit-status` | Passed on 2026-04-30: hosted `CI` workflow completed `build-test-pack` in 2m36s on commit `7df0d60d` |
| `gh run watch 25147850047 --repo incursa/quic-dotnet --exit-status` | Passed on 2026-04-30: hosted `CodeQL` workflow completed on commit `7df0d60d` |
| `gh run watch 25147993693 --repo incursa/quic-dotnet --exit-status` | Passed on 2026-04-30: hosted `CI` workflow completed `build-test-pack` in 2m33s on commit `16e575e4` |
| `gh run watch 25147993402 --repo incursa/quic-dotnet --exit-status` | Passed on 2026-04-30: hosted `CodeQL` workflow completed on commit `16e575e4` |
| `gh run watch 25149446012 --repo incursa/quic-dotnet --exit-status` | Passed on 2026-04-30: hosted `CI` workflow completed `build-test-pack` in 3m4s on commit `b03f879e` |
| `gh run watch 25149445624 --repo incursa/quic-dotnet --exit-status` | Passed on 2026-04-30: hosted `CodeQL` workflow completed on commit `b03f879e` |
| `gh run watch 25149650001 --repo incursa/quic-dotnet --exit-status` | Passed on 2026-04-30: hosted `CI` workflow completed `build-test-pack` in 2m29s on commit `88a3172e` |
| `gh run watch 25149649726 --repo incursa/quic-dotnet --exit-status` | Passed on 2026-04-30: hosted `CodeQL` workflow completed on commit `88a3172e` |
| `gh run watch 25149821476 --repo incursa/quic-dotnet --exit-status` | Passed on 2026-04-30: hosted `CI` workflow completed `build-test-pack` in 2m26s on commit `ee86bb13` |
| `gh run watch 25149821187 --repo incursa/quic-dotnet --exit-status` | Passed on 2026-04-30: hosted `CodeQL` workflow completed on commit `ee86bb13` |
| focused API stream-capacity filter | Passed on 2026-04-30: 48 passed, 0 failed, 0 skipped |
| focused pinned-policy API/CRT filter | Passed on 2026-04-30: 28 passed, 0 failed, 0 skipped |
| focused public API surface filter | Passed on 2026-04-30: 81 passed, 0 failed, 0 skipped |
| focused public API/CRT boundary filter | Passed on 2026-04-30 after local commit `dd73ac26`: 109 passed, 0 failed, 0 skipped |
| full `REQ_QUIC_CRT_` requirement-home filter | Passed on 2026-04-30: 304 passed, 0 failed, 0 skipped |
| full `REQ_QUIC_INT` requirement-home filter | Passed on 2026-04-30 after local commit `dd73ac26`: 72 passed, 0 failed, 0 skipped |
| focused diagnostics CRT filter | Passed on 2026-04-30: 4 passed, 0 failed, 0 skipped |
| `QuicDiagnosticsBenchmarks` Dry run | Passed on 2026-04-30: 4 benchmarks executed; disabled no-op/guarded paths allocated 0 B and enabled typed-event construction allocated 192 B |
| focused endpoint-host shell INT filter | Passed on 2026-04-30: 8 passed, 0 failed, 0 skipped |
| focused harness-foundation INT filter | Passed on 2026-04-30: 11 passed, 0 failed, 0 skipped |
| focused CRT deadline-scheduler filter | Passed on 2026-04-30: 12 passed, 0 failed, 0 skipped |
| focused CRT endpoint-ingress filter | Passed on 2026-04-30: 20 passed, 0 failed, 0 skipped |
| focused CRT high-density execution filter | Passed on 2026-04-30: 18 passed, 0 failed, 0 skipped |
| focused RFC 8999 packet-invariant filter | Passed on 2026-04-30: 22 passed, 0 failed, 0 skipped |
| RFC 8999 fuzz harness build/instrument/smoke | Passed on 2026-04-30: fuzz project built, `sharpfuzz` instrumented `fuzz\bin\Release\net10.0\Incursa.Quic.dll`, and stdin smoke through `Incursa.Quic.Fuzz.dll` exited 0 |
| `QuicHeaderParsingBenchmarks` Dry run | Passed on 2026-04-30: 9 benchmarks executed; BenchmarkDotNet reported expected Dry minimum-iteration-time warnings |
| focused RFC 9000 transport filter | Passed on 2026-04-30: 1,682 passed, 0 failed, 0 skipped |
| `QuicFrameCodecBenchmarks` Dry run | Passed on 2026-04-30: 12 benchmarks executed; BenchmarkDotNet reported expected Dry minimum-iteration-time warnings |
| `QuicStreamParsingBenchmarks` Dry run | Passed on 2026-04-30: 4 benchmarks executed; BenchmarkDotNet reported expected Dry minimum-iteration-time warnings |
| `QuicVariableLengthIntegerBenchmarks` Dry run | Passed on 2026-04-30: 8 benchmarks executed; BenchmarkDotNet reported expected Dry minimum-iteration-time warnings |
| focused RFC 9001 packet-protection/TLS helper filter | Passed on 2026-04-30: 323 passed, 0 failed, 0 skipped |
| `QuicInitialPacketProtectionBenchmarks` Dry run | Passed on 2026-04-30: 3 benchmarks executed; BenchmarkDotNet reported expected Dry minimum-iteration-time warnings |
| `QuicHandshakePacketProtectionBenchmarks` Dry run | Passed on 2026-04-30: 10 benchmarks executed; BenchmarkDotNet reported expected Dry minimum-iteration-time warnings |
| `QuicRetryIntegrityBenchmarks` Dry run | Passed on 2026-04-30: 4 benchmarks executed; BenchmarkDotNet reported expected Dry minimum-iteration-time warnings |
| `QuicAeadUsageLimitCalculatorBenchmarks` Dry run | Passed on 2026-04-30: 4 benchmarks executed; BenchmarkDotNet reported expected Dry minimum-iteration-time warnings |
| focused RFC 9001 repeated key-update lifecycle filter | Passed on 2026-04-30 after local commit `df0414f3`: 229 passed, 0 failed, 0 skipped |
| focused RFC 9002 recovery/congestion filter | Passed on 2026-04-30: 576 passed, 0 failed, 0 skipped |
| focused CRT migration path-state verification-artifact filter | Passed on 2026-04-30: 9 passed, 0 failed, 0 skipped |
| focused CRT migration direct requirement filter | Passed on 2026-04-30: 6 passed, 0 failed, 0 skipped |
| focused handshake/`HANDSHAKE_DONE`/wide-epoch guard | Passed on 2026-04-30: 256 passed, 0 failed, 0 skipped |
| focused S13P2P1 ACK packet-composition filter | Passed on 2026-04-30: 29 passed, 0 failed, 0 skipped |

BenchmarkDotNet reported expected evidence-quality warnings in these smoke
lanes, including Dry minimum-iteration-time warnings and Short zero-measurement
warnings for trivial helper methods. Treat the benchmark results as preserved
local evidence that the benchmark suites execute, not as a rigorous public
performance comparison.

## Trace Surface

The QUIC trace corpus is now green under the repo-local core validation path.
Canonical SpecTrace artifacts are JSON-first; generated summaries and
documentation remain derived surfaces.

Current artifact inventory:

| Surface | Count |
|---|---:|
| Requirement specs in `specs/requirements/quic` | 7 |
| Requirement clauses | 1,949 |
| Architecture artifacts | 104 |
| Work-item artifacts | 105 |
| Verification artifacts | 106 |

Requirement family counts:

| Family | Requirement clauses |
|---|---:|
| `SPEC-QUIC-API` | 16 |
| `SPEC-QUIC-CRT` | 148 |
| `SPEC-QUIC-INT` | 14 |
| `SPEC-QUIC-RFC8999` | 8 |
| `SPEC-QUIC-RFC9000` | 1,443 |
| `SPEC-QUIC-RFC9001` | 96 |
| `SPEC-QUIC-RFC9002` | 224 |

Status summary across architecture, work-item, and verification JSON artifacts:

| Artifact type | Passed or implemented | Planned or draft |
|---|---:|---:|
| Architecture | 104 implemented | 0 draft |
| Work items | 105 complete | 0 planned |
| Verification | 106 passed | 0 planned |

## Implementation State

The implementation is beyond scaffolding. The solution contains:

- [`src/Incursa.Quic`](../src/Incursa.Quic): packable managed QUIC library.
- [`src/Incursa.Quic.Qlog`](../src/Incursa.Quic.Qlog): qlog adapter package.
- [`src/Incursa.Quic.InteropHarness`](../src/Incursa.Quic.InteropHarness): local interop-runner companion process.
- [`tests/Incursa.Quic.Tests`](../tests/Incursa.Quic.Tests): requirement-home and integration proof corpus.
- [`benchmarks/Incursa.Quic.Benchmarks`](../benchmarks): BenchmarkDotNet suites.
- [`fuzz/Incursa.Quic.Fuzz`](../fuzz): fuzz harness project.

The current honest support boundary is narrow:

- Public facade and core option/error/stream types exist.
- Managed loopback connect/listen and narrow stream open/accept behavior exist.
- Narrow write/completion, abort, stream-capacity, retry replay, packet
  protection, recovery, and selected TLS/trust floors are implemented and
  traced.
- Interop harness dispatch exists for `handshake`, `post-handshake-stream`,
  `keyupdate`, `multiconnect`, `resumption`, `retry`, and `transfer`, with
  local requirement-home and integration proof now green for the documented
  supported cells.
- Internal repeated 1-RTT key-update lifecycle proof is closed for the bounded
  moving-window runtime model, including wide internal epoch identifiers, but
  this remains outside the public support promise.
- Hosted CI and CodeQL workflows passed on `main` for the latest
  hosted-validated runtime/trace commit `ee86bb13` (`25149821476` and
  `25149821187`).
- A manual hosted GitHub Actions lane runs the server-role `handshake` helper
  cell against quic-go and uploads the complete interop-runner artifact tree
  for advisory review. Run `25145021654` passed on 2026-04-30 for commit
  `e6dcbb80` after the workflow moved its repo-controlled Python setup and
  artifact upload actions to Node 24-compatible majors; the log had no Node.js
  deprecation hits.
- The same manual hosted workflow now exposes an opt-in `supported-subset`
  profile for the already-supported helper cells: same-slot `retry`, split-role
  `transfer`, and client-role `multiconnect` through the runner
  `handshakeloss` mapping. Local dry-run planning, requirement-home tests,
  SpecTrace core validation, and Workbench core validation passed for the
  profile on 2026-04-30; hosted execution of that wider profile has not yet
  been collected.
- The manual Library Fast Quality workflow passed on run `25145022368` at
  commit `e6dcbb80` after its artifact upload action moved to the
  Node 24-compatible major.

Do not claim broad QUIC support, broad public early-data support, broad key
update support, public API stability beyond the traced facade, or broad interop
readiness from this state.

## Remaining Work

There are no known red clusters in the current local full test, core trace,
hosted CI, or hosted CodeQL baseline. Remaining work should be selected from
explicit requirements and gap records, not inferred from the green baseline.

The next useful lanes are:

- Use `specs/generated/quic/quic-requirement-coverage-triage.*` as the
  current selection surface. The canonical/generated trace gate is repaired,
  and older per-slice count snapshots in this file are historical notes.
- If the goal is fast trace-clean burn-down, continue with the 55 metadata-only
  missing-xref requirements, for example `REQ-QUIC-RFC9000-S19P16-0011`,
  `REQ-QUIC-RFC9000-S20P1-0002`, and
  `REQ-QUIC-RFC9000-S21P12-0001`.
- If the goal is harder protocol proof, start with the 221 new-test-needed
  requirements or the 45 partially-covered requirements, for example
  `REQ-QUIC-RFC9000-S10P2P1-0006`,
  `REQ-QUIC-RFC9000-S10P2P1-0009`, or
  `REQ-QUIC-RFC9000-S12P3-0007`.
- Resolve the 54 blocked requirements only through the recorded gap families,
  notably connection close, stateless reset, migration/path-validation, and
  RFC 9001 TLS/packet-space work.
- Dispatch and inspect the opt-in hosted `supported-subset` interop profile
  when a fresh hosted artifact refresh is needed; current local proof covers
  the workflow shape and helper plans, while hosted evidence still covers only
  the server-role `handshake` cell against quic-go.
- Install Wireshark packet-analysis tools locally, or use the hosted workflow
  that installs them, before attempting additional non-DryRun local
  interop-runner cells.
- Narrow public-surface hardening only where the existing API requirements
  already authorize it.
- Additional fuzz and benchmark evidence for any newly touched wire-facing or
  hot-path code.
- No known red local executable clusters remain in the current core QUIC
  artifact set. The RFC 9002 recovery/congestion front door, migration-core
  path-state decomposition front, handshake-orchestration umbrella, and ACK
  piggyback proof-tail are closed for their current repository-owned proof
  surfaces. Future work should still be selected from explicit generated
  triage and gap records, including hosted interop expansion, public-surface
  hardening, 0-RTT receive/anti-replay, concrete future path-migration matrix
  cells, or newly discovered behavior gaps. The internal repeated key-update
  lifecycle and epoch-cap slices are closed, but they are not broad public
  key-update support claims.

When starting a new protocol slice, follow
[`docs/requirements-workflow.md`](requirements-workflow.md), inspect
[`specs/requirements/quic/REQUIREMENT-GAPS.md`](../specs/requirements/quic/REQUIREMENT-GAPS.md),
and use the owning `SPEC-...`, `ARC-...`, `WI-...`, and `VER-...` artifacts
before editing code.
