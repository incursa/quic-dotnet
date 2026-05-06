# Current Repository Status

Last verified: 2026-05-06 for the S7P4P1 client 0-RTT updated
transport-parameter packet-use policy, S7P4P1 client 0-RTT handshake-value
supersession policy, S7P4P1 server 0-RTT transport-parameter acceptance
policy, S7P4P1 client 0-RTT remembered transport-parameter policy, S18P2
max_ack_delay alarm-slack policy, S18P2 max_udp_payload_size receiver limit,
S18P2 initial_max_data runtime commit, S18P2 max_idle_timeout trace cleanup,
S22P1P1 provisional-registration policy closeout, S18P2 preferred-address
field-shape, disable-active-migration, and initial stream-count transport
parameter closeouts, the S17P2P5P2/P3 Retry client processing closeout, and
the adjacent S7P3 transport-parameter connection-ID authentication closeout;
broader executive-read evidence remains pinned to its stated 2026-04-30
refresh unless otherwise noted.

This page is an operator snapshot. It records the current repo state and the
next recommended work lane, but it does not replace the canonical requirements,
architecture, work items, or verification artifacts under `specs/`.

## 2026-05-06 Restart Note

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
| Architecture artifacts | 102 |
| Work-item artifacts | 103 |
| Verification artifacts | 104 |

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
| Architecture | 102 implemented | 0 draft |
| Work items | 103 complete | 0 planned |
| Verification | 104 passed | 0 planned |

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
  `multiconnect`, `retry`, and `transfer`, with local requirement-home and
  integration proof now green.
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
- No known planned or draft trace artifacts, stale open local proof-tail gaps,
  or red local executable clusters remain in the current core QUIC artifact
  set. The RFC 9002 recovery/congestion front door, migration-core
  path-state decomposition front, handshake-orchestration umbrella, and ACK
  piggyback proof-tail are closed for their current repository-owned proof
  surfaces. Future work should be selected from explicit gap records such as
  hosted interop expansion, public-surface hardening, 0-RTT receive/anti-replay,
  concrete future path-migration matrix cells, or newly discovered behavior
  gaps. The internal repeated key-update lifecycle and epoch-cap slices are
  closed, but they are not broad public key-update support claims.

When starting a new protocol slice, follow
[`docs/requirements-workflow.md`](requirements-workflow.md), inspect
[`specs/requirements/quic/REQUIREMENT-GAPS.md`](../specs/requirements/quic/REQUIREMENT-GAPS.md),
and use the owning `SPEC-...`, `ARC-...`, `WI-...`, and `VER-...` artifacts
before editing code.
