# Incursa.Quic Interop Prep Plan

This is a planning artifact only. It does not widen the supported public promise or add production behavior.

Source of truth for this plan:

- `docs/design/quic-public-api.md`
- `docs/design/quic-public-api-gap-matrix.md`
- `docs/reviews/quic-tls-handshake-walkthrough.md`
- `specs/requirements/quic/REQUIREMENT-GAPS.md`
- `specs/requirements/quic/SPEC-QUIC-API.json`
- `specs/requirements/quic/SPEC-QUIC-CRT.json`
- the current requirement-home tests

The current narrow supported slice is real. The remaining work is about keeping the public promise truthful while the deeper runtime, TLS, stream, and interop surfaces catch up.

## Remaining-Work Buckets

### 1. Public-Surface Truthfulness And Freeze

Supported today:

- The approved public facade described in `SPEC-QUIC-API` and `docs/design/quic-public-api.md`.
- Listener/client connect, positive loopback establishment, stream open/accept, narrow write/completion, narrow `RESET_STREAM` / `STOP_SENDING` abort, the `IsSupported` marker, and the narrow stream-capacity callback subset.

Partially implemented but not yet promised:

- Internal runtime, stream-state, TLS bridge, and endpoint-host seams that already back the narrow slice.
- More complete connection/runtime facts that exist internally but are intentionally hidden behind the current facade.

Still missing:

- Any broader public promise beyond the current narrow loopback and stream slice.
- A decision to expose richer connection metadata or broader TLS/client-auth options before the underlying runtime and validation work is stable.

Why this stays separate:

- The current public contract should stay frozen until the deeper runtime and TLS work is stable enough to support any broader promise without backtracking.

### 2. Broader Stream-Management Parity

Supported today:

- Narrow stream-entry support on the active loopback path.
- Supported write/completion on send-capable streams.
- Narrow `Abort(QuicAbortDirection.Read, ...)` / `Abort(QuicAbortDirection.Write, ...)` support.
- Initial peer stream-capacity reporting, later real peer `MAX_STREAMS` growth, and the narrow close-driven capacity-release subset already proven by the requirement-home tests.

Partially implemented but not yet promised:

- Internal stream registry, flow-control, final-size, and close/release plumbing already exist behind the facade.
- The current narrow callback and stream-state machinery can already support the supported slice, but not a broader contract.

Still missing:

- `Abort(Both, ...)`.
- Broader abort-heavy behavior.
- Broader close-driven capacity release and fuller stream lifecycle parity.

Why this stays separate:

- Transfer-oriented work and any future widening of the stream contract depend on this bucket being honest first.

### 3. Transport / Runtime Cleanup

Supported today:

- The connection runtime already owns phase, close/drain, timers, stream registry coordination, send/recovery ownership, and the current supported loopback handshake path.
- The handshake-flow and TLS bridge seams already exist internally and are test-backed.
- The server-role 1-RTT publication floor and the client-role post-Finished 1-RTT readiness seam are now proven internally.

Partially implemented but not yet promised:

- Endpoint-host and runtime bootstrap plumbing that can already be exercised by the shell tests, but not yet by a fully honest interop runner path.

Still missing:

- A stable interop-facing bootstrap story for Initial/DCID handling on the runner path.
- Enough runtime cleanup to treat the current handshake floor as stable instead of partially proven.
- Broader sender/recovery and diagnostics ownership that the interop harness still depends on.

Why this stays separate:

- The current broader API+CRT requirement-home pass still shows red areas in the handshake floor, so this bucket must be stabilized before interop work can claim more than a narrow shell.

### 4. TLS / Policy / Trust / Validation

Supported today:

- Narrow TLS 1.3 proof slices.
- The explicit pinned-leaf acceptance seam.
- The reject-first supported subset of client TLS options already described in the public API docs.

Partially implemented but not yet promised:

- The managed proof and commit gates that already separate transcript progression from local policy acceptance and peer transport-parameter commit.
- The current server-role proof floor, including the local handshake-flight pieces already recorded in the CRT requirement homes.

Still missing:

- Trust-store policy.
- Hostname and identity validation.
- Certificate-path validation.
- Revocation handling.
- Broader client-auth or TLS-option support.
- `0-RTT`.
- Key update.

Why this stays separate:

- The current client policy story is still narrow and explicit. It should not be widened until the repo can prove a broader trust story honestly.

### 5. Interop-Runner Enablement

Supported today:

- The thin endpoint-host shell around the library runtime.
- Honest unsupported testcase behavior that returns `127` for `transfer` and `retry`.
- The shell-level requirement-home coverage for the connected UDP boundary.
- The managed client/listener host path already owns honest Initial/DCID bootstrap and server Initial-response emission.
- The harness `handshake` testcase already routes into that managed bootstrap path.

Partially implemented but not yet promised:

- A real socket boundary that can already surface outbound handshake datagrams through the library-owned runtime shell.
- The internal plumbing needed to drive a testcase without pretending the runner is already complete.

Still missing:

- Testcase enablement for `transfer` and `retry`.
- Runner-side testcase dispatch.
- Honest end-to-end interop-visible `transfer` and `retry` execution.

Why this stays separate:

- The harness should keep returning `127` for unsupported testcases until it can dispatch into the real endpoint-host path; the managed bootstrap path is already proven for handshake.

## Recommended Execution Order

1. Freeze the public promise and stabilize the current handshake/runtime proof floor.
2. Clean up transport/runtime bootstrap, especially the runner-facing Initial/DCID path and the endpoint-host seams.
3. Tighten TLS / policy / trust / validation on top of the stable handshake floor.
4. Finish broader stream-management parity, including the remaining abort and close/release behavior.
5. Enable interop-runner testcase dispatch only after the runtime, TLS, and stream buckets above are stable enough to support it honestly.

Notes on dependency:

- Step 2 is the prerequisite for the rest of the interop-prep sequence.
- Steps 3 and 4 can run in either order once step 2 is stable, but neither should be treated as complete enough for step 5 until both are green.
- Any public-surface widening should stay frozen until the runtime, TLS, and stream buckets above are no longer red in the broader requirement-home runs.

## Next Concrete Slices

1. `Transfer-owned completion contract`
   - Goal: keep the first honest `transfer` slice traceable under `REQ-QUIC-INT-0010`, `ARC-QUIC-INT-0003`, `WI-QUIC-INT-0003`, and `VER-QUIC-INT-0003`.
   - Focus: the transfer-owned child-process completion rule, including one stream, one `REQUESTS` URL, one `/www` to `/downloads` mapping, and byte-delivery-plus-EOF proof on the existing managed Active-phase path.
   - Current blocker: the runtime primitives are already present on the managed active path; the missing piece is one explicit application-protocol and ALPN pairing plus matching child-process proof.
   - Depends on: the client-role 1-RTT readiness seam and the current narrow stream slice staying stable.

2. `Initial/DCID bootstrap and endpoint-host cleanup`
   - Goal: make the interop-facing bootstrap path honest enough to drive a real testcase entry instead of a shell-only path, building on the already-proven managed client/listener bootstrap seam.
   - Focus: runner-facing Initial/DCID handoff, endpoint-host integration, and any remaining runtime bootstrap cleanup that blocks runner entry.
   - Depends on: the current handshake/runtime proof floor and the client-role 1-RTT readiness seam.

3. `TLS trust/policy/validation`
   - Goal: decide and implement the next honest trust-policy step without claiming a broader client-auth story than exists.
   - Focus: trust-store policy, hostname/identity validation, certificate-path validation, and the boundaries around the current reject-first client options.
   - Depends on: the current handshake/runtime proof floor and the client-role 1-RTT readiness seam.

4. `Broader stream-management parity`
   - Goal: close the remaining stream lifecycle gap so transfer-oriented work has a truthful contract.
   - Focus: `Abort(Both, ...)`, broader abort-heavy behavior, and remaining close-driven capacity-release parity.
   - Depends on: the client-role 1-RTT readiness seam and the current narrow stream slice staying stable.

5. `Interop runner dispatch`
   - Goal: route `transfer` and `retry` into the real endpoint-host path instead of returning `127`.
   - Focus: testcase enablement, runner-side bootstrap, and honest end-to-end dispatch after the transfer-owned application pairing and proof are fixed. `handshake` is already wired into the managed bootstrap path.
   - Depends on: the transfer-owned completion contract slice, the client-role 1-RTT readiness seam, the TLS trust/policy slice, and any stream follow-ons that prove inseparable from the chosen transfer pairing.

## Do-Not-Widen Boundaries

- Keep `QuicConnection` and `QuicListener` on the current narrow supported promise until the runtime and TLS buckets are stable.
- Keep `IsSupported` as a narrow managed capability marker. It must not become a feature-completeness claim.
- Keep `Abort(Both, ...)` unsupported.
- Keep `0-RTT` and key update out of the public promise.
- Keep broader stream-management parity out of the public promise until the stream bucket is actually closed.
- Keep hostname validation, trust-store validation, and certificate-path validation out of the public client promise until they are implemented and proven.
- Keep interop runner testcase support at `127` for unsupported cases until the dispatch and bootstrap path is real.

## Current Unstable Areas Before Interop Continues

- The handshake-floor tail slice for `REQ-QUIC-CRT-0117` and `REQ-QUIC-CRT-0119` is now closed.
- The client-role 1-RTT readiness prerequisite under `REQ-QUIC-CRT-0121` is now closed.
- The interop harness still returns `127` for `transfer` and `retry`.
- The managed client/listener bootstrap seam is already proven.
- The current client trust story is still pinned-leaf only; it is not yet a broader trust-store or hostname-validation story.

## Trace Links

- Public API design: `docs/design/quic-public-api.md`
- Public API gap matrix: `docs/design/quic-public-api-gap-matrix.md`
- Handshake walkthrough: `docs/reviews/quic-tls-handshake-walkthrough.md`
- Requirement gaps: `specs/requirements/quic/REQUIREMENT-GAPS.md`
- API specification: `specs/requirements/quic/SPEC-QUIC-API.json`
- CRT specification: `specs/requirements/quic/SPEC-QUIC-CRT.json`
- Interop requirement home: `tests/Incursa.Quic.Tests/RequirementHomes/INT/REQ-QUIC-INT-0008.cs`
