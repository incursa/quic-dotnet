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
- The public `QuicClientConnectionOptions.PeerCertificatePolicy` plus `QuicPeerCertificatePolicy` carrier for exact peer leaf DER and explicit trust-material SHA-256, feeding the existing internal exact-match snapshot.
- The reject-first supported subset of client TLS options already described in the public API docs.

Partially implemented but not yet promised:

- The managed proof and commit gates that already separate transcript progression from local policy acceptance and peer transport-parameter commit.
- The internal exact peer-identity and explicit trust-material snapshot seam that backs the public carrier.
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
- The narrow child-process transfer slice on the managed active-phase path.
- The narrow child-process `retry` slice on the managed one-Retry replay path.
- Honest unsupported testcase behavior that returns `127` for any other unsupported testcase.
- The shell-level requirement-home coverage for the connected UDP boundary.
- The managed client/listener host path already owns honest Initial/DCID bootstrap and server Initial-response emission.
- The harness `handshake` testcase already routes into that managed bootstrap path.

Partially implemented but not yet promised:

- A real socket boundary that can already surface outbound handshake datagrams through the library-owned runtime shell.
- The internal plumbing needed to drive a testcase without pretending the runner is already complete.

Still missing:

- Runner-side testcase dispatch.
- Honest end-to-end interop-visible dispatch for the remaining unsupported interop testcases.

Why this stays separate:

- The harness should keep returning `127` for unsupported testcases other than the narrow supported `retry` contract until it can dispatch into the real endpoint-host path; the managed bootstrap path is already proven for handshake, post-handshake stream open/accept, the narrow transfer slice, and the child-process retry slice.

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

1. `Post-handshake stream open/accept prerequisite`
   - Goal: keep the smaller post-handshake stream open/accept prerequisite traceable under `REQ-QUIC-INT-0011`, `ARC-QUIC-INT-0004`, `WI-QUIC-INT-0004`, and `VER-QUIC-INT-0004`.
   - Focus: the child-process-only `post-handshake-stream` testcase, the first application-stream open after handshake completion, and peer accept on the same managed harness path.
   - Status: landed. The managed client/listener handshake floor and the server receive-path 1-RTT admission seam are now sufficient for the first application-stream open and peer accept on the same harness path.
   - Depends on: the client-role 1-RTT readiness seam and the current narrow stream slice staying stable.

2. `Transfer-owned completion contract`
   - Goal: keep the first honest `transfer` slice traceable under `REQ-QUIC-INT-0010`, `ARC-QUIC-INT-0003`, `WI-QUIC-INT-0003`, and `VER-QUIC-INT-0003`.
   - Focus: the transfer-owned child-process completion rule, including one stream, one `REQUESTS` URL, one `/www` to `/downloads` mapping, and byte-delivery-plus-EOF proof on the existing managed Active-phase path.
   - Status: landed. The runtime primitives were already present on the managed active path, the explicit application-protocol and ALPN pairing is now wired, and the child-process proof closes the narrow file-pump contract.
   - Depends on: the client-role 1-RTT readiness seam and the current narrow stream slice staying stable.

3. `Retry bootstrap ownership`
   - Goal: keep the library-owned one-Retry replay seam honest before any interop dispatch attempt.
   - Focus: original destination connection ID retention, Retry token replay, `retry_source_connection_id` binding validation, and the current client/listener bootstrap path.
   - Status: landed. The runtime already classifies Retry and carries the helper math, and the one-Retry bootstrap handoff now retains the original destination connection ID, retains the Retry token, validates `retry_source_connection_id`, and reissues the next Initial through the real managed path.
   - Depends on: the client-role 1-RTT readiness seam and the current Initial/DCID bootstrap path staying stable.

4. `Initial/DCID bootstrap and endpoint-host cleanup`
   - Goal: make the interop-facing bootstrap path honest enough to drive a real testcase entry instead of a shell-only path, building on the already-proven managed client/listener bootstrap seam.
   - Focus: runner-facing Initial/DCID handoff, endpoint-host integration, and any remaining runtime bootstrap cleanup that blocks runner entry.
   - Depends on: the current handshake/runtime proof floor and the client-role 1-RTT readiness seam.

5. `TLS trust/policy/validation`
   - Goal: keep the landed public client-policy carrier aligned with the internal snapshot and exact-match floor.
   - Focus: the public carrier shape for explicit pinned peer identity and explicit trust material, the exact snapshot handoff, and the boundaries around the current reject-first client options.
   - Status: landed. The public carrier now exists and feeds the internal snapshot/fail-closed bridge seam, while the broader trust-policy story stays out of scope.
   - Depends on: the current handshake/runtime proof floor and the client-role 1-RTT readiness seam.

6. `Broader stream-management parity`
   - Goal: close the remaining stream lifecycle gap so transfer-oriented work has a truthful contract.
   - Focus: `Abort(Both, ...)`, broader abort-heavy behavior, and remaining close-driven capacity-release parity.
   - Depends on: the client-role 1-RTT readiness seam and the current narrow stream slice staying stable.

7. `Interop runner dispatch`
   - Goal: route the remaining unsupported interop testcases into the real endpoint-host path instead of returning `127`.
   - Focus: testcase enablement, runner-side bootstrap, and honest end-to-end dispatch after the current proof floor is fixed. `handshake` is already wired into the managed bootstrap path, and the narrow child-process `retry` path is now handled separately.
   - Depends on: the client-role 1-RTT readiness seam, the TLS trust/policy slice, the current narrow stream slice staying stable, and any stream follow-ons that prove inseparable from the remaining cases.

## Do-Not-Widen Boundaries

- Keep `QuicConnection` and `QuicListener` on the current narrow supported promise until the runtime and TLS buckets are stable.
- Keep `IsSupported` as a narrow managed capability marker. It must not become a feature-completeness claim.
- Keep `Abort(Both, ...)` unsupported.
- Keep `0-RTT` and key update out of the public promise.
- Keep broader stream-management parity out of the public promise until the stream bucket is actually closed.
- Keep hostname validation, trust-store validation, and certificate-path validation out of the public client promise until they are implemented and proven.
- Keep interop runner testcase support at `127` for unsupported cases other than the narrow supported `retry` child-process contract.

## Current Unstable Areas Before Interop Continues

- The handshake-floor tail slice for `REQ-QUIC-CRT-0117` and `REQ-QUIC-CRT-0119` is now closed.
- The client-role 1-RTT readiness prerequisite under `REQ-QUIC-CRT-0121` is now closed.
- The smaller post-handshake stream open/accept prerequisite under `REQ-QUIC-INT-0011`, `ARC-QUIC-INT-0004`, `WI-QUIC-INT-0004`, and `VER-QUIC-INT-0004` is now closed by the managed child-process harness path.
- The narrow child-process `retry` contract under `REQ-QUIC-INT-0012`, `ARC-QUIC-INT-0005`, `WI-QUIC-INT-0005`, and `VER-QUIC-INT-0005` is now closed.
- The managed client/listener bootstrap seam is already proven.
- The current client trust story now has a public exact peer-identity and explicit trust-material carrier plus the internal snapshot seam, and the remaining trust-policy story still does not widen to trust-store or hostname-validation semantics.

## Trace Links

- Public API design: `docs/design/quic-public-api.md`
- Public API gap matrix: `docs/design/quic-public-api-gap-matrix.md`
- Handshake walkthrough: `docs/reviews/quic-tls-handshake-walkthrough.md`
- Requirement gaps: `specs/requirements/quic/REQUIREMENT-GAPS.md`
- API specification: `specs/requirements/quic/SPEC-QUIC-API.json`
- CRT specification: `specs/requirements/quic/SPEC-QUIC-CRT.json`
- Interop requirement home: `tests/Incursa.Quic.Tests/RequirementHomes/INT/REQ-QUIC-INT-0008.cs`
