# QUIC Interop Status Matrix

This is the current green / advisory / open split for the QUIC interoperability program.

If a lane row names RFC 9000 or RFC 9002 requirement IDs, reconcile those references against the derived RFC9000 crosswalk and retired-ID ledger in `specs/generated/quic` before renaming or reclassifying the row.

## What The Buckets Mean

- Green means the repo has direct proof for the lane and it can be treated as currently working within the recorded scope.
- Advisory means the repo has evidence, characterization, or proof-planning data for the lane, but that data is not a support verdict and does not count as a runtime or hosted-readiness claim.
- Still open means the lane currently has an unresolved failure or blocker that needs a real fix or a fresh proof run before it can move into Green.

## Matrix

| Lane | Status | Why It Sits There | Next Move |
| --- | --- | --- | --- |
| QUIC RFC protocol requirement coverage | Green | Generated coverage reports RFC 8999, RFC 9000, RFC 9001, and RFC 9002 as 1,771/1,771 `trace_clean`. | Keep it pinned by refreshing coverage triage when new proof lands. |
| `REQ-QUIC-INT-0027` all-upstream handshake matrix | Green | The May 19 all-upstream handshake sweep passed Incursa.Quic as client against 16/16 server-capable upstream implementations and as server against 14/14 supported client-capable upstream implementations. | Keep the handshake matrix as a bounded advisory proof lane; do not read it as every testcase against every peer. |
| `REQ-QUIC-INT-0018` `chacha20` | Green | Supported/executed in the helper inventory and confirmed by a successful local runner proof. | Keep as a stable supported cell. |
| `REQ-QUIC-INT-0021` `zerortt` | Green | Supported/executed in the helper inventory and confirmed by hosted proof. | Keep as a stable supported cell. |
| `REQ-QUIC-INT-0026` simulator baseline | Green | `SIM-QUIC-BASE-0001` passed in the local network simulator with staged Incursa.Quic client and server endpoints. | Keep baseline proof separate from deterministic loss promotion. |
| `REQ-QUIC-INT-0016` peer-characterization matrix pilot | Advisory | This reporting surface preserves mixed peer results instead of flattening them into green/red, and its generated pilot, inventory, and evidence reports (`interop-peer-characterization-matrix-pilot`, `interop-major-peer-matrix-inventory`, `interop-major-peer-matrix-evidence-25904716076`) live under `specs/generated/quic`. | Refresh from new evidence when the source bundles change. |
| `REQ-QUIC-INT-0019` major-peer matrix | Advisory | The completed major-peer run `25904716076` is preserved in the dedicated evidence report `interop-major-peer-matrix-evidence-25904716076`, but it remains characterization, not support proof. | Use it to decide which lane is actually Incursa-side before changing runtime behavior. |
| `REQ-QUIC-INT-0023` quic-go download-liveness | Green | The client download loop now completes against the known mounted source-length body instead of waiting for peer EOF. | Keep it stable and use the bounded helper as the transfer-backed completion path. |
| `REQ-QUIC-INT-0024` msquic peer-blocked evidence | Advisory | The preserved failures are peer-side TLS alert 50 / termination noise, so this is blocked evidence rather than an Incursa defect. | Keep it classified, but do not spend local runtime time unless new evidence changes the attribution. |
| `REQ-QUIC-INT-0025` connectionmigration source-address proof | Green | Hosted run `26174181713` passed the `connectionmigration-server-proof` profile at commit `9ee3266e`, with `runner-report.json` recording `connectionmigration` as `succeeded`, completed 2 MiB transfer, original and preferred server paths observed, qlog-backed PATH_CHALLENGE/PATH_RESPONSE evidence, and active-migration DCID change. | Keep this bounded to `connectionmigration`; do not promote `rebind-port`, `rebind-addr`, QUIC v2, or HTTP/3 from this proof. |
| `SIM-QUIC-LOSS-0001` deterministic simulator loss | Green | `VER-QUIC-INT-0020` accepts the completed local evidence-preserved run under `.artifacts/network-simulator-live/SIM-QUIC-LOSS-0001/20260522T060348Z` with `--drops_to_server=41`; the helper preserved current-run qlog/pcap evidence under `simulator-logs/`, the client completed the transfer, and the review accepts the run as bounded deterministic-loss proof for the mapped RFC 9002 requirements. | Keep this bounded to the accepted deterministic-loss proof; do not promote hosted workflow coverage, rebind/migration scenarios, cross-traffic performance results, or broad simulator-matrix support from it. |

## Practical Reading

- You should not read `Advisory` as "good enough."
- You should read `Advisory` as "useful evidence, but not a support claim."
- If a lane is still open, it is still work.
- If a lane is green, it is the only part of the matrix that can be treated as currently working within scope.
