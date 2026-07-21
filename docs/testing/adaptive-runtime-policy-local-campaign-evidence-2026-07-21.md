---
title: "Adaptive Runtime Local Campaign Evidence - 2026-07-21"
---

# Adaptive Runtime Local Campaign Evidence - 2026-07-21

Status: local gate not cleared; rack-lab submission not eligible

This record extends the shadow-foundation evidence with the first permanent
forced-policy local campaign work. It remains diagnostic and non-promoting.
No active controller, online learning, public adaptive-policy API, package
upload, or ProtocolLab controller job was created.

## Implemented Checkpoints

- `2890ef58` exposes internal-only connection options for
  `legacy_current`, `immediate`, `read_dominant_batch`, and `shadow`, applies
  them exactly once before connection admission, and forwards the selected
  value through the source-backed raw QUIC campaign host.
- `90670a25` adds the permanent ABBA/BAAB local cell runner, frozen-binary
  checks, append-only output roots, schema-v1 result emission, manifests,
  commands, raw artifacts, and checksum inventories.
- `b2d4b197` rejects scenario-declared stream or payload mismatches before the
  first sample and fixes result-note serialization.
- `edb48adb` resolves the authoritative inner campaign-host stdout through the
  adapter artifact contract and copies it into the permanent cell root.
- `448ccfad` treats any throughput or p95 within-treatment relative range over
  five percent as `invalid_environment` and classifies against the explicit
  `legacy_current` baseline regardless of A/B order.

The controls remain internal to friend assemblies. The public API baseline
did not change. Forced modes bypass selector eligibility only; the existing
progress, terminal, flow-control, ownership, and saturation guards remain in
force. Shadow continues to apply `legacy_current` and has no behavior consumer.

## Retained Cohorts

All roots below are append-only under `.artifacts/adaptive-runtime`. Earlier
invalid results were not deleted or rewritten after the runner was corrected.

| Campaign | Cell | Stored classification | Review disposition |
| --- | --- | --- | --- |
| `adaptive-receive-credit-20260721-local1` | `sustained-upload-1kb-c16` | `invalid_contract` | The named scenario declares one stream while the cell requested 16. All four commands stopped before workload execution. The result also retains the original nested-note schema failure. |
| `adaptive-receive-credit-20260721-local2` | `duplex-64kb-c16` | `invalid_contract` | The result is schema-valid, but the first runner inspected outer adapter stdout instead of the authoritative inner host log. One legacy sample also had a load-tool failure. Not usable for a policy claim. |
| `adaptive-receive-credit-20260721-local3` | `duplex-64kb-c16` | `neutral_local` | All four samples were correct and authoritative logs matched their forced modes. The then-current classifier did not yet reject within-treatment variance. Manual review found a maximum p95 relative range of about 16.2 percent, so this immutable row is not accepted or promotable. |
| `adaptive-receive-credit-20260721-local4` | `duplex-64kb-c16` | `invalid_environment` | All four samples passed exact payload, shape, timeout, and protocol checks. Maximum within-treatment range was 22.84 percent, so the apparent 9.46 percent throughput improvement and 14.06 percent p95 improvement are not credited. |
| `adaptive-receive-credit-20260721-local5` | `upload-1mb-c1` | `invalid_environment` | All four low-cardinality samples passed exact payload, shape, timeout, and protocol checks. Maximum within-treatment range was 23.30 percent, so the 3.52 percent throughput difference and apparent p95 improvement are not credited. |

The last two cohorts prove that the conservative classifier retains correct
but noisy measurements rather than converting workstation variance into a
policy claim. They do not show a correctness regression, and they also do not
clear either the target or sparse guardrail.

## Artifact Identities

| Campaign | Result SHA-256 | Manifest SHA-256 | Checksum inventory SHA-256 |
| --- | --- | --- | --- |
| `local1` | `1c97040e2f4a153358cb15a15493c591d04411896bc4b8d15a5bf7a10f102359` | `8d61ffe7d5bb7f7a5ca2dc08d520b4ef9dbc6ffcb468f4216cab7b64de075059` | `f149cdcea45d4913a5d053eb82da03b308cf092dbfc51027115e38e906c9f556` |
| `local2` | `863da0028c6847c51df55b7709eecbc7d25da2ba568831f0e1fa90e304273763` | `a66c42495e2dcdc238261a8981874f8e0ea53e78d72adf36deca2ff447fbe833` | `df78e1e69cc163bcaef3911047f7d18beb41aecf885723c12e60a62efdae093d` |
| `local3` | `a5e4505161922bd9d2df1d96f96d452a920edb1641860a6f352ee6961b2ed1d7` | `e4f25c01e7c4c81eb245ec319324cdde2f236aab02ceb633cadbd1fc2d10ede2` | `3579c890f014ed0c0c8129f65a13d79adcd9b89d71fcb049948d54a996514065` |
| `local4` | `ab869bb836cf6dacc1619aa7724e4eeb2d15aa8d6b7280f7a03e2e0c2b5285d1` | `e8cf47b0ce76168122b6b4350b5f0388abba823044783cbc7d382dadd1150561` | `9404ff07c4509756c620d4644382328369881fc33aa95673542d91031883a089` |
| `local5` | `ed099b5caa8698abcdd0e52c63eb65b217d3d457609d8b9250d664f1a004412f` | `6ec8d6c025f35880aeaf898fcee3a942fbeb1e3244d9b503ad2a47074cc905b5` | `647c5c1be0b6bd39819a064445f8a403f94d5d860c974aff87fd848b2b4a0229` |

The `local2` through `local5` result documents validate against
`adaptive-runtime-policy-local-result-v1`. A fresh hash audit of all 120
artifacts referenced by those four results reported zero missing files and
zero mismatches. `local1` intentionally retains its original invalid result
document and is excluded from schema-valid evidence.

## Verification

- `Incursa.Quic` Release build: passed, zero warnings and errors.
- `IncursaRawQuicServer` Release build: passed, zero warnings and errors.
- Final `REQ-QUIC-CRT-0164` through `REQ-QUIC-CRT-0169` run: 38 passed,
  zero failed, zero skipped.
- Public API requirement guards: 13 passed.
- ProtocolLab package-template guards: 22 passed.
- Unset, `legacy_current`, `immediate`, `read_dominant_batch`, and `shadow`
  host startup smoke: all reported the requested mode; an invalid value was
  rejected before listening.

The earlier complete Release-suite results and isolated HTTP/3 and DoQ reruns
remain recorded in
[`adaptive-runtime-policy-shadow-foundation-evidence-2026-07-21.md`](adaptive-runtime-policy-shadow-foundation-evidence-2026-07-21.md).
This campaign did not reinterpret those retained suite-load sensitivities.

## Gate Decision

The local gate is not cleared. The reviewed campaign contract requires stable
matched local evidence before a ProtocolLab proposal. The controller at
`http://10.10.99.176:5088` was reachable by read-only probes on 2026-07-21,
but no upload, package mutation, or job was submitted because the local
environment gate failed.

Next work must stay evidence-oriented: improve or isolate local host stability,
repeat required sparse, target, neighboring, and retained-negative cells under
the same contracts, add end-to-end shadow epoch capture and join validation,
and review the complete local evidence. It must not widen the selector, enable
`active_internal`, begin online learning, or treat the noisy apparent gains as
accepted tuning evidence.
