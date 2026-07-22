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
- `5fbed292` adds a bounded actor-boundary shadow sink and asynchronous raw
  host export without adding a policy consumer.
- `228023be` adds controller-owned transition and dwell metadata required for
  honest epoch-row export.
- `5ed514ca` adds permanent `-ShadowOnly` capture, schema-v1 row generation,
  analysis exclusions, and result/epoch join validation.
- `20a139ee` retains the actual counter summary as pressure evidence while
  keeping same-host target and generator health conservatively `limited`.
- `bd2e045a` requires counter capture for every forced-policy sample, treats a
  missing counter summary as an invalid contract, adds resumable deterministic
  higher-count measurement schedules, and keeps stress cells non-promoting.

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
| `adaptive-shadow-20260721-local1` | `upload-1mb-c1` | `invalid_contract` | The clean-repository sample retained 13 raw epochs, but the first project-reference build after the checkpoint changed the commit-stamped frozen binary. The result is preserved and not joined as authoritative evidence. |
| `adaptive-shadow-20260721-local2` | `upload-1mb-c1` | `neutral_local` | Clean provenance, 12 schema-valid joined epochs, exact payload validation, and stable frozen hashes. This pre-pressure-path checkpoint remains diagnostic. |
| `adaptive-shadow-20260721-local3` | `upload-1mb-c1` | `neutral_local` | Clean provenance, 13 schema-valid joined epochs, exact payload validation, stable frozen hashes, and retained counter pressure evidence. Same-host target and generator health remain `limited`, so this is contract proof rather than a performance claim. |
| `adaptive-receive-credit-20260721-guardrail1` | `upload-1mb-x1-s1` | `invalid_environment` | The first post-checkpoint forced guardrail retained four counter summaries and passed exact payload, shape, timeout, protocol, and forced-mode checks. Baseline throughput repeated within 1.67 percent, but candidate throughput split between 45.59 and 4.24 MiB/s for a 165.97 percent relative range; candidate p95 also ranged by 159.47 percent. The apparent fast sample is not credited. |

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
| `shadow-local1` | `3238d4890a103ef64db58432eb62deecaa9ae0e50d7034ec90562d2e126af7d4` | `86a2a992e1173cbf7dc6fe8e821664c942ba2905b2fa9ebdcf077ac8d62e36bd` | `4d3b64aebfbfc7f15b7228710630e6db64350c7d8df34d62a6d4e55578e44734` |
| `shadow-local3` | `043814067455f3f8039ed3b9eb080e0e087b1d95d07db8099fe8a5b6e4358aef` | `7e435cb6c5d2b24f81b60a0cac3b168c6982411cb1f5f1c249d833d713fd047b` | `0117d0f77de788744b9812ab6d56043b0a8bdaa8040eceee6ec0fcc89b6d1957` |
| `guardrail1` | `eec3eb5842bdbfc3112fd652b63bf1080119a8a24d1b167be532d58c43af5326` | `1e712e1646dc2997538cb8b7eec5dd5804313b3105d44047433a6b4e28a8ad92` | `64424cd1a6c1b2464fa03036083bc5e5410eac502c24a23656e31eb43caa8d5a` |

The `local2` through `local5` result documents validate against
`adaptive-runtime-policy-local-result-v1`. A fresh hash audit of all 120
artifacts referenced by those four results reported zero missing files and
zero mismatches. `local1` intentionally retains its original invalid result
document and is excluded from schema-valid evidence.

The final `shadow-local3` evidence validation summary is schema-valid and
join-valid for 13 epoch rows; its SHA-256 is
`86692aa532bb50e34b298c3d91b20c8558d11d0b4cbe06c034ec8fd126404585`.
All 13 recommendations were `legacy_selector`, no controller transition or
stale/out-of-domain/contradictory epoch occurred, and three early epochs with
missing optional queue-delay observations remain present with explicit
analysis exclusions.

The retained counter summary reported 2,498 samples, 7.81 percent mean process
CPU, 15.10 percent maximum process CPU, and a maximum thread-pool queue length
of one. Those observations improve reviewability but do not isolate the target
from the generator and therefore do not justify upgrading either health field
or rerunning the broader forced-policy matrix as trusted evidence.

The `guardrail1` row retains one counter summary for each of its four forced
samples. The anomalous first candidate sample reported 0.33 percent mean
process CPU and 0.91 percent maximum CPU while reaching 45.59 MiB/s; the other
three samples reported roughly 9.24-9.59 percent mean CPU and 14.84-15.49
percent maximum CPU while reaching 3.95-4.24 MiB/s. This is a concrete host or
measurement-regime mismatch, not evidence for the forced policy. A fresh audit
of the 33 files in its checksum inventory found zero missing files and zero
hash mismatches.

## Verification

- `Incursa.Quic` Release build: passed, zero warnings and errors.
- `IncursaRawQuicServer` Release build: passed, zero warnings and errors.
- Final `REQ-QUIC-CRT-0164` through `REQ-QUIC-CRT-0169` run: 42 passed,
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

End-to-end shadow epoch capture and join validation are now complete for the
bounded c1 proof cell. Remaining work must stay evidence-oriented: materially
isolate local host stability, repeat required sparse, target, neighboring, and
retained-negative cells under the same contracts, and review the complete
local evidence. It must not widen the selector, enable `active_internal`, begin
online learning, or treat the noisy apparent gains as accepted tuning evidence.

The post-checkpoint `guardrail1` rerun confirms that the higher-count schedule
must remain paused: one candidate sample entered a materially different regime
despite identical requested shape and frozen binaries. The next bounded slice
is to explain or eliminate that regime split, then create a new append-only c1
guardrail result. Do not advance to the c16/c100 schedule on this row.
