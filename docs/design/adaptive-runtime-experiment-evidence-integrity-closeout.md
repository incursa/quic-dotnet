# Adaptive-runtime experiment evidence-integrity closeout

Status: reviewed correctness-only follow-up
Source checkpoint: `e6830c909b11f337d53421ec5e5c24d749eda1bb`
Scope: offline evidence tooling for `application_send_batch_formation` and
`buffer_copy_coalescing`

This decision closes the remaining evidence-integrity gaps in the accepted v2
experiment-control architecture. It does not change a runtime policy mechanism,
migrate another axis, release an interaction workload, authorize measurement,
activate `active_internal`, or authorize production behavior.

## Compatibility boundary

The v1 and v2 schemas, documents, fixtures, expected outputs, and retained
evidence continue to validate under their original contracts. Incompatible
identity and projection semantics are additive:

| Concern | Retained contract | Closeout contract |
| --- | --- | --- |
| Operation evidence and classifications | operation evidence v1/v2 | operation evidence v3 |
| Behavior aggregate source accounting | materialization v1/v2 | materialization v3 |
| Outcome aggregate source accounting | outcome materialization v1 | outcome materialization v2 |
| Analytical projection | projection v1/v2 | projection v3 |
| Classification compatibility | implicit v2 checks | classification-compatibility catalog v1 |

Readers select a contract by exact `schema_version`. No v1 or v2 target ID is
silently reinterpreted as a v3 composite identity.

## Catalog-owned operation outcomes

The effective-behavior catalog v2 remains the canonical owner of
`outcome_definitions`. Offline materialization resolves:

```text
operation.result
  -> every catalog outcome definition whose result_kinds contains the value
  -> exactly one outcome definition
  -> outcome_id and requires_retained_classification
```

Zero matches for a non-behavior result fail with
`outcome_derivation_no_match`. Multiple matches fail with
`outcome_derivation_ambiguous`. A successful mechanism result that is not a
non-behavior outcome is explicitly identified by the retained v2 `succeeded`
or additive v3 `applied` operation-contract value and does not produce an
outcome aggregate. No code-owned result-to-outcome switch is authoritative.
The catalog remains an offline dependency only.

## Composite identities

Operation identity v1 is the ordered tuple:

```text
run_id
connection_key
epoch_sequence
axis_id
decision_instance_id
operation_id
```

Its stable key is canonical JSON for those fields, hashed with SHA-256 and
prefixed `operation_identity_v1:`. Structured components remain present beside
the key so readers never have to reverse an opaque identifier.

Decision identity is the corresponding tuple without `operation_id`. Release
identity carries `operation_epoch_sequence` as part of the full linked
operation identity and adds `release_epoch_sequence`. The separately copied
`decision_epoch_sequence` remains a checked assertion only. Epoch identity is
`run_id`, `connection_key`, and `epoch_sequence`. Artifact identity is
`artifact_id` plus its immutable document context.

The same operation identity is used for decision joins, release joins, behavior
and outcome derivations, aggregate sources, accounting, classification targets,
and projection joins. Numeric operation IDs alone are never sufficient in v3.

## Release authority

A release is resolved first to exactly one operation by the complete operation
identity and then to exactly one linked decision. The linked decision's actual
epoch is authoritative. The copied release `decision_epoch_sequence` is only a
checked assertion and cannot weaken ordering validation.

The validator checks exact run, connection, axis, decision, operation, decision
epoch, release epoch existence, nondecreasing release order, and exactly-once
terminal release. Forged copied epochs therefore fail before they can suppress
`release_precedes_decision`.

## Exact classification targets

Operation evidence v3 classifications use a structured `target` containing
`target_kind` and all required identity components. Each classification must
resolve to exactly one target. Zero matches fail
`classification_target_missing`; more than one fails
`classification_target_ambiguous`. Classification identity is copied without
loss into outcome materialization v2 and projection v3. Artifact targets are
resolved only when the explicit immutable artifact inventory is supplied and
must match exactly one inventory document ID; a role label is not an artifact
identity.

## Classification compatibility

The classification-compatibility catalog v1 is the sole owner of the closed
classification vocabulary, primary-versus-supplemental role, and pairwise
compatibility. Validator code resolves rules from the catalog rather than
carrying a second contradiction list.

Every operation whose resolved outcome requires retention has exactly one
matching primary retained classification. Supplemental classifications never
satisfy that requirement. Any pair not explicitly permitted for the same exact
target produces `classification_contradiction`.

## Aggregate accounting

Behavior and outcome aggregates retain sorted structured operation identities
and their stable keys. Within each aggregate kind an operation can contribute
at most once to one aggregate ID unless the behavior catalog explicitly permits
composition. One operation may truthfully contribute once to a behavior
aggregate and once to an applicable outcome aggregate.

Reconciliation compares complete identity sets, counts, work, and bytes.
Operations cannot be omitted or substituted by another operation that reuses a
numeric ID on a different run, connection, epoch, decision, or axis.

## Complete immutable projection

Projection v3 accepts fifteen explicit immutable inputs:

1. experiment plan;
2. plan validation;
3. compiled execution manifest;
4. experiment run;
5. host fingerprint;
6. binary cohort;
7. workload instance;
8. requested workload shape;
9. effective workload shape;
10. operation evidence;
11. behavior materialization;
12. outcome materialization;
13. metric observations;
14. artifact inventory; and
15. classifications.

Every input has an explicit schema, valid content hash, and exact reference
checks. The builder also receives the behavior and classification catalogs as
explicit contract dependencies. They are not mutable projection inputs.

Before projection, behavior and outcome materializations are recomputed from
operation evidence and the exact catalog. Canonical bytes must match the
supplied materializations. Metrics resolve to real run/connection/epoch
identities, classifications resolve to exact evidence targets, and the artifact
inventory hashes the other fourteen immutable inputs. The inventory cannot
contain its own content hash without self-reference; its own immutable
reference is carried by the projection authority chain.

Projection v3's authority chain contains exact document references for all
fifteen inputs. There is no fixed fixture path, implicit discovery, placeholder
identity, mutable database authority, or performance-derived input.

## Closed safety posture

All closeout documents keep:

```text
active_behavior_authorization = false
performance_acceptance_authorization = false
```

No runtime dictionary, hot-path catalog lookup, new policy mechanism, axis
migration, interaction execution, performance campaign, transform, ML work, CI
change, push, or activation is authorized.
