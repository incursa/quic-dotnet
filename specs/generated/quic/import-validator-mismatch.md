# QUIC Validator Mismatch Assessment

## Current Issue

- [`specs/generated/quic/core-validation.json`](./core-validation.json) reports 1736 errors under code `REQ-CLAUSE`, one for every QUIC requirement.
- The message is namespace-alignment text of the form "requirement ... does not align with specification namespace ..." rather than a malformed-identifier complaint.
- Historical validator behavior also failed against the reference SpecTrace suite because it missed linked REQ headings there; that issue is separate from the QUIC import corpus itself.

## Do The Section-Scoped REQ IDs Satisfy Spec Trace Rules?

- Yes. `artifact-id-policy.json` and the published SpecTrace model use requirement identifiers of the form `REQ-<DOMAIN>(-<GROUPING>...)-<SEQUENCE:4+>`.
- Yes. [`artifact-id-policy.json`](../../../artifact-id-policy.json) allows zero or more grouping segments and constrains each grouping segment only to `^[A-Z][A-Z0-9]*$`.
- Yes. Tokens such as `S5P1`, `S10P3P2`, and `SAP11` are uppercase alphanumeric and letter-starting, so they satisfy the published grouping-token rule.

## Representative Valid-Looking IDs

- `REQ-QUIC-RFC8999-S5P1-0001`
- `REQ-QUIC-RFC9000-S10-0001`
- `REQ-QUIC-RFC9000-S10P3P2-0001`
- `REQ-QUIC-RFC9002-SAP11-0003`

## Assessment

- Imported-content invalidity: no evidence that the section-scoped QUIC REQ IDs violate the published Spec Trace identifier rules.
- Validator-policy mismatch: yes. The current helper requires the requirement namespace to exactly equal the specification namespace and therefore rejects valid extra section grouping segments.
- Unknown / needs further review: only for future validator behavior changes, not for the present QUIC ID validity question.

## Clear Conclusion

- The current blocker is validator-policy mismatch.
- The section-scoped QUIC REQ IDs are standard-valid under Spec Trace as currently specified.
- The QUIC import should not be downgraded to failed `core` solely because of this namespace check.
