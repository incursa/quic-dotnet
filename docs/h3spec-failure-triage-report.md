# h3spec Failure Triage Report Template

This template records h3spec failures against the local Incursa HTTP/3 server. Generated reports are written under `.artifacts/http3-h3spec/<run-id>/h3spec-report.md`.

## Run Metadata

- Date:
- Commit:
- h3spec version:
- Server command:
- Artifact root:

## Summary

| Status | Count |
| --- | --- |
| Parsed cases | not run |
| Failures | not run |
| RFC 9114/RFC 9204 failures | not run |

## Failing Cases

| h3spec case | RFC section | Internal requirement/gap | Follow-up TODO |
| --- | --- | --- | --- |
| not run | not run | not run | not run |

## Follow-Up Rules

- RFC 9114 failures map to `http3-adapter-boundary` until a narrower HTTP/3 protocol requirement exists.
- RFC 9204 failures map to `qpack-stream-state-boundary` until a narrower QPACK protocol requirement exists.
- Transport or TLS failures are recorded for context, but they do not become HTTP/3/QPACK TODO items.
- A green h3spec run is evidence for the h3spec harness only unless protocol-owned requirements and focused tests also support the claim.
