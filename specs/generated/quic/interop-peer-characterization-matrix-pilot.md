# Interop Peer Characterization Matrix Pilot

Advisory seed report. Derived from preserved hosted bundles and intentionally not a support verdict.

## Sources

- `25891504134`: `connectionmigration-server-proof`
- `25882671754`: `connectionmigration-server-proof-blocked`

| peer | role | testcase | outcome class | failure class | artifact root |
| --- | --- | --- | --- | --- | --- |
| neqo | server | connectionmigration | failed | peer-acked-unsent-packet | artifacts/tmp-run-25891504134/20260514-232809159-server-nginx |
| quic-go | server | connectionmigration | failed | peer-zero-length-dcid-cid-retirement | artifacts/tmp-run-25882671754/interop-runner-server-connectionmigration-quic-go-blocked-25882671754/20260514-200548260-server-neqo |
| msquic | server | connectionmigration | failed | peer-packet-layer-missing | artifacts/tmp-run-25882671754/interop-runner-server-connectionmigration-msquic-blocked-25882671754/20260514-200543902-server-neqo |
| ngtcp2 | server | connectionmigration | failed | peer-transfer-size-mismatch | artifacts/tmp-run-25882671754/interop-runner-server-connectionmigration-ngtcp2-blocked-25882671754/20260514-200540179-server-neqo |
