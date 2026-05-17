# Interop Peer Characterization Matrix Pilot

Advisory report. Derived from preserved hosted bundles and the completed major-peer evidence, and intentionally not a support verdict.

## Sources

- `25891504134`: `connectionmigration-server-proof`
- `25882671754`: `connectionmigration-server-proof-blocked`
- `25904716076`: `major-peer-matrix`

| peer | role | testcase | outcome class | failure class | artifact root |
| --- | --- | --- | --- | --- | --- |
| neqo | server | connectionmigration | failed | peer-acked-unsent-packet | artifacts/tmp-run-25891504134/20260514-232809159-server-nginx |
| quic-go | server | connectionmigration | failed | peer-zero-length-dcid-cid-retirement | artifacts/tmp-run-25882671754/interop-runner-server-connectionmigration-quic-go-blocked-25882671754/20260514-200548260-server-neqo |
| msquic | server | connectionmigration | failed | peer-packet-layer-missing | artifacts/tmp-run-25882671754/interop-runner-server-connectionmigration-msquic-blocked-25882671754/20260514-200543902-server-neqo |
| ngtcp2 | server | connectionmigration | failed | peer-transfer-size-mismatch | artifacts/tmp-run-25882671754/interop-runner-server-connectionmigration-ngtcp2-blocked-25882671754/20260514-200540179-server-neqo |
| quic-go | client | handshake | passed | none | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-client-handshake-quic-go-25904716076/20260515-065257862-client-chrome |
| quic-go | server | handshake | passed | none | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-server-handshake-quic-go-25904716076/20260515-065251299-server-nginx |
| quic-go | client | retry | passed | none | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-client-retry-quic-go-25904716076/20260515-065300497-client-chrome |
| quic-go | server | retry | passed | none | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-server-retry-quic-go-25904716076/20260515-065312750-server-nginx |
| quic-go | client | transfer | failed | peer-transfer-response-timeout | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-client-transfer-quic-go-25904716076/20260515-065307540-client-chrome |
| quic-go | server | transfer | passed | none | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-server-transfer-quic-go-25904716076/20260515-065451339-server-nginx |
| quic-go | client | keyupdate | failed | peer-keyupdate-response-timeout | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-client-keyupdate-quic-go-25904716076/20260515-065255258-client-chrome |
| quic-go | server | keyupdate | passed | none | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-server-keyupdate-quic-go-25904716076/20260515-065252220-server-nginx |
| quic-go | client | resumption | passed | none | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-client-resumption-quic-go-25904716076/20260515-065257636-client-chrome |
| quic-go | server | resumption | passed | none | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-server-resumption-quic-go-25904716076/20260515-065622235-server-nginx |
| msquic | client | handshake | failed | peer-tls-alert-50 | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-client-handshake-msquic-25904716076/20260515-065520779-client-chrome |
| msquic | server | handshake | passed | none | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-server-handshake-msquic-25904716076/20260515-065520562-server-nginx |
| msquic | client | retry | failed | peer-tls-alert-50 | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-client-retry-msquic-25904716076/20260515-065307819-client-chrome |
| msquic | server | retry | passed | none | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-server-retry-msquic-25904716076/20260515-065301859-server-nginx |
| msquic | client | transfer | failed | peer-tls-alert-50 | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-client-transfer-msquic-25904716076/20260515-065301883-client-chrome |
| msquic | server | transfer | passed | none | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-server-transfer-msquic-25904716076/20260515-065418678-server-nginx |
| msquic | client | keyupdate | failed | peer-tls-alert-50 | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-client-keyupdate-msquic-25904716076/20260515-065306276-client-chrome |
| msquic | server | keyupdate | failed | peer-keyupdate-missing-file | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-server-keyupdate-msquic-25904716076/20260515-065307734-server-nginx |
| msquic | client | resumption | failed | peer-tls-alert-50 | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-client-resumption-msquic-25904716076/20260515-065309380-client-chrome |
| msquic | server | resumption | failed | peer-connection-terminated | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-server-resumption-msquic-25904716076/20260515-065254819-server-nginx |
