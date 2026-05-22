# Interop Major Peer Matrix Evidence - 25904716076

Advisory evidence report `interop-major-peer-matrix-evidence-25904716076`. Derived from the completed hosted major-peer-matrix run and intentionally not a support verdict.

## Sources

- 25904716076: major-peer-matrix

## Summary

- rows: 20
- passed: 11
- failed: 9
- failure classes:
  - peer-tls-alert-50: 5
  - peer-connection-terminated: 1
  - peer-keyupdate-missing-file: 1
  - peer-keyupdate-response-timeout: 1
  - peer-transfer-response-timeout: 1

| cell | peer | role | testcase | timeout | outcome class | failure class | artifact root |
| --- | --- | --- | --- | --- | --- | --- | --- |
| client-handshake-quic-go | quic-go | client | handshake | 0 | passed | none | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-client-handshake-quic-go-25904716076/20260515-065257862-client-chrome |
| server-handshake-quic-go | quic-go | server | handshake | 0 | passed | none | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-server-handshake-quic-go-25904716076/20260515-065251299-server-nginx |
| client-retry-quic-go | quic-go | client | retry | 0 | passed | none | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-client-retry-quic-go-25904716076/20260515-065300497-client-chrome |
| server-retry-quic-go | quic-go | server | retry | 0 | passed | none | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-server-retry-quic-go-25904716076/20260515-065312750-server-nginx |
| client-transfer-quic-go | quic-go | client | transfer | 180 | failed | peer-transfer-response-timeout | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-client-transfer-quic-go-25904716076/20260515-065307540-client-chrome |
| server-transfer-quic-go | quic-go | server | transfer | 180 | passed | none | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-server-transfer-quic-go-25904716076/20260515-065451339-server-nginx |
| client-keyupdate-quic-go | quic-go | client | keyupdate | 180 | failed | peer-keyupdate-response-timeout | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-client-keyupdate-quic-go-25904716076/20260515-065255258-client-chrome |
| server-keyupdate-quic-go | quic-go | server | keyupdate | 180 | passed | none | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-server-keyupdate-quic-go-25904716076/20260515-065252220-server-nginx |
| client-resumption-quic-go | quic-go | client | resumption | 180 | passed | none | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-client-resumption-quic-go-25904716076/20260515-065257636-client-chrome |
| server-resumption-quic-go | quic-go | server | resumption | 180 | passed | none | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-server-resumption-quic-go-25904716076/20260515-065622235-server-nginx |
| client-handshake-msquic | msquic | client | handshake | 0 | failed | peer-tls-alert-50 | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-client-handshake-msquic-25904716076/20260515-065520779-client-chrome |
| server-handshake-msquic | msquic | server | handshake | 0 | passed | none | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-server-handshake-msquic-25904716076/20260515-065520562-server-nginx |
| client-retry-msquic | msquic | client | retry | 0 | failed | peer-tls-alert-50 | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-client-retry-msquic-25904716076/20260515-065307819-client-chrome |
| server-retry-msquic | msquic | server | retry | 0 | passed | none | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-server-retry-msquic-25904716076/20260515-065301859-server-nginx |
| client-transfer-msquic | msquic | client | transfer | 180 | failed | peer-tls-alert-50 | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-client-transfer-msquic-25904716076/20260515-065301883-client-chrome |
| server-transfer-msquic | msquic | server | transfer | 180 | passed | none | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-server-transfer-msquic-25904716076/20260515-065418678-server-nginx |
| client-keyupdate-msquic | msquic | client | keyupdate | 180 | failed | peer-tls-alert-50 | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-client-keyupdate-msquic-25904716076/20260515-065306276-client-chrome |
| server-keyupdate-msquic | msquic | server | keyupdate | 180 | failed | peer-keyupdate-missing-file | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-server-keyupdate-msquic-25904716076/20260515-065307734-server-nginx |
| client-resumption-msquic | msquic | client | resumption | 180 | failed | peer-tls-alert-50 | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-client-resumption-msquic-25904716076/20260515-065309380-client-chrome |
| server-resumption-msquic | msquic | server | resumption | 180 | failed | peer-connection-terminated | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-server-resumption-msquic-25904716076/20260515-065254819-server-nginx |
