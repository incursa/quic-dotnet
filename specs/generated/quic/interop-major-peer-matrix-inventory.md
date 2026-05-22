# Interop Major Peer Matrix Inventory

Advisory inventory only. The cells are the manually dispatched major-peer matrix shape owned by `REQ-QUIC-INT-0019`; this report `interop-major-peer-matrix-inventory` does not claim execution evidence.

## Profile

- `major-peer-matrix`
- peers: `quic-go`, `msquic`
- roles: `client`, `server`
- testcases: `handshake`, `retry`, `transfer`, `keyupdate`, `resumption`

| cell | role | peer | testcase | timeout | execution state | target artifact root |
| --- | --- | --- | --- | --- | --- | --- |
| client-handshake-quic-go | client | quic-go | handshake | 0 | planned | artifacts/interop-runner/client-handshake-quic-go |
| server-handshake-quic-go | server | quic-go | handshake | 0 | planned | artifacts/interop-runner/server-handshake-quic-go |
| client-retry-quic-go | client | quic-go | retry | 0 | planned | artifacts/interop-runner/client-retry-quic-go |
| server-retry-quic-go | server | quic-go | retry | 0 | planned | artifacts/interop-runner/server-retry-quic-go |
| client-transfer-quic-go | client | quic-go | transfer | 180 | planned | artifacts/interop-runner/client-transfer-quic-go |
| server-transfer-quic-go | server | quic-go | transfer | 180 | planned | artifacts/interop-runner/server-transfer-quic-go |
| client-keyupdate-quic-go | client | quic-go | keyupdate | 180 | planned | artifacts/interop-runner/client-keyupdate-quic-go |
| server-keyupdate-quic-go | server | quic-go | keyupdate | 180 | planned | artifacts/interop-runner/server-keyupdate-quic-go |
| client-resumption-quic-go | client | quic-go | resumption | 180 | planned | artifacts/interop-runner/client-resumption-quic-go |
| server-resumption-quic-go | server | quic-go | resumption | 180 | planned | artifacts/interop-runner/server-resumption-quic-go |
| client-handshake-msquic | client | msquic | handshake | 0 | planned | artifacts/interop-runner/client-handshake-msquic |
| server-handshake-msquic | server | msquic | handshake | 0 | planned | artifacts/interop-runner/server-handshake-msquic |
| client-retry-msquic | client | msquic | retry | 0 | planned | artifacts/interop-runner/client-retry-msquic |
| server-retry-msquic | server | msquic | retry | 0 | planned | artifacts/interop-runner/server-retry-msquic |
| client-transfer-msquic | client | msquic | transfer | 180 | planned | artifacts/interop-runner/client-transfer-msquic |
| server-transfer-msquic | server | msquic | transfer | 180 | planned | artifacts/interop-runner/server-transfer-msquic |
| client-keyupdate-msquic | client | msquic | keyupdate | 180 | planned | artifacts/interop-runner/client-keyupdate-msquic |
| server-keyupdate-msquic | server | msquic | keyupdate | 180 | planned | artifacts/interop-runner/server-keyupdate-msquic |
| client-resumption-msquic | client | msquic | resumption | 180 | planned | artifacts/interop-runner/client-resumption-msquic |
| server-resumption-msquic | server | msquic | resumption | 180 | planned | artifacts/interop-runner/server-resumption-msquic |
