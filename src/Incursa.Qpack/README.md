# Incursa.Qpack

`Incursa.Qpack` is the standalone QPACK package for HTTP/3 header compression.

## Install

```bash
dotnet add package Incursa.Qpack
```

## Design Notes

- This package must not depend on `Incursa.Quic`.
- Encoder and decoder state machines should be testable without a network transport.
- Wire parsing, serialization, dynamic-table accounting, and blocked-stream handling belong here.
- Decoding accepts both raw and Huffman-encoded string literals. Encoding remains deterministic and currently emits raw string literals.
