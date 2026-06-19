---
title: "RFC 9204 QPACK First Milestone"
---

# RFC 9204 QPACK First Milestone

This note tracks the standalone `Incursa.Qpack` package milestone. The first slice established the static, no-dynamic-table field-section floor. The second slice adds bounded dynamic-table state and blocked-stream handling without coupling QPACK to HTTP/3 hosting or QUIC transport internals. The third slice makes the QPACK encoder and decoder unidirectional instruction streams incremental so callers can feed network-sized buffers without assuming instruction alignment.

## Covered

- RFC 9204 Section 3.1 static table, including zero-based indexes 0 through 98.
- RFC 9204 Section 4.1.1 prefixed integer encoding and decoding for values up to 62 bits.
- RFC 9204 Section 4.1.2 string literal structure for non-Huffman literals.
- RFC 9204 Section 4.5.1 encoded field-section prefix for `Required Insert Count = 0` and `Base = 0`.
- RFC 9204 Section 4.5.2 static indexed field-line decoding and encoding.
- RFC 9204 Section 4.5.4 literal field lines with static table name references.
- RFC 9204 Section 4.5.6 literal field lines with literal names.
- RFC 9204 Appendix B.1 static-name-reference example.
- RFC 9204 Section 2.1.1 encoder-side insertion limits for entries that exceed capacity or would evict entries that are not yet evictable.
- RFC 9204 Section 2.1.2 and Section 2.2.1 Required Insert Count driven blocked stream accounting, including the configured maximum blocked streams limit.
- RFC 9204 Section 2.2.3 invalid dynamic-reference error mapping for field sections and encoder-stream instructions.
- RFC 9204 Section 3.2 dynamic table capacity, entry sizing, insertion, eviction, and duplicate entries.
- RFC 9204 Sections 3.2.4 through 3.2.6 absolute indexing, relative indexing, and post-Base indexing.
- RFC 9204 Sections 4.3.1 through 4.3.4 Set Dynamic Table Capacity, Insert with Name Reference, Insert with Literal Name, and Duplicate encoder instructions.
- RFC 9204 Sections 4.4.1 through 4.4.3 decoder-stream Section Acknowledgment, Stream Cancellation, and Insert Count Increment parsing on the encoder side.
- RFC 9204 Section 4.3 and Section 4.4 instruction streams with partial-buffer accumulation, deterministic malformed-instruction errors, and explicit end-of-stream validation.
- RFC 9204 Sections 4.5.1 through 4.5.5 dynamic Required Insert Count reconstruction, Base reconstruction, dynamic indexed fields, post-Base indexed fields, dynamic-name literals, and post-Base dynamic-name literals.
- RFC 9204 Appendix B.2 through B.5 dynamic table, speculative insert, duplicate, cancellation, and eviction examples.

## Deferred

- Huffman string literal decoding and encoding.
- HTTP/3 SETTINGS integration for QPACK table capacity and blocked-stream limits.
- Automatic HTTP/3 emission of QPACK decoder-stream instructions.
- Advanced encoder compression policy, including speculative insertion during single-pass field-section encoding.
- Fuzz and benchmark suites for the new dynamic-table and blocked-stream hot paths.

Invalid static and dynamic references in field sections map to `QPACK_DECOMPRESSION_FAILED`. Invalid static and dynamic references in encoder-stream instructions map to `QPACK_ENCODER_STREAM_ERROR`.
