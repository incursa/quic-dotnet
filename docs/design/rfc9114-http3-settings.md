---
title: "RFC 9114 HTTP/3 SETTINGS Handling"
---

# RFC 9114 HTTP/3 SETTINGS Handling

This slice adds semantic SETTINGS handling above the transport-agnostic HTTP/3 frame and stream layers.

## Covered

- RFC 9114 Section 7.2.4 SETTINGS parsing and writing.
- RFC 9114 Section 7.2.4 duplicate SETTINGS identifier rejection with `H3_SETTINGS_ERROR`.
- RFC 9114 Section 7.2.4.1 `SETTINGS_MAX_FIELD_SECTION_SIZE` capture and validation hook.
- RFC 9114 Section 11.2.2 reserved SETTINGS identifier rejection for `0x00` and HTTP/2 carryover identifiers `0x02` through `0x05`.
- Unknown non-forbidden settings are ignored by the typed settings model while remaining visible in raw frame settings.
- RFC 9204 Section 5 QPACK settings capture for `SETTINGS_QPACK_MAX_TABLE_CAPACITY` and `SETTINGS_QPACK_BLOCKED_STREAMS`.
- Initial local control-stream byte generation: stream type `0x00` followed by exactly one SETTINGS frame when the transport adapter is ready to send HTTP/3 data.

## Deferred

- Automatic integration with live QUIC stream creation.
- Applying peer QPACK SETTINGS directly to a higher-level HTTP/3 encoder owner.
- Full HEADERS/PUSH_PROMISE field-section decoding and automatic `SETTINGS_MAX_FIELD_SECTION_SIZE` enforcement at that decode boundary.
- Fuzz and benchmark suites for SETTINGS parsing and validation.
