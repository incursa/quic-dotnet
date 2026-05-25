# RFC 9114 HTTP/3 Stream Mapping

This slice adds transport-agnostic HTTP/3 stream mapping and stream-type validation to `Incursa.Quic.Http3`.

## Covered

- RFC 9114 Section 6.1 request stream mapping: client-initiated bidirectional streams map to HTTP request streams.
- RFC 9114 Section 6.1 invalid server-initiated bidirectional streams unless an extension explicitly enables them.
- RFC 9114 Section 6.2 unidirectional stream type parsing with partial-buffer support for the leading stream-type varint.
- RFC 9114 Section 6.2.1 control stream registration and one-control-stream-per-endpoint enforcement.
- RFC 9114 Section 6.2.1 SETTINGS-first enforcement on the control stream.
- RFC 9114 Sections 6.2.2 and 6.2.3 push-stream and reserved-stream-type classification. Push streams remain disabled by default.
- RFC 9114 Section 7 frame placement validation for request, control, push, QPACK, unknown, and reserved stream kinds.

## Deferred

- Full HTTP request and response sequencing.
- Direction-sensitive request-stream frame validation, such as client-to-server versus server-to-client PUSH_PROMISE rules.
- Push-stream Push ID payload parsing beyond stream-type classification.
- HTTP/3 lifecycle integration with the managed QUIC runtime.
- Extension negotiation for server-initiated bidirectional streams beyond an explicit dispatcher option.
- Fuzz and benchmark suites for stream mapping and frame-placement state transitions.
