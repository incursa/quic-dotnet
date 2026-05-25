# HTTP/3 and QPACK Error-Handling Matrix

This matrix records the expected protocol outcome for focused HTTP/3 and QPACK
negative tests. HTTP/3 references are from RFC 9114; QPACK references are from
RFC 9204.

| Case | RFC section | Expected error code | Error scope | Connection remains usable? | Unit test name | Interop/fuzz possibility |
|---|---|---|---|---|---|---|
| DATA frame on control stream | RFC 9114 Sections 6.2.1, 7.2.1, 8.1 | H3_FRAME_UNEXPECTED | Connection error | No | `ControlStream_DataFrame_ThrowsFrameUnexpected` | Interop peer can send DATA after SETTINGS on control stream; fuzz frame placement by stream kind. |
| HEADERS frame on control stream | RFC 9114 Sections 6.2.1, 7.2.2, 8.1 | H3_FRAME_UNEXPECTED | Connection error | No | `ControlStream_HeadersFrame_ThrowsFrameUnexpected` | Interop peer can send HEADERS after SETTINGS on control stream; fuzz frame placement by stream kind. |
| SETTINGS not first frame on control stream | RFC 9114 Sections 6.2.1, 7.2.4 | H3_MISSING_SETTINGS | Connection error | No | `ControlStream_SettingsNotFirst_ThrowsMissingSettings` | Interop peer can send GOAWAY before SETTINGS; fuzz first-frame permutations. |
| Duplicate SETTINGS parameter | RFC 9114 Section 7.2.4 | H3_SETTINGS_ERROR | Connection error | No | `SettingsFrame_DuplicateParameter_ThrowsSettingsError` | Interop peer can duplicate a known setting; fuzz SETTINGS identifier/value pairs. |
| Duplicate control stream | RFC 9114 Section 6.2.1 | H3_STREAM_CREATION_ERROR | Connection error | No | `ControlStream_DuplicateControlStream_ThrowsStreamCreationError` | Interop peer can open two control streams from one endpoint. |
| Server-initiated bidirectional stream | RFC 9114 Section 6.1 | H3_STREAM_CREATION_ERROR | Connection error | No | `BidirectionalStream_ServerInitiated_ThrowsStreamCreationError` | Interop server can open a bidi stream without extension negotiation. |
| Client-initiated push stream | RFC 9114 Section 6.2.2 | H3_STREAM_CREATION_ERROR | Connection error | No | `UnidirectionalStream_ClientInitiatedPushStream_ThrowsStreamCreationError` | Interop client can open push stream type 0x01; fuzz stream-type/initiator combinations. |
| Invalid static table index | RFC 9204 Sections 3.1, 4.5 | QPACK_DECOMPRESSION_FAILED | Connection error | No | `QPackFieldSection_InvalidStaticIndex_ThrowsDecompressionFailed` | Fuzz static index encodings in all field-line representations. |
| Invalid dynamic table reference | RFC 9204 Section 2.2.3 | QPACK_DECOMPRESSION_FAILED | Connection error | No | `QPackFieldSection_InvalidDynamicReference_ThrowsDecompressionFailed` | Fuzz Required Insert Count, Base, relative index, and post-base index combinations. |
| Encoder stream instruction references evicted entry | RFC 9204 Section 2.2.3 | QPACK_ENCODER_STREAM_ERROR | Connection error | No | `QPackEncoderStream_DynamicNameReferenceToEvictedEntry_ThrowsEncoderStreamError` | Fuzz encoder-stream instructions after capacity reductions and evictions. |
| Truncated frame | RFC 9114 Section 7.1 | H3_FRAME_ERROR | Connection error | No | `FrameReader_TruncatedFrame_ThrowsFrameError` | Fuzz end-of-stream at every frame-header and payload byte boundary. |
| Frame payload has extra bytes | RFC 9114 Section 7.1 | H3_FRAME_ERROR | Connection error | No | `FrameReader_ExtraPayloadBytes_ThrowsFrameError` | Fuzz fixed-shape frame payloads with trailing bytes. |
| Invalid content-length | RFC 9114 Section 4.1.2 | H3_MESSAGE_ERROR | Stream error | Yes | `HeaderValidator_InvalidContentLength_ThrowsMessageError` | Interop peer can mismatch DATA length; fuzz DATA length accumulation and duplicate Content-Length fields. |
| Missing `:status` in response | RFC 9114 Sections 4.1.2, 4.3.2 | H3_MESSAGE_ERROR | Stream error | Yes | `HeaderValidator_ResponseMissingStatus_ThrowsMessageError` | Interop peer can send response HEADERS without `:status`; fuzz response pseudo-header sets. |
| Missing required request pseudo-header | RFC 9114 Sections 4.1.2, 4.3.1 | H3_MESSAGE_ERROR | Stream error | Yes | `HeaderValidator_RequestMissingPseudoHeader_ThrowsMessageError` | Interop peer can omit `:method`, `:scheme`, `:authority`, or `:path`; fuzz request pseudo-header sets. |
| Uppercase header name | RFC 9114 Sections 4.1.2, 4.2 | H3_MESSAGE_ERROR | Stream error | Yes | `HeaderValidator_UppercaseHeaderName_ThrowsMessageError` | Fuzz field-name casing and invalid characters. |
| Pseudo-header after regular header | RFC 9114 Sections 4.1.2, 4.3 | H3_MESSAGE_ERROR | Stream error | Yes | `HeaderValidator_PseudoHeaderAfterRegularHeader_ThrowsMessageError` | Fuzz field ordering and mixed request/response pseudo-headers. |

Notes:

- "Connection remains usable" describes the RFC-level outcome. The current unit
  tests assert the protocol error surfaced by the layer; transport close/reset
  wiring is tested separately.
- Malformed HTTP messages are stream errors by RFC 9114 Section 4.1.2, but an
  endpoint can choose to escalate a stream error to a connection error under
  RFC 9114 Section 8.
