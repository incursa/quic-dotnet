namespace Incursa.Quic.Tests;

internal static class QuicFrameRegistryProofSupport
{
    internal static readonly (ulong FrameType, string FrameTypeName, string FieldSemantics)[] PermanentFrameTypes =
    [
        (0x00UL, "PADDING", "No payload fields; consumes bytes as padding."),
        (0x01UL, "PING", "No payload fields; elicits an acknowledgment."),
        (0x02UL, "ACK", "Largest acknowledged, ack delay, range count, first range, and additional ranges."),
        (0x03UL, "ACK_ECN", "ACK fields plus ECT(0), ECT(1), and ECN-CE counts."),
        (0x04UL, "RESET_STREAM", "Stream ID, application error code, and final size."),
        (0x05UL, "STOP_SENDING", "Stream ID and application protocol error code."),
        (0x06UL, "CRYPTO", "Offset and crypto data length followed by crypto data bytes."),
        (0x07UL, "NEW_TOKEN", "Token length followed by opaque token bytes."),
        (0x10UL, "MAX_DATA", "Maximum data value."),
        (0x11UL, "MAX_STREAM_DATA", "Stream ID and maximum stream data value."),
        (0x12UL, "MAX_STREAMS_BIDI", "Maximum bidirectional stream count."),
        (0x13UL, "MAX_STREAMS_UNI", "Maximum unidirectional stream count."),
        (0x14UL, "DATA_BLOCKED", "Maximum data value."),
        (0x15UL, "STREAM_DATA_BLOCKED", "Stream ID and maximum stream data value."),
        (0x16UL, "STREAMS_BLOCKED_BIDI", "Maximum bidirectional stream count."),
        (0x17UL, "STREAMS_BLOCKED_UNI", "Maximum unidirectional stream count."),
        (0x18UL, "NEW_CONNECTION_ID", "Sequence number, retire prior to, connection ID, and stateless reset token."),
        (0x19UL, "RETIRE_CONNECTION_ID", "Sequence number."),
        (0x1AUL, "PATH_CHALLENGE", "Eight bytes of opaque path challenge data."),
        (0x1BUL, "PATH_RESPONSE", "Eight bytes of opaque path response data."),
        (0x1CUL, "CONNECTION_CLOSE", "Transport error code, triggering frame type, and reason phrase."),
        (0x1DUL, "APPLICATION_CLOSE", "Application error code and reason phrase."),
        (0x1EUL, "HANDSHAKE_DONE", "No payload fields; marks handshake completion."),
    ];
}
