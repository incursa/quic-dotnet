using System.Reflection;

namespace Incursa.Quic.Tests;

internal static class QuicFrameRegistryProofSupport
{
    internal static readonly (string FieldName, ulong WireValue, string FrameTypeName, string FieldDescription)[] DefinedFrameRegistrations =
    [
        Create("PaddingFrameType", "PADDING", "Contains no fields and contributes only padding octets."),
        Create("PingFrameType", "PING", "Contains no fields and elicits an immediate ACK."),
        Create("AckFrameType", "ACK", "Carries the largest acknowledged packet number, ACK delay, ACK range, and optional ECN count fields."),
        Create("AckEcnFrameType", "ACK_ECN", "Carries ACK range fields plus ECN count fields."),
        Create("ResetStreamFrameType", "RESET_STREAM", "Carries stream ID, application error code, and final size fields."),
        Create("StopSendingFrameType", "STOP_SENDING", "Carries stream ID and application error code fields."),
        Create("CryptoFrameType", "CRYPTO", "Carries stream offset and CRYPTO data fields."),
        Create("NewTokenFrameType", "NEW_TOKEN", "Carries token fields issued by the server."),
        Create("MaxDataFrameType", "MAX_DATA", "Carries the connection-level flow-control limit field."),
        Create("MaxStreamDataFrameType", "MAX_STREAM_DATA", "Carries the per-stream flow-control limit field."),
        Create("MaxStreamsBidirectionalFrameType", "MAX_STREAMS_BIDI", "Carries the bidirectional stream-count limit field."),
        Create("MaxStreamsUnidirectionalFrameType", "MAX_STREAMS_UNI", "Carries the unidirectional stream-count limit field."),
        Create("DataBlockedFrameType", "DATA_BLOCKED", "Carries the connection-level limit field that caused blocking."),
        Create("StreamDataBlockedFrameType", "STREAM_DATA_BLOCKED", "Carries the stream-level limit field that caused blocking."),
        Create("StreamsBlockedBidirectionalFrameType", "STREAMS_BLOCKED_BIDI", "Carries the bidirectional stream-count limit field that caused blocking."),
        Create("StreamsBlockedUnidirectionalFrameType", "STREAMS_BLOCKED_UNI", "Carries the unidirectional stream-count limit field that caused blocking."),
        Create("NewConnectionIdFrameType", "NEW_CONNECTION_ID", "Carries the sequence number, retire-prior-to value, connection ID, and stateless reset token fields."),
        Create("RetireConnectionIdFrameType", "RETIRE_CONNECTION_ID", "Carries the sequence-number field of the connection ID to retire."),
        Create("PathChallengeFrameType", "PATH_CHALLENGE", "Carries the 8-byte path-challenge data field."),
        Create("PathResponseFrameType", "PATH_RESPONSE", "Carries the 8-byte path-response data field."),
        Create("ConnectionCloseFrameType", "CONNECTION_CLOSE", "Carries the transport error code, triggering frame type, and reason phrase fields."),
        Create("ApplicationConnectionCloseFrameType", "APPLICATION_CLOSE", "Carries the application error code and reason phrase fields."),
        Create("HandshakeDoneFrameType", "HANDSHAKE_DONE", "Contains no fields and signals the handshake is complete."),
    ];

    private static (string FieldName, ulong WireValue, string FrameTypeName, string FieldDescription) Create(
        string fieldName,
        string frameTypeName,
        string fieldDescription)
    {
        FieldInfo? field = typeof(QuicFrameCodec).GetField(fieldName, BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(field);

        return (
            fieldName,
            (ulong)field!.GetRawConstantValue()!,
            frameTypeName,
            fieldDescription);
    }
}
