namespace Incursa.Quic.Tests;

internal static class QuicTransportErrorCodeRegistryProofSupport
{
    internal static readonly (ulong WireValue, string ExpectedName, string ExpectedDescription)[] DefinedTransportErrorCodes =
    [
        (0x00UL, nameof(QuicTransportErrorCode.NoError), "The connection closed without an error."),
        (0x01UL, nameof(QuicTransportErrorCode.InternalError), "The endpoint encountered an internal error."),
        (0x02UL, nameof(QuicTransportErrorCode.ConnectionRefused), "The server refused to accept the connection."),
        (0x03UL, nameof(QuicTransportErrorCode.FlowControlError), "The peer violated the advertised flow control limits."),
        (0x04UL, nameof(QuicTransportErrorCode.StreamLimitError), "The peer opened too many streams."),
        (0x05UL, nameof(QuicTransportErrorCode.StreamStateError), "The endpoint observed an invalid stream state transition."),
        (0x06UL, nameof(QuicTransportErrorCode.FinalSizeError), "The peer changed a stream's final size."),
        (0x07UL, nameof(QuicTransportErrorCode.FrameEncodingError), "The peer encoded a frame incorrectly."),
        (0x08UL, nameof(QuicTransportErrorCode.TransportParameterError), "The peer violated transport-parameter processing rules."),
        (0x09UL, nameof(QuicTransportErrorCode.ConnectionIdLimitError), "The peer exceeded the active connection ID limit."),
        (0x0AUL, nameof(QuicTransportErrorCode.ProtocolViolation), "The peer violated a QUIC transport rule."),
        (0x0BUL, nameof(QuicTransportErrorCode.InvalidToken), "The peer supplied an invalid token."),
        (0x0CUL, nameof(QuicTransportErrorCode.ApplicationError), "The application closed the connection."),
        (0x0DUL, nameof(QuicTransportErrorCode.CryptoBufferExceeded), "The endpoint could not buffer all required CRYPTO data."),
        (0x0EUL, nameof(QuicTransportErrorCode.KeyUpdateError), "The endpoint encountered a key update failure."),
        (0x0FUL, nameof(QuicTransportErrorCode.AeadLimitReached), "The endpoint reached the AEAD usage limit."),
        (0x10UL, nameof(QuicTransportErrorCode.NoViablePath), "The endpoint has no viable path to its peer."),
    ];
}
