namespace Incursa.Quic.Tests;

public sealed class QuicTransportErrorCodeTests
{
    public static TheoryData<QuicTransportErrorCode, ulong> StandardTransportErrorCodes => new()
    {
        { QuicTransportErrorCode.NoError, 0x00 },
        { QuicTransportErrorCode.InternalError, 0x01 },
        { QuicTransportErrorCode.ConnectionRefused, 0x02 },
        { QuicTransportErrorCode.FlowControlError, 0x03 },
        { QuicTransportErrorCode.StreamLimitError, 0x04 },
        { QuicTransportErrorCode.StreamStateError, 0x05 },
        { QuicTransportErrorCode.FinalSizeError, 0x06 },
        { QuicTransportErrorCode.FrameEncodingError, 0x07 },
        { QuicTransportErrorCode.TransportParameterError, 0x08 },
        { QuicTransportErrorCode.ConnectionIdLimitError, 0x09 },
        { QuicTransportErrorCode.ProtocolViolation, 0x0A },
        { QuicTransportErrorCode.InvalidToken, 0x0B },
        { QuicTransportErrorCode.ApplicationError, 0x0C },
        { QuicTransportErrorCode.CryptoBufferExceeded, 0x0D },
        { QuicTransportErrorCode.KeyUpdateError, 0x0E },
        { QuicTransportErrorCode.AeadLimitReached, 0x0F },
        { QuicTransportErrorCode.NoViablePath, 0x10 },
    };

    [Theory]
    [MemberData(nameof(StandardTransportErrorCodes))]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0002")]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0007")]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0008")]
    [Trait("Category", "Positive")]
    public void TransportErrorCodeRegistry_ExposesTheRFC9000Values(
        QuicTransportErrorCode code,
        ulong expectedWireValue)
    {
        Assert.Equal(expectedWireValue, (ulong)code);
    }
}
