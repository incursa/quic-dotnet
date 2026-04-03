using System.ComponentModel;
using System.Reflection;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S22P5-0003")]
[Requirement("REQ-QUIC-RFC9000-S22P5-0004")]
[Requirement("REQ-QUIC-RFC9000-S22P5-0005")]
public sealed class QuicTransportErrorCodeTests
{
    public static TheoryData<QuicTransportErrorCode, ulong, string> StandardTransportErrorCodes => new()
    {
        { QuicTransportErrorCode.NoError, 0x00, nameof(QuicTransportErrorCode.NoError) },
        { QuicTransportErrorCode.InternalError, 0x01, nameof(QuicTransportErrorCode.InternalError) },
        { QuicTransportErrorCode.ConnectionRefused, 0x02, nameof(QuicTransportErrorCode.ConnectionRefused) },
        { QuicTransportErrorCode.FlowControlError, 0x03, nameof(QuicTransportErrorCode.FlowControlError) },
        { QuicTransportErrorCode.StreamLimitError, 0x04, nameof(QuicTransportErrorCode.StreamLimitError) },
        { QuicTransportErrorCode.StreamStateError, 0x05, nameof(QuicTransportErrorCode.StreamStateError) },
        { QuicTransportErrorCode.FinalSizeError, 0x06, nameof(QuicTransportErrorCode.FinalSizeError) },
        { QuicTransportErrorCode.FrameEncodingError, 0x07, nameof(QuicTransportErrorCode.FrameEncodingError) },
        { QuicTransportErrorCode.TransportParameterError, 0x08, nameof(QuicTransportErrorCode.TransportParameterError) },
        { QuicTransportErrorCode.ConnectionIdLimitError, 0x09, nameof(QuicTransportErrorCode.ConnectionIdLimitError) },
        { QuicTransportErrorCode.ProtocolViolation, 0x0A, nameof(QuicTransportErrorCode.ProtocolViolation) },
        { QuicTransportErrorCode.InvalidToken, 0x0B, nameof(QuicTransportErrorCode.InvalidToken) },
        { QuicTransportErrorCode.ApplicationError, 0x0C, nameof(QuicTransportErrorCode.ApplicationError) },
        { QuicTransportErrorCode.CryptoBufferExceeded, 0x0D, nameof(QuicTransportErrorCode.CryptoBufferExceeded) },
        { QuicTransportErrorCode.KeyUpdateError, 0x0E, nameof(QuicTransportErrorCode.KeyUpdateError) },
        { QuicTransportErrorCode.AeadLimitReached, 0x0F, nameof(QuicTransportErrorCode.AeadLimitReached) },
        { QuicTransportErrorCode.NoViablePath, 0x10, nameof(QuicTransportErrorCode.NoViablePath) },
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
    [CoverageType(RequirementCoverageType.Positive)]
    public void TransportErrorCodeRegistry_ExposesTheRFC9000Values(
        QuicTransportErrorCode code,
        ulong expectedWireValue,
        string expectedName)
    {
        Assert.Equal(expectedWireValue, (ulong)code);
        Assert.Equal(expectedName, code.ToString());

        FieldInfo? field = typeof(QuicTransportErrorCode).GetField(expectedName);
        Assert.NotNull(field);
        DescriptionAttribute? description = field!.GetCustomAttribute<DescriptionAttribute>();
        Assert.NotNull(description);
        Assert.NotEmpty(description!.Description);
    }
}
