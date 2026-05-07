using System.ComponentModel;
using System.Reflection;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S20P1-0001")]
public sealed class REQ_QUIC_RFC9000_S20P1_0001_Focused
{
    private static readonly (ulong WireValue, string ExpectedName)[] DefinedTransportErrorCodes =
    [
        (0x00UL, nameof(QuicTransportErrorCode.NoError)),
        (0x01UL, nameof(QuicTransportErrorCode.InternalError)),
        (0x02UL, nameof(QuicTransportErrorCode.ConnectionRefused)),
        (0x03UL, nameof(QuicTransportErrorCode.FlowControlError)),
        (0x04UL, nameof(QuicTransportErrorCode.StreamLimitError)),
        (0x05UL, nameof(QuicTransportErrorCode.StreamStateError)),
        (0x06UL, nameof(QuicTransportErrorCode.FinalSizeError)),
        (0x07UL, nameof(QuicTransportErrorCode.FrameEncodingError)),
        (0x08UL, nameof(QuicTransportErrorCode.TransportParameterError)),
        (0x09UL, nameof(QuicTransportErrorCode.ConnectionIdLimitError)),
        (0x0AUL, nameof(QuicTransportErrorCode.ProtocolViolation)),
        (0x0BUL, nameof(QuicTransportErrorCode.InvalidToken)),
        (0x0CUL, nameof(QuicTransportErrorCode.ApplicationError)),
        (0x0DUL, nameof(QuicTransportErrorCode.CryptoBufferExceeded)),
        (0x0EUL, nameof(QuicTransportErrorCode.KeyUpdateError)),
        (0x0FUL, nameof(QuicTransportErrorCode.AeadLimitReached)),
        (0x10UL, nameof(QuicTransportErrorCode.NoViablePath)),
    ];

    private static readonly ulong[] UndefinedTransportErrorCodes =
    [
        0x11UL,
        0xFFUL,
    ];

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TransportErrorCodeRegistry_ExposesTheDefinedRFC9000Values()
    {
        foreach ((ulong wireValue, string expectedName) in DefinedTransportErrorCodes)
        {
            QuicTransportErrorCode code = (QuicTransportErrorCode)wireValue;

            Assert.Equal(wireValue, (ulong)code);
            Assert.Equal(expectedName, code.ToString());

            FieldInfo? field = typeof(QuicTransportErrorCode).GetField(expectedName);
            Assert.NotNull(field);

            DescriptionAttribute? description = field!.GetCustomAttribute<DescriptionAttribute>();
            Assert.NotNull(description);
            Assert.NotEmpty(description!.Description);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TransportErrorCodeRegistry_DoesNotDefineUnknownValues()
    {
        foreach (ulong wireValue in UndefinedTransportErrorCodes)
        {
            Assert.False(Enum.IsDefined(typeof(QuicTransportErrorCode), wireValue));
            Assert.Null(typeof(QuicTransportErrorCode).GetField(wireValue.ToString()));
        }
    }
}
