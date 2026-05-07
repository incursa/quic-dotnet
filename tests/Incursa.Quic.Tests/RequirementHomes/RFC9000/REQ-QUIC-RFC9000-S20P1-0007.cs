namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S20P1-0007")]
public sealed class REQ_QUIC_RFC9000_S20P1_0007
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0007")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TransportErrorCodeRegistry_ExposesHandshakeSpecificErrorCodes()
    {
        (ulong keyUpdateWireValue, string keyUpdateName, string keyUpdateDescription) =
            QuicTransportErrorCodeRegistryProofSupport.GetDefinedTransportErrorCode(nameof(QuicTransportErrorCode.KeyUpdateError));
        (ulong aeadLimitWireValue, string aeadLimitName, string aeadLimitDescription) =
            QuicTransportErrorCodeRegistryProofSupport.GetDefinedTransportErrorCode(nameof(QuicTransportErrorCode.AeadLimitReached));

        Assert.Equal(0x0EUL, keyUpdateWireValue);
        Assert.Equal(nameof(QuicTransportErrorCode.KeyUpdateError), keyUpdateName);
        Assert.Equal(keyUpdateName, ((QuicTransportErrorCode)keyUpdateWireValue).ToString());
        Assert.NotEmpty(keyUpdateDescription);

        Assert.Equal(0x0FUL, aeadLimitWireValue);
        Assert.Equal(nameof(QuicTransportErrorCode.AeadLimitReached), aeadLimitName);
        Assert.Equal(aeadLimitName, ((QuicTransportErrorCode)aeadLimitWireValue).ToString());
        Assert.NotEmpty(aeadLimitDescription);
    }
}
