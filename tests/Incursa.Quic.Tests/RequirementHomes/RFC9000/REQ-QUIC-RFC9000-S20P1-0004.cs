namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S20P1-0004")]
public sealed class REQ_QUIC_RFC9000_S20P1_0004
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TransportErrorCodeRegistry_ExposesCryptoBufferExceeded()
    {
        (ulong wireValue, string expectedName, string expectedDescription) =
            QuicTransportErrorCodeRegistryProofSupport.GetDefinedTransportErrorCode(nameof(QuicTransportErrorCode.CryptoBufferExceeded));

        Assert.Equal(0x0DUL, wireValue);
        Assert.Equal(nameof(QuicTransportErrorCode.CryptoBufferExceeded), expectedName);
        Assert.Equal(expectedName, ((QuicTransportErrorCode)wireValue).ToString());
        Assert.NotEmpty(expectedDescription);
    }
}
