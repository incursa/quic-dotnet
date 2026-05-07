namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S20P1-0003")]
public sealed class REQ_QUIC_RFC9000_S20P1_0003
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TransportErrorCodeRegistry_ExposesInternalError()
    {
        (ulong wireValue, string expectedName, string expectedDescription) =
            QuicTransportErrorCodeRegistryProofSupport.GetDefinedTransportErrorCode(nameof(QuicTransportErrorCode.InternalError));

        Assert.Equal(0x01UL, wireValue);
        Assert.Equal(nameof(QuicTransportErrorCode.InternalError), expectedName);
        Assert.Equal(expectedName, ((QuicTransportErrorCode)wireValue).ToString());
        Assert.NotEmpty(expectedDescription);
    }
}
