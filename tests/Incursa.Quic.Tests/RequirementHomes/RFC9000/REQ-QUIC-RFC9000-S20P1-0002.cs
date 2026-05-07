namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S20P1-0002")]
public sealed class REQ_QUIC_RFC9000_S20P1_0002
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TransportErrorCodeRegistry_ExposesNoError()
    {
        (ulong wireValue, string expectedName, string expectedDescription) =
            QuicTransportErrorCodeRegistryProofSupport.GetDefinedTransportErrorCode(nameof(QuicTransportErrorCode.NoError));

        Assert.Equal(0x00UL, wireValue);
        Assert.Equal(nameof(QuicTransportErrorCode.NoError), expectedName);
        Assert.Equal(expectedName, ((QuicTransportErrorCode)wireValue).ToString());
        Assert.NotEmpty(expectedDescription);
    }
}
