namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S20P1-0005")]
public sealed class REQ_QUIC_RFC9000_S20P1_0005
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TransportErrorCodeRegistry_ExposesNoViablePath()
    {
        (ulong wireValue, string expectedName, string expectedDescription) =
            QuicTransportErrorCodeRegistryProofSupport.GetDefinedTransportErrorCode(nameof(QuicTransportErrorCode.NoViablePath));

        Assert.Equal(0x10UL, wireValue);
        Assert.Equal(nameof(QuicTransportErrorCode.NoViablePath), expectedName);
        Assert.Equal(expectedName, ((QuicTransportErrorCode)wireValue).ToString());
        Assert.NotEmpty(expectedDescription);
    }
}
