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
        (ulong wireValue, string expectedName, string expectedDescription) = Assert.Single(
            QuicTransportErrorCodeRegistryProofSupport.DefinedTransportErrorCodes,
            candidate => candidate.ExpectedName == nameof(QuicTransportErrorCode.NoViablePath));

        Assert.Equal(0x10UL, wireValue);
        Assert.Equal(nameof(QuicTransportErrorCode.NoViablePath), expectedName);
        Assert.NotEmpty(expectedDescription);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0005")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TransportErrorCodeRegistry_DoesNotDefineUnknownValuesBeyondTheRFC9000Set()
    {
        Assert.False(Enum.IsDefined(typeof(QuicTransportErrorCode), 0x11UL));
        Assert.False(Enum.IsDefined(typeof(QuicTransportErrorCode), 0xFFUL));
    }
}
