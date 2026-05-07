namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S20P1-0006")]
public sealed class REQ_QUIC_RFC9000_S20P1_0006
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TransportErrorCodeRegistry_ReservesTheHandshakeSpecificCodeRange()
    {
        Assert.False(Enum.IsDefined(typeof(QuicTransportErrorCode), 0x100UL));
        Assert.False(Enum.IsDefined(typeof(QuicTransportErrorCode), 0x1FFUL));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0006")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TransportErrorCodeRegistry_DoesNotDefineHandshakeSpecificValues()
    {
        Assert.DoesNotContain(
            QuicTransportErrorCodeRegistryProofSupport.DefinedTransportErrorCodes,
            candidate => candidate.WireValue is >= 0x100UL and <= 0x1FFUL);
    }
}
