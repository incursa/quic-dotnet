namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S20P1-0006")]
public sealed class REQ_QUIC_RFC9000_S20P1_0006
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0006")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TransportErrorCodeRegistry_DoesNotAssignDefinedValuesToTheHandshakeReservedRange()
    {
        Assert.All(
            QuicTransportErrorCodeRegistryProofSupport.DefinedTransportErrorCodes,
            entry => Assert.InRange(entry.WireValue, 0x00UL, 0xFFUL));
    }
}
