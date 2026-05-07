namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S20P1-0007")]
public sealed class REQ_QUIC_RFC9000_S20P1_0007
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0007")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TransportErrorCodeRegistry_LeavesHandshakeErrorsToQuicTls()
    {
        Assert.Equal(0x10UL, QuicTransportErrorCodeRegistryProofSupport.DefinedTransportErrorCodes[^1].WireValue);
        Assert.Equal(nameof(QuicTransportErrorCode.NoViablePath), QuicTransportErrorCodeRegistryProofSupport.DefinedTransportErrorCodes[^1].ExpectedName);
    }
}
