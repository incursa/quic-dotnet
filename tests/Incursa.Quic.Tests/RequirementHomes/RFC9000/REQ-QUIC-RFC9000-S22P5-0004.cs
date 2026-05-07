namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S22P5-0004")]
public sealed class REQ_QUIC_RFC9000_S22P5_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TransportErrorCodeRegistry_UsesShortMnemonicCodeNames()
    {
        foreach ((ulong wireValue, string expectedName, _) in QuicTransportErrorCodeRegistryProofSupport.DefinedTransportErrorCodes)
        {
            QuicTransportErrorCode code = (QuicTransportErrorCode)wireValue;

            Assert.Equal(wireValue, (ulong)code);
            Assert.Equal(expectedName, code.ToString());
        }
    }
}
