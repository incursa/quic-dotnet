namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S10-0003")]
public sealed class REQ_QUIC_RFC9001_S10_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QuicTransportParametersCodec_ListsClientHelloAndEncryptedExtensionsInTheTls13Column()
    {
        Assert.True(QuicTransportParametersCodec.QuicTransportParametersClientHello);
        Assert.True(QuicTransportParametersCodec.QuicTransportParametersEncryptedExtensions);
    }
}
