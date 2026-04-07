namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S10-0001")]
public sealed class REQ_QUIC_RFC9001_S10_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void QuicTransportParametersCodec_ExposesTheRegisteredTlsExtensionMetadata()
    {
        Assert.Equal((ushort)57, QuicTransportParametersCodec.QuicTransportParametersExtensionType);
        Assert.True(QuicTransportParametersCodec.QuicTransportParametersRecommended);
        Assert.True(QuicTransportParametersCodec.QuicTransportParametersClientHello);
        Assert.True(QuicTransportParametersCodec.QuicTransportParametersEncryptedExtensions);
    }
}
