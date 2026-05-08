namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S3-0007")]
public sealed class REQ_QUIC_RFC9001_S3_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CanonicalArtifactsKeepTlsDeliveryOnQuicCryptoFrames()
    {
        QuicRfc9001TailProofTestSupport.AssertCanonicalArtifactsOwnRequirement(
            "REQ-QUIC-RFC9001-S3-0007",
            "src/Incursa.Quic/QuicFrameCodec.cs",
            "src/Incursa.Quic/QuicCryptoFrame.cs",
            "src/Incursa.Quic/QuicTransportTlsBridgeState.cs");
    }
}
