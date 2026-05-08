namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S3-0010")]
public sealed class REQ_QUIC_RFC9001_S3_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CanonicalArtifactsOwnTlsToQuicUpdateDelivery()
    {
        QuicRfc9001TailProofTestSupport.AssertCanonicalArtifactsOwnRequirement(
            "REQ-QUIC-RFC9001-S3-0010",
            "src/Incursa.Quic/QuicTlsTransport.cs",
            "src/Incursa.Quic/QuicTransportTlsBridgeState.cs");
    }
}
