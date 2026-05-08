namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S3-0005")]
public sealed class REQ_QUIC_RFC9001_S3_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CanonicalArtifactsKeepSecurityCriticalNegotiationOnTlsBridge()
    {
        QuicRfc9001TailProofTestSupport.AssertCanonicalArtifactsOwnRequirement(
            "REQ-QUIC-RFC9001-S3-0005",
            "src/Incursa.Quic/QuicTlsTransport.cs",
            "src/Incursa.Quic/QuicTransportTlsBridgeState.cs",
            "src/Incursa.Quic/QuicConnectionRuntime.cs");
    }
}
