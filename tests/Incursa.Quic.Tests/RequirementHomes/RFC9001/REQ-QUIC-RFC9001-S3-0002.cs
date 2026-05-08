namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S3-0002")]
public sealed class REQ_QUIC_RFC9001_S3_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CanonicalArtifactsBindPacketKeysToTlsDerivedMaterial()
    {
        QuicRfc9001TailProofTestSupport.AssertCanonicalArtifactsOwnRequirement(
            "REQ-QUIC-RFC9001-S3-0002",
            "src/Incursa.Quic/QuicTlsPacketProtectionMaterial.cs",
            "src/Incursa.Quic/QuicTlsTransport.cs",
            "src/Incursa.Quic/QuicTransportTlsBridgeState.cs");
    }
}
