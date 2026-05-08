namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S3-0004")]
public sealed class REQ_QUIC_RFC9001_S3_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CanonicalArtifactsKeepTlsRecordResponsibilitiesInQuicPacketProtection()
    {
        QuicRfc9001TailProofTestSupport.AssertCanonicalArtifactsOwnRequirement(
            "REQ-QUIC-RFC9001-S3-0004",
            "src/Incursa.Quic/QuicTlsTransport.cs",
            "src/Incursa.Quic/QuicTlsTranscriptProgress.cs",
            "src/Incursa.Quic/QuicConnectionRuntime.cs");
    }
}
