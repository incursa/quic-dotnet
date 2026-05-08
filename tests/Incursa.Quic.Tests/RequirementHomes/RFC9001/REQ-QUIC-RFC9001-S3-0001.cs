namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S3-0001")]
public sealed class REQ_QUIC_RFC9001_S3_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CanonicalArtifactsAssignPacketProtectionResponsibilityToQuic()
    {
        QuicRfc9001TailProofTestSupport.AssertCanonicalArtifactsOwnRequirement("REQ-QUIC-RFC9001-S3-0001");
    }
}
