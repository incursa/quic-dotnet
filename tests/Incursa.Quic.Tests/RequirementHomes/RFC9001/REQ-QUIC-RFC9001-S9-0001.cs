namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S9-0001")]
public sealed class REQ_QUIC_RFC9001_S9_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CanonicalArtifactsApplyTlsSecurityConsiderationsToQuicTlsUse()
    {
        QuicRfc9001TailProofTestSupport.AssertCanonicalArtifactsOwnRequirement(
            "REQ-QUIC-RFC9001-S9-0001",
            "src/Incursa.Quic/QuicTlsTransport.cs",
            "src/Incursa.Quic/QuicTransportTlsBridgeState.cs",
            "src/Incursa.Quic/QuicTlsPacketProtectionMaterial.cs");
    }
}
