namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5-0012">The Retry Integrity Tag field MUST be 128 bits long.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P5-0012")]
public sealed class REQ_QUIC_RFC9000_S17P2P5_0012
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5-0012">The Retry Integrity Tag field MUST be 128 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5-0012")]
    public void TryParseLongHeader_PreservesTheRetryIntegrityTagLength()
    {
        byte[] retryIntegrityTag = new byte[16];
        byte[] packet = QuicRetryPacketRequirementTestData.BuildRetryPacket(retryIntegrityTag: retryIntegrityTag);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(16, header.VersionSpecificData.Length);
        Assert.True(retryIntegrityTag.AsSpan().SequenceEqual(header.VersionSpecificData));
    }
}
