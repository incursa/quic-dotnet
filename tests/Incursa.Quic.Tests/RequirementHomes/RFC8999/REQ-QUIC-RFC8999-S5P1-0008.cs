namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0008">The remainder of a QUIC long header packet MUST contain version-specific content.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC8999-S5P1-0008")]
public sealed class REQ_QUIC_RFC8999_S5P1_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0008">The remainder of a QUIC long header packet MUST contain version-specific content.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC8999-S5P1-0008")]
    public void TryParseVersionNegotiation_PreservesTheVersionSpecificRemainder()
    {
        byte[] supportedVersionBytes =
        [
            0x11, 0x22, 0x33, 0x44,
            0xAA, 0xBB, 0xCC, 0xDD,
        ];
        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4C,
            destinationConnectionId: [0x01, 0x02],
            sourceConnectionId: [0x03, 0x04, 0x05],
            supportedVersions: [0x11223344, 0xAABBCCDD]);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(packet, out QuicVersionNegotiationPacket header));
        Assert.Equal((uint)0, header.Version);
        Assert.True(header.IsVersionNegotiation);
        Assert.True(supportedVersionBytes.AsSpan().SequenceEqual(header.SupportedVersionBytes));
        Assert.Equal(2, header.SupportedVersionCount);
        Assert.True(header.ContainsSupportedVersion(0x11223344));
        Assert.True(header.ContainsSupportedVersion(0xAABBCCDD));
    }
}
