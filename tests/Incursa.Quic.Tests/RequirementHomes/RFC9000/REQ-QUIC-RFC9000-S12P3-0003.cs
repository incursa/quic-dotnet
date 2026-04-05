namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P3-0003">Version Negotiation (Section 17.2.1) and Retry (Section 17.2.5) packets MUST NOT include a packet number.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P3-0003")]
public sealed class REQ_QUIC_RFC9000_S12P3_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryGetPacketNumberSpace_RejectsVersionNegotiationAndRetryPackets()
    {
        byte[] versionNegotiationPacket = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4A,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            supportedVersions: [0x11223344, 0x55667788]);
        byte[] retryPacket = QuicRetryPacketRequirementTestData.BuildRetryPacket();

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(versionNegotiationPacket, out QuicVersionNegotiationPacket versionNegotiationHeader));
        Assert.Equal(2, versionNegotiationHeader.SupportedVersionCount);
        Assert.False(QuicPacketParser.TryGetPacketNumberSpace(versionNegotiationPacket, out _));

        Assert.True(QuicPacketParser.TryParseLongHeader(retryPacket, out QuicLongHeaderPacket retryHeader));
        Assert.Equal((byte)0x03, retryHeader.LongPacketTypeBits);
        Assert.False(QuicPacketParser.TryGetPacketNumberSpace(retryPacket, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseLongHeader_TreatsRetryPacketsAsOpaqueTrailingDataSoTheyCannotBeFollowedByAnotherPacket()
    {
        byte[] retryVersionSpecificData = [0x30, 0x31, 0x32, 0x33];
        byte[] trailingPacket = QuicHeaderTestData.BuildShortHeader(0x24, [0x40, 0x41, 0x42]);
        byte[] datagram = QuicHeaderTestData.BuildLongHeader(
            QuicRetryPacketRequirementTestData.BuildRetryHeaderControlBits(),
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            versionSpecificData: [.. retryVersionSpecificData, .. trailingPacket]);

        Assert.True(QuicPacketParser.TryParseLongHeader(datagram, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x03, header.LongPacketTypeBits);
        Assert.Equal(retryVersionSpecificData.Length + trailingPacket.Length, header.VersionSpecificData.Length);
        Assert.True(trailingPacket.AsSpan().SequenceEqual(header.VersionSpecificData.Slice(retryVersionSpecificData.Length)));
    }
}
