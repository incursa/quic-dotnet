namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S14P1-0002">Initial packets can even be coalesced with invalid packets, which a receiver will discard.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S14P1-0002")]
public sealed class REQ_QUIC_RFC9000_S14P1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_AllowsAValidInitialPacketToBeCoalescedWithAnInvalidTrailingPacket()
    {
        byte[] initialVersionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
            token: [0xA1],
            packetNumber: [0x01, 0x02],
            protectedPayload: [0xB1]);
        byte[] initialPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x42,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            initialVersionSpecificData);
        byte[] invalidTrailingPacket = QuicHeaderTestData.BuildShortHeader(0x18, [0x30, 0x31, 0x32]);
        byte[] datagram = [.. initialPacket, .. invalidTrailingPacket];

        Assert.True(QuicPacketParser.TryParseLongHeader(datagram, out QuicLongHeaderPacket parsedHeader));
        Assert.Equal((byte)QuicLongPacketTypeBits.Initial, parsedHeader.LongPacketTypeBits);
        Assert.Equal(1u, parsedHeader.Version);
        Assert.Equal(initialVersionSpecificData.Length + invalidTrailingPacket.Length, parsedHeader.VersionSpecificData.Length);
        Assert.True(initialVersionSpecificData.AsSpan().SequenceEqual(parsedHeader.VersionSpecificData[..initialVersionSpecificData.Length]));
        Assert.True(invalidTrailingPacket.AsSpan().SequenceEqual(parsedHeader.VersionSpecificData[initialVersionSpecificData.Length..]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseShortHeader_RejectsTheInvalidCoalescedPacketOnItsOwn()
    {
        byte[] invalidTrailingPacket = QuicHeaderTestData.BuildShortHeader(0x18, [0x30, 0x31, 0x32]);

        Assert.False(QuicPacketParser.TryParseShortHeader(invalidTrailingPacket, out _));
    }
}
