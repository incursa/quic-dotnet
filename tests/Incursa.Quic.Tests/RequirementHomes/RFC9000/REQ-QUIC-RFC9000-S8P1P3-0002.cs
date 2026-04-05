namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P1P3-0002">The client MUST include the token in all Initial packets it sends, unless a Retry replaces the token with a newer one.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S8P1P3-0002")]
public sealed class REQ_QUIC_RFC9000_S8P1P3_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_PreservesTheTokenEncodedInInitialPackets()
    {
        byte[] token = [0xA0, 0xA1, 0xA2];
        byte[] versionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
            token,
            packetNumber: [0x01],
            protectedPayload: [0xBB, 0xBC]);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId: [0x11],
            sourceConnectionId: [0x22],
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((uint)1, header.Version);
        Assert.Equal((byte)0x00, header.LongPacketTypeBits);
        Assert.True(
            QuicVariableLengthInteger.TryParse(
                header.VersionSpecificData,
                out ulong tokenLength,
                out int tokenLengthBytesConsumed));
        Assert.Equal((ulong)token.Length, tokenLength);
        Assert.True(token.AsSpan().SequenceEqual(header.VersionSpecificData.Slice(tokenLengthBytesConsumed, token.Length)));
    }
}
