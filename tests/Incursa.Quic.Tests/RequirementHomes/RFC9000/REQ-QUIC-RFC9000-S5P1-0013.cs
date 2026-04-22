namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P1-0013")]
public sealed class REQ_QUIC_RFC9000_S5P1_0013
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1-0013">A zero-length connection ID MAY be used when a connection ID is not needed to route to the correct endpoint.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P1-0013")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseLongHeader_AllowsZeroLengthConnectionIds()
    {
        byte[] versionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
            token: [],
            packetNumber: [0x01],
            protectedPayload: [0xAA]);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId: [],
            sourceConnectionId: [],
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((uint)1, header.Version);
        Assert.Equal(0, header.DestinationConnectionIdLength);
        Assert.Equal(0, header.SourceConnectionIdLength);
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1-0013">A zero-length connection ID MAY be used when a connection ID is not needed to route to the correct endpoint.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P1-0013")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryBuildProtectedInitialPacketForHandshakeDestination_AllowsAZeroLengthPeerConnectionId()
    {
        byte[] originalDestinationConnectionId = [0x11, 0x12, 0x13, 0x14];
        byte[] serverSourceConnectionId = [0x21, 0x22, 0x23, 0x24];

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            originalDestinationConnectionId,
            out QuicInitialPacketProtection serverProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            originalDestinationConnectionId,
            out QuicInitialPacketProtection clientProtection));

        QuicHandshakeFlowCoordinator coordinator = new(originalDestinationConnectionId, serverSourceConnectionId);
        Assert.True(coordinator.TrySetHandshakeDestinationConnectionId([]));
        Assert.True(coordinator.TryBuildProtectedInitialPacketForHandshakeDestination(
            [0xA1, 0xA2, 0xA3],
            cryptoPayloadOffset: 0,
            serverProtection,
            out byte[] protectedPacket));

        Assert.True(coordinator.TryOpenInitialPacket(
            protectedPacket,
            clientProtection,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));
        Assert.True(QuicPacketParsing.TryParseLongHeaderFields(
            openedPacket,
            out byte headerControlBits,
            out uint version,
            out ReadOnlySpan<byte> destinationConnectionId,
            out ReadOnlySpan<byte> sourceConnectionId,
            out _));
        Assert.Equal((uint)1, version);
        Assert.Equal(
            (byte)QuicLongPacketTypeBits.Initial,
            (byte)((headerControlBits & QuicPacketHeaderBits.LongPacketTypeBitsMask) >> QuicPacketHeaderBits.LongPacketTypeBitsShift));
        Assert.Empty(destinationConnectionId.ToArray());
        Assert.Equal(serverSourceConnectionId, sourceConnectionId.ToArray());

        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            out QuicCryptoFrame cryptoFrame,
            out _));
        Assert.Equal(0UL, cryptoFrame.Offset);
        Assert.Equal([0xA1, 0xA2, 0xA3], cryptoFrame.CryptoData.ToArray());
    }
}
