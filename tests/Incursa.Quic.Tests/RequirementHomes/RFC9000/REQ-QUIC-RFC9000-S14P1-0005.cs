namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S14P1-0005">Datagrams containing Initial packets MAY exceed 1200 bytes if the sender believes that the network path and peer both support the size that it chooses.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S14P1-0005")]
public sealed class REQ_QUIC_RFC9000_S14P1_0005
{
    private static readonly byte[] InitialDestinationConnectionId =
    [
        0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
    ];

    private static readonly byte[] InitialSourceConnectionId =
    [
        0x01, 0x02, 0x03, 0x04,
    ];

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildProtectedInitialPacket_AllowsAnOversizedDatagramWhenThePayloadGrowsPastTheRFCMinimum()
    {
        byte[] cryptoPayload = new byte[1400];
        for (int index = 0; index < cryptoPayload.Length; index++)
        {
            cryptoPayload[index] = (byte)index;
        }

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            InitialDestinationConnectionId,
            out QuicInitialPacketProtection clientProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            InitialDestinationConnectionId,
            out QuicInitialPacketProtection serverProtection));

        QuicHandshakeFlowCoordinator coordinator = new(InitialDestinationConnectionId, InitialSourceConnectionId);

        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            cryptoPayload,
            cryptoPayloadOffset: 0,
            clientProtection,
            out byte[] protectedPacket));
        Assert.True(protectedPacket.Length > QuicVersionNegotiation.Version1MinimumDatagramPayloadSize);

        Assert.True(coordinator.TryOpenInitialPacket(
            protectedPacket,
            serverProtection,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            out QuicCryptoFrame parsedFrame,
            out int bytesConsumed));

        Assert.Equal(payloadLength, bytesConsumed);
        Assert.Equal(cryptoPayload.Length, parsedFrame.CryptoData.Length);
        Assert.Equal(0UL, parsedFrame.Offset);
        Assert.True(parsedFrame.CryptoData.SequenceEqual(cryptoPayload));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryBuildProtectedInitialPacket_RejectsEmptyCryptoPayloads()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            InitialDestinationConnectionId,
            out QuicInitialPacketProtection clientProtection));

        QuicHandshakeFlowCoordinator coordinator = new(InitialDestinationConnectionId, InitialSourceConnectionId);

        Assert.False(coordinator.TryBuildProtectedInitialPacket(
            ReadOnlySpan<byte>.Empty,
            cryptoPayloadOffset: 0,
            clientProtection,
            out _));
    }
}
