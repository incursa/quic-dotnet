namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0019">Initial packets sent by the server MUST set the Token Length field to 0.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P2-0019")]
public sealed class REQ_QUIC_RFC9000_S17P2P2_0019
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0019">Initial packets sent by the server MUST set the Token Length field to 0.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0019")]
    public void TryBuildProtectedInitialPacketForHandshakeDestination_EncodesZeroTokenLength()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            InitialDestinationConnectionId,
            out QuicInitialPacketProtection senderProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            InitialDestinationConnectionId,
            out QuicInitialPacketProtection receiverProtection));

        QuicHandshakeFlowCoordinator coordinator = new(InitialDestinationConnectionId, InitialSourceConnectionId);
        Assert.True(coordinator.TryBuildProtectedInitialPacketForHandshakeDestination(
            [0xA1, 0xA2],
            cryptoPayloadOffset: 0,
            senderProtection,
            out byte[] protectedPacket));

        Assert.True(coordinator.TryOpenInitialPacket(
            protectedPacket,
            receiverProtection,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        Assert.True(QuicPacketParsing.TryParseLongHeaderFields(
            openedPacket,
            out byte headerControlBits,
            out uint version,
            out _,
            out _,
            out ReadOnlySpan<byte> versionSpecificData));
        Assert.Equal((uint)1, version);
        Assert.Equal(
            (byte)QuicLongPacketTypeBits.Initial,
            (byte)((headerControlBits & QuicPacketHeaderBits.LongPacketTypeBitsMask) >> QuicPacketHeaderBits.LongPacketTypeBitsShift));
        Assert.True(
            QuicVariableLengthInteger.TryParse(
                versionSpecificData,
                out ulong tokenLength,
                out int tokenLengthBytesConsumed));
        Assert.Equal(0UL, tokenLength);
        Assert.Equal(1, tokenLengthBytesConsumed);
        Assert.Equal(openedPacket.Length, payloadOffset + payloadLength);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryBuildProtectedInitialPacketForHandshakeDestination_DoesNotUseTheClientRetryTokenPath()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            InitialDestinationConnectionId,
            out QuicInitialPacketProtection clientSenderProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            InitialDestinationConnectionId,
            out QuicInitialPacketProtection serverReceiverProtection));

        QuicHandshakeFlowCoordinator clientCoordinator = new(InitialDestinationConnectionId, InitialSourceConnectionId);
        byte[] retryToken = [0xAA, 0xBB];
        Assert.True(clientCoordinator.TryBuildProtectedInitialPacket(
            [0xA1, 0xA2],
            cryptoPayloadOffset: 0,
            destinationConnectionId: [0x31, 0x32],
            retryToken,
            clientSenderProtection,
            out byte[] clientProtectedPacket));
        Assert.True(clientCoordinator.TryOpenInitialPacket(
            clientProtectedPacket,
            serverReceiverProtection,
            out byte[] clientOpenedPacket,
            out _,
            out _));
        QuicS17P2P2TestSupport.AssertInitialTokenLength(clientOpenedPacket, (ulong)retryToken.Length);

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            InitialDestinationConnectionId,
            out QuicInitialPacketProtection serverSenderProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            InitialDestinationConnectionId,
            out QuicInitialPacketProtection clientReceiverProtection));

        QuicHandshakeFlowCoordinator serverCoordinator = new(InitialDestinationConnectionId, InitialSourceConnectionId);
        Assert.True(serverCoordinator.TryBuildProtectedInitialPacketForHandshakeDestination(
            [0xB1, 0xB2],
            cryptoPayloadOffset: 0,
            serverSenderProtection,
            out byte[] serverProtectedPacket));
        Assert.True(serverCoordinator.TryOpenInitialPacket(
            serverProtectedPacket,
            clientReceiverProtection,
            out byte[] serverOpenedPacket,
            out _,
            out _));
        QuicS17P2P2TestSupport.AssertInitialTokenLength(serverOpenedPacket, 0UL);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryBuildProtectedInitialPacketForHandshakeDestination_EncodesZeroTokenLengthForTheSmallestCryptoPayload()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            InitialDestinationConnectionId,
            out QuicInitialPacketProtection senderProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            InitialDestinationConnectionId,
            out QuicInitialPacketProtection receiverProtection));

        QuicHandshakeFlowCoordinator coordinator = new(InitialDestinationConnectionId, InitialSourceConnectionId);
        Assert.True(coordinator.TryBuildProtectedInitialPacketForHandshakeDestination(
            [0xA1],
            cryptoPayloadOffset: 0,
            senderProtection,
            out byte[] protectedPacket));
        Assert.True(coordinator.TryOpenInitialPacket(
            protectedPacket,
            receiverProtection,
            out byte[] openedPacket,
            out _,
            out _));

        QuicS17P2P2TestSupport.AssertInitialTokenLength(openedPacket, 0UL);
    }
}
