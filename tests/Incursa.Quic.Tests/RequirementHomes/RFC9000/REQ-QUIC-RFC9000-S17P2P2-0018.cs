namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0018">A client that receives an Initial packet with a non-zero Token Length field MUST either discard the packet or generate a connection error of type PROTOCOL_VIOLATION.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P2-0018")]
public sealed class REQ_QUIC_RFC9000_S17P2P2_0018
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
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0018">A client that receives an Initial packet with a non-zero Token Length field MUST either discard the packet or generate a connection error of type PROTOCOL_VIOLATION.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0018")]
    public void TryOpenInitialPacket_ForClientReceipt_AllowsZeroTokenLength()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            InitialDestinationConnectionId,
            out QuicInitialPacketProtection senderProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            InitialDestinationConnectionId,
            out QuicInitialPacketProtection receiverProtection));

        (byte[] plaintextPacket, byte[] protectedPacket) = BuildProtectedInitialPacket(
            token: [],
            senderProtection);

        QuicHandshakeFlowCoordinator coordinator = new();
        Assert.True(coordinator.TryOpenInitialPacket(
            protectedPacket,
            receiverProtection,
            requireZeroTokenLength: true,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        Assert.True(plaintextPacket.AsSpan().SequenceEqual(openedPacket));
        Assert.True(payloadOffset > 0);
        Assert.True(payloadLength > 0);
        Assert.Equal(openedPacket.Length, payloadOffset + payloadLength);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0018">A client that receives an Initial packet with a non-zero Token Length field MUST either discard the packet or generate a connection error of type PROTOCOL_VIOLATION.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0018")]
    public void TryOpenInitialPacket_ForClientReceipt_RejectsNonZeroTokenLength()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            InitialDestinationConnectionId,
            out QuicInitialPacketProtection senderProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            InitialDestinationConnectionId,
            out QuicInitialPacketProtection receiverProtection));

        var (_, protectedPacket) = BuildProtectedInitialPacket(
            token: [0xAA],
            senderProtection);

        QuicHandshakeFlowCoordinator coordinator = new();
        Assert.False(coordinator.TryOpenInitialPacket(
            protectedPacket,
            receiverProtection,
            requireZeroTokenLength: true,
            out _,
            out _,
            out _));
    }

    private static (byte[] PlaintextPacket, byte[] ProtectedPacket) BuildProtectedInitialPacket(
        ReadOnlySpan<byte> token,
        QuicInitialPacketProtection senderProtection)
    {
        byte[] plaintextPacket = QuicInitialPacketProtectionTestData.BuildInitialPlaintextPacket(
            InitialDestinationConnectionId,
            InitialSourceConnectionId,
            token,
            packetNumber: [0x01],
            plaintextPayload: QuicS12P3TestSupport.CreateSequentialBytes(0x30, 20));

        byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        Assert.True(senderProtection.TryProtect(plaintextPacket, protectedPacket, out int protectedBytesWritten));
        Assert.Equal(protectedPacket.Length, protectedBytesWritten);

        return (plaintextPacket, protectedPacket);
    }
}
