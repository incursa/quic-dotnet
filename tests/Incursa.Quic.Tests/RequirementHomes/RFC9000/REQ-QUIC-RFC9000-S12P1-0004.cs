namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P1-0004">Initial protection exists to ensure that the sender of the packet is on the network path.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P1-0004")]
public sealed class REQ_QUIC_RFC9000_S12P1_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryProtectInitialPacket_LeavesTheLongHeaderConnectionIdsVisible()
    {
        byte[] clientInitialDcid =
        [
            0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
        ];
        byte[] sourceConnectionId =
        [
            0x21, 0x22, 0x23, 0x24,
        ];

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            clientInitialDcid,
            out QuicInitialPacketProtection senderProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            clientInitialDcid,
            out QuicInitialPacketProtection receiverProtection));

        byte[] plaintextPacket = QuicInitialPacketProtectionTestData.BuildInitialPlaintextPacket(
            destinationConnectionId: clientInitialDcid,
            sourceConnectionId: sourceConnectionId,
            token: [],
            packetNumber: [0x01],
            plaintextPayload: QuicS12P3TestSupport.CreateSequentialBytes(0x10, 20));

        byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        Assert.True(senderProtection.TryProtect(plaintextPacket, protectedPacket, out int protectedBytesWritten));
        Assert.Equal(protectedPacket.Length, protectedBytesWritten);
        Assert.True(clientInitialDcid.AsSpan().SequenceEqual(protectedPacket.AsSpan(6, clientInitialDcid.Length)));
        int sourceConnectionIdOffset = 7 + clientInitialDcid.Length;
        Assert.True(sourceConnectionId.AsSpan().SequenceEqual(
            protectedPacket.AsSpan(sourceConnectionIdOffset, sourceConnectionId.Length)));

        byte[] openedPacket = new byte[plaintextPacket.Length];
        Assert.True(receiverProtection.TryOpen(
            protectedPacket,
            openedPacket,
            out int openedBytesWritten));
        Assert.Equal(plaintextPacket.Length, openedBytesWritten);
        Assert.True(plaintextPacket.AsSpan().SequenceEqual(openedPacket));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryOpenInitialPacket_WithADifferentClientInitialDcid_DoesNotSucceed()
    {
        byte[] clientInitialDcid =
        [
            0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
        ];
        byte[] differentClientInitialDcid =
        [
            0x93, 0x84, 0xD8, 0xE0, 0x4E, 0x61, 0x47, 0x18,
        ];

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            clientInitialDcid,
            out QuicInitialPacketProtection senderProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            differentClientInitialDcid,
            out QuicInitialPacketProtection receiverProtection));

        byte[] plaintextPacket = QuicInitialPacketProtectionTestData.BuildInitialPlaintextPacket(
            destinationConnectionId: clientInitialDcid,
            sourceConnectionId:
            [
                0x21, 0x22, 0x23, 0x24,
            ],
            token: [],
            packetNumber: [0x01],
            plaintextPayload: QuicS12P3TestSupport.CreateSequentialBytes(0x10, 20));

        byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        Assert.True(senderProtection.TryProtect(plaintextPacket, protectedPacket, out int protectedBytesWritten));

        Assert.False(receiverProtection.TryOpen(
            protectedPacket.AsSpan(0, protectedBytesWritten),
            new byte[plaintextPacket.Length],
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryProtectInitialPacket_AcceptsTheMaximumClientInitialDcidLength()
    {
        byte[] maximumClientInitialDcid =
        [
            0xA0, 0xA1, 0xA2, 0xA3, 0xA4,
            0xA5, 0xA6, 0xA7, 0xA8, 0xA9,
            0xAA, 0xAB, 0xAC, 0xAD, 0xAE,
            0xAF, 0xB0, 0xB1, 0xB2, 0xB3,
        ];
        byte[] sourceConnectionId =
        [
            0x31, 0x32, 0x33, 0x34,
        ];

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            maximumClientInitialDcid,
            out QuicInitialPacketProtection senderProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            maximumClientInitialDcid,
            out QuicInitialPacketProtection receiverProtection));

        byte[] plaintextPacket = QuicInitialPacketProtectionTestData.BuildInitialPlaintextPacket(
            destinationConnectionId: maximumClientInitialDcid,
            sourceConnectionId: sourceConnectionId,
            token: [],
            packetNumber: [0x01],
            plaintextPayload: QuicS12P3TestSupport.CreateSequentialBytes(0x20, 20));

        byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        Assert.True(senderProtection.TryProtect(plaintextPacket, protectedPacket, out int protectedBytesWritten));
        Assert.Equal(protectedPacket.Length, protectedBytesWritten);

        byte[] openedPacket = new byte[plaintextPacket.Length];
        Assert.True(receiverProtection.TryOpen(
            protectedPacket,
            openedPacket,
            out int openedBytesWritten));
        Assert.Equal(plaintextPacket.Length, openedBytesWritten);
        Assert.True(plaintextPacket.AsSpan().SequenceEqual(openedPacket));
    }
}
