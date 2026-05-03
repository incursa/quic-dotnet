namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P1-0006">The AEAD also protects Initial packets against accidental modification.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P1-0006")]
public sealed class REQ_QUIC_RFC9000_S12P1_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryOpenInitialPacket_AuthenticatesTheOriginalPacketAndRejectsTampering()
    {
        byte[] clientInitialDcid =
        [
            0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
        ];
        byte[] sourceConnectionId =
        [
            0x71, 0x72, 0x73, 0x74,
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

        byte[] openedPacket = new byte[plaintextPacket.Length];
        Assert.True(receiverProtection.TryOpen(
            protectedPacket,
            openedPacket,
            out int openedBytesWritten));
        Assert.Equal(plaintextPacket.Length, openedBytesWritten);
        Assert.True(plaintextPacket.AsSpan().SequenceEqual(openedPacket));

        byte[] tamperedPacket = protectedPacket.ToArray();
        tamperedPacket[^1] ^= 0x80;

        Assert.False(receiverProtection.TryOpen(
            tamperedPacket,
            new byte[plaintextPacket.Length],
            out _));
    }
}
