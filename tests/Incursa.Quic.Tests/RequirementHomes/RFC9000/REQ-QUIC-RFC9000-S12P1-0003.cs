namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P1-0003">Initial packets use an AEAD function, the keys for which are derived using a value that is visible on the wire.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P1-0003")]
public sealed class REQ_QUIC_RFC9000_S12P1_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryProtectInitialPacket_UsesTheVisibleClientInitialDcidWhenDerivingKeys()
    {
        byte[] clientInitialDcid =
        [
            0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
        ];
        byte[] sourceConnectionId =
        [
            0x01, 0x02, 0x03, 0x04,
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
}
