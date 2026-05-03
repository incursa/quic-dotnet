namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P1-0005">Any entity that receives an Initial packet from a client can recover the keys that will allow them to both read the contents of the packet and generate Initial packets that will be successfully authenticated at either endpoint.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P1-0005")]
public sealed class REQ_QUIC_RFC9000_S12P1_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryProtectInitialPacket_AndTryOpenInitialPacket_InBothDirections()
    {
        byte[] clientInitialDcid =
        [
            0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
        ];
        byte[] clientSourceConnectionId =
        [
            0x41, 0x42, 0x43, 0x44,
        ];
        byte[] serverSourceConnectionId =
        [
            0x51, 0x52, 0x53, 0x54,
        ];

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            clientInitialDcid,
            out QuicInitialPacketProtection clientProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            clientInitialDcid,
            out QuicInitialPacketProtection serverProtection));

        byte[] clientPlaintextPacket = QuicInitialPacketProtectionTestData.BuildInitialPlaintextPacket(
            destinationConnectionId: clientInitialDcid,
            sourceConnectionId: clientSourceConnectionId,
            token: [],
            packetNumber: [0x01],
            plaintextPayload: QuicS12P3TestSupport.CreateSequentialBytes(0x10, 24));
        byte[] clientProtectedPacket = new byte[clientPlaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        Assert.True(clientProtection.TryProtect(clientPlaintextPacket, clientProtectedPacket, out int clientProtectedBytesWritten));

        byte[] clientOpenedPacket = new byte[clientPlaintextPacket.Length];
        Assert.True(serverProtection.TryOpen(
            clientProtectedPacket.AsSpan(0, clientProtectedBytesWritten),
            clientOpenedPacket,
            out int clientOpenedBytesWritten));
        Assert.Equal(clientPlaintextPacket.Length, clientOpenedBytesWritten);
        Assert.True(clientPlaintextPacket.AsSpan().SequenceEqual(clientOpenedPacket));

        byte[] serverPlaintextPacket = QuicInitialPacketProtectionTestData.BuildInitialPlaintextPacket(
            destinationConnectionId: clientInitialDcid,
            sourceConnectionId: serverSourceConnectionId,
            token: [],
            packetNumber: [0x02],
            plaintextPayload: QuicS12P3TestSupport.CreateSequentialBytes(0x30, 24));
        byte[] serverProtectedPacket = new byte[serverPlaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        Assert.True(serverProtection.TryProtect(serverPlaintextPacket, serverProtectedPacket, out int serverProtectedBytesWritten));

        byte[] serverOpenedPacket = new byte[serverPlaintextPacket.Length];
        Assert.True(clientProtection.TryOpen(
            serverProtectedPacket.AsSpan(0, serverProtectedBytesWritten),
            serverOpenedPacket,
            out int serverOpenedBytesWritten));
        Assert.Equal(serverPlaintextPacket.Length, serverOpenedBytesWritten);
        Assert.True(serverPlaintextPacket.AsSpan().SequenceEqual(serverOpenedPacket));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryOpenInitialPacket_WithAReceiverDerivedFromADifferentClientInitialDcid_DoesNotSucceed()
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
                0x41, 0x42, 0x43, 0x44,
            ],
            token: [],
            packetNumber: [0x01],
            plaintextPayload: QuicS12P3TestSupport.CreateSequentialBytes(0x10, 24));

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
    public void TryProtectInitialPacket_AtTheMinimumProtectedPayloadBoundaryStillRoundTrips()
    {
        byte[] clientInitialDcid =
        [
            0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
        ];
        byte[] sourceConnectionId =
        [
            0x61, 0x62, 0x63, 0x64,
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
