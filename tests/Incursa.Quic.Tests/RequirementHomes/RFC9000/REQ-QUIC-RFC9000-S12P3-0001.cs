namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P3-0001">This number MUST be used in determining the cryptographic nonce for packet protection.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P3-0001")]
public sealed class REQ_QUIC_RFC9000_S12P3_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryOpenInitialPacket_UsesThePacketNumberWhenDerivingTheNonce()
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

        byte[] openedPacket = new byte[plaintextPacket.Length];
        Assert.True(receiverProtection.TryOpen(
            protectedPacket,
            openedPacket,
            out int openedBytesWritten));
        Assert.Equal(plaintextPacket.Length, openedBytesWritten);
        Assert.True(plaintextPacket.AsSpan().SequenceEqual(openedPacket));

        int packetNumberOffset = GetInitialPacketNumberOffset(plaintextPacket);
        byte[] tamperedPacket = protectedPacket.ToArray();
        tamperedPacket[packetNumberOffset] ^= 0x01;

        Assert.False(receiverProtection.TryOpen(
            tamperedPacket,
            new byte[plaintextPacket.Length],
            out _));
    }

    private static int GetInitialPacketNumberOffset(ReadOnlySpan<byte> plaintextPacket)
    {
        Assert.True(QuicPacketParsing.TryParseLongHeaderFields(
            plaintextPacket,
            out _,
            out _,
            out _,
            out _,
            out ReadOnlySpan<byte> versionSpecificData));

        Assert.True(QuicVariableLengthInteger.TryParse(versionSpecificData, out ulong tokenLength, out int tokenLengthBytes));
        ReadOnlySpan<byte> afterToken = versionSpecificData.Slice(tokenLengthBytes + checked((int)tokenLength));
        Assert.True(QuicVariableLengthInteger.TryParse(afterToken, out _, out int lengthFieldBytes));

        return QuicHeaderTestData.GetLongHeaderPayloadOffset(plaintextPacket)
            + tokenLengthBytes
            + checked((int)tokenLength)
            + lengthFieldBytes;
    }
}
