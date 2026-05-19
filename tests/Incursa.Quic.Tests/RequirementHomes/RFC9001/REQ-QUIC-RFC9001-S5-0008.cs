namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S5-0008")]
public sealed class REQ_QUIC_RFC9001_S5_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryProtectInitialPacket_AndTryOpenInitialPacket_RoundTrip()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            [0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08],
            out QuicInitialPacketProtection senderProtection));

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            [0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08],
            out QuicInitialPacketProtection receiverProtection));

        byte[] plaintextPacket = QuicInitialPacketProtectionTestData.BuildInitialPlaintextPacket(
            destinationConnectionId: [0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08],
            sourceConnectionId: [0x01, 0x02, 0x03, 0x04],
            token: [0xAA, 0xBB],
            packetNumber: [0x01],
            plaintextPayload: [
                0x10, 0x11, 0x12, 0x13, 0x14,
                0x15, 0x16, 0x17, 0x18, 0x19,
                0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
                0x1F, 0x20, 0x21, 0x22, 0x23,
            ]);

        byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        Assert.True(senderProtection.TryProtect(plaintextPacket, protectedPacket, out int protectedBytesWritten));
        Assert.Equal(protectedPacket.Length, protectedBytesWritten);
        Assert.False(plaintextPacket.AsSpan().SequenceEqual(protectedPacket));

        byte[] recoveredPacket = new byte[plaintextPacket.Length];
        Assert.True(receiverProtection.TryOpen(
            protectedPacket.AsSpan(0, protectedBytesWritten),
            recoveredPacket,
            out int recoveredBytesWritten));

        Assert.Equal(plaintextPacket.Length, recoveredBytesWritten);
        Assert.True(plaintextPacket.AsSpan().SequenceEqual(recoveredPacket));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryOpenInitialPacket_OpensCapturedPicoquicClientInitial()
    {
        byte[] protectedPacket = Convert.FromHexString(
            "cf000000010859fd06c1af891c1508c2c37b869b4ed3e9004140b66c7a3008f2665aaa81d3efd723b600c3ff549dd05665104119b2342130e3d628a31c4ecb9e620c7af7bc17698032196dffc3090ee911c6725b4a4121cdf4510506a2a862741f3ec9d436d9605f10d245463350480c400cce65814ffddf98e05eed0143f347a9d8edf55b067e604ce20273ce935f0f5c5eb908ab3d17e0163e56ecc93266bae3cd7746909becc22c783d22bcc27afa75545caead446d6391d5f43706072a53381667bc23d44fbac19dbaf5d88990a328972113b924d5a39a3feee332df0954e25cf6bd25648e47205923e9a3dc4d17570985127df0d48157bd84284e7b897e87ef386b9f1e3753e3e26c16e49e9ac7778a20321636965dff4de0383fd24303e37f187b69d27df61653ecc882b67f6b1c903daf203a3b03f13eba4a511f75e088e06565ee4e4ee35503de7c925cad3c858e1fd0cf3f55246648");

        Assert.True(QuicPacketParser.TryGetPacketLength(protectedPacket, out int packetLength));
        Assert.Equal(protectedPacket.Length, packetLength);
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            [0x59, 0xFD, 0x06, 0xC1, 0xAF, 0x89, 0x1C, 0x15],
            out QuicInitialPacketProtection protection));

        QuicHandshakeFlowCoordinator coordinator = new();
        Assert.True(coordinator.TryOpenInitialPacket(
            protectedPacket,
            protection,
            out byte[] recoveredPacket,
            out int payloadOffset,
            out int payloadLength));

        Assert.Equal(330, recoveredPacket.Length);
        ReadOnlySpan<byte> payload = recoveredPacket.AsSpan(payloadOffset, payloadLength);
        Assert.True(QuicFrameCodec.TryParsePingFrame(payload, out int pingBytesConsumed));
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            payload[pingBytesConsumed..],
            out QuicCryptoFrame cryptoFrame,
            out int bytesConsumed));
        Assert.Equal(0UL, cryptoFrame.Offset);
        Assert.Equal(payloadLength, pingBytesConsumed + bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryProtectInitialPacket_RejectsPacketsThatCannotProvideAHeaderProtectionSample()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            [0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08],
            out QuicInitialPacketProtection protection));

        byte[] plaintextPacket = QuicInitialPacketProtectionTestData.BuildInitialPlaintextPacket(
            destinationConnectionId: [0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08],
            sourceConnectionId: [0x01, 0x02, 0x03, 0x04],
            token: [],
            packetNumber: [0x01],
            plaintextPayload: [
                0x10, 0x11, 0x12, 0x13, 0x14,
                0x15, 0x16, 0x17, 0x18, 0x19,
                0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
                0x1F, 0x20, 0x21, 0x22,
            ]);

        byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        Assert.False(protection.TryProtect(plaintextPacket, protectedPacket, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InitialPacketProtection_RoundTripsRandomValidInputs()
    {
        Random random = new(0x5150_2091);

        for (int iteration = 0; iteration < 32; iteration++)
        {
            QuicTlsRole senderRole = random.Next(2) == 0 ? QuicTlsRole.Client : QuicTlsRole.Server;
            QuicTlsRole receiverRole = senderRole == QuicTlsRole.Client ? QuicTlsRole.Server : QuicTlsRole.Client;
            byte[] dcid = QuicHeaderTestData.RandomBytes(random, random.Next(0, 21));
            byte[] scid = QuicHeaderTestData.RandomBytes(random, random.Next(0, 21));
            byte[] token = QuicHeaderTestData.RandomBytes(random, random.Next(0, 9));
            byte[] packetNumber = QuicHeaderTestData.RandomBytes(random, random.Next(1, 5));
            byte[] plaintextPayload = QuicHeaderTestData.RandomBytes(random, random.Next(20, 65));

            Assert.True(QuicInitialPacketProtection.TryCreate(senderRole, dcid, out QuicInitialPacketProtection senderProtection));
            Assert.True(QuicInitialPacketProtection.TryCreate(receiverRole, dcid, out QuicInitialPacketProtection receiverProtection));

            byte[] plaintextPacket = QuicInitialPacketProtectionTestData.BuildInitialPlaintextPacket(
                dcid,
                scid,
                token,
                packetNumber,
                plaintextPayload);

            byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
            Assert.True(senderProtection.TryProtect(plaintextPacket, protectedPacket, out int protectedBytesWritten));
            Assert.Equal(plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength, protectedBytesWritten);

            byte[] recoveredPacket = new byte[plaintextPacket.Length];
            Assert.True(receiverProtection.TryOpen(
                protectedPacket.AsSpan(0, protectedBytesWritten),
                recoveredPacket,
                out int recoveredBytesWritten));

            Assert.Equal(plaintextPacket.Length, recoveredBytesWritten);
            Assert.True(plaintextPacket.AsSpan().SequenceEqual(recoveredPacket));
        }
    }
}
