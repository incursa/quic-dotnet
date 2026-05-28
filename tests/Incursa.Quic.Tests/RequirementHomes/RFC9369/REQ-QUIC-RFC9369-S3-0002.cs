// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9369-S3-0002")]
public sealed class REQ_QUIC_RFC9369_S3_0002
{
    private static readonly byte[] ClientInitialDcid =
    [
        0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
    ];

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryCreate_Version2InitialPacketProtector_ProtectsAndOpensVersion2InitialPackets()
    {
        byte[] plaintextPacket = BuildVersion2InitialPlaintextPacket(
            destinationConnectionId: ClientInitialDcid,
            sourceConnectionId: [0x01, 0x02, 0x03, 0x04],
            token: [0xAA, 0xBB],
            packetNumber: [0x01],
            plaintextPayload:
            [
                0x10, 0x11, 0x12, 0x13,
                0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1A, 0x1B,
                0x1C, 0x1D, 0x1E, 0x1F,
                0x20, 0x21, 0x22, 0x23,
            ]);

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            QuicVersionNegotiation.Version2,
            ClientInitialDcid,
            out QuicInitialPacketProtection senderProtection));

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            QuicVersionNegotiation.Version2,
            ClientInitialDcid,
            out QuicInitialPacketProtection receiverProtection));

        byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        Assert.True(senderProtection.TryProtect(plaintextPacket, protectedPacket, out int bytesWritten));
        Assert.Equal(protectedPacket.Length, bytesWritten);

        byte[] recoveredPacket = new byte[plaintextPacket.Length];
        Assert.True(receiverProtection.TryOpen(protectedPacket, recoveredPacket, out int openedBytes));
        Assert.Equal(plaintextPacket.Length, openedBytes);
        Assert.True(plaintextPacket.AsSpan().SequenceEqual(recoveredPacket));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryCreate_Version1InitialPacketProtector_DoesNotOpenVersion2InitialPackets()
    {
        byte[] plaintextPacket = BuildVersion2InitialPlaintextPacket(
            destinationConnectionId: ClientInitialDcid,
            sourceConnectionId: [0x01, 0x02, 0x03, 0x04],
            token: [0xAA, 0xBB],
            packetNumber: [0x01],
            plaintextPayload:
            [
                0x10, 0x11, 0x12, 0x13,
                0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1A, 0x1B,
                0x1C, 0x1D, 0x1E, 0x1F,
                0x20, 0x21, 0x22, 0x23,
            ]);

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            QuicVersionNegotiation.Version2,
            ClientInitialDcid,
            out QuicInitialPacketProtection v2SenderProtection));

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            QuicVersionNegotiation.Version1,
            ClientInitialDcid,
            out QuicInitialPacketProtection v1ReceiverProtection));

        byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        Assert.True(v2SenderProtection.TryProtect(plaintextPacket, protectedPacket, out _));

        byte[] recoveredPacket = new byte[plaintextPacket.Length];
        Assert.False(v1ReceiverProtection.TryOpen(protectedPacket, recoveredPacket, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryDeriveInitialKeyMaterial_UsesDistinctMaterialForVersion1AndVersion2()
    {
        Assert.True(QuicInitialPacketProtection.TryDeriveInitialKeyMaterial(
            QuicVersionNegotiation.Version1,
            ClientInitialDcid,
            out QuicInitialPacketProtectionMaterial v1ClientMaterial,
            out QuicInitialPacketProtectionMaterial v1ServerMaterial));

        Assert.True(QuicInitialPacketProtection.TryDeriveInitialKeyMaterial(
            QuicVersionNegotiation.Version2,
            ClientInitialDcid,
            out QuicInitialPacketProtectionMaterial v2ClientMaterial,
            out QuicInitialPacketProtectionMaterial v2ServerMaterial));

        Assert.False(v1ClientMaterial.AeadKey.SequenceEqual(v2ClientMaterial.AeadKey));
        Assert.False(v1ServerMaterial.AeadKey.SequenceEqual(v2ServerMaterial.AeadKey));
        Assert.False(v1ClientMaterial.HeaderProtectionKey.SequenceEqual(v2ClientMaterial.HeaderProtectionKey));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Version2InitialPacketProtection_RoundTripsRepresentativePayloads()
    {
        Random random = new(unchecked((int)0x9369_0002));

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            QuicVersionNegotiation.Version2,
            ClientInitialDcid,
            out QuicInitialPacketProtection senderProtection));

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            QuicVersionNegotiation.Version2,
            ClientInitialDcid,
            out QuicInitialPacketProtection receiverProtection));

        for (int iteration = 0; iteration < 32; iteration++)
        {
            byte[] token = RandomBytes(random, random.Next(1, 5));
            byte[] packetNumber = RandomBytes(random, 1);
            byte[] payload = RandomBytes(
                random,
                QuicInitialPacketProtection.HeaderProtectionSampleOffset
                + QuicInitialPacketProtection.HeaderProtectionSampleLength
                + random.Next(0, 8));
            byte[] plaintextPacket = BuildVersion2InitialPlaintextPacket(
                destinationConnectionId: ClientInitialDcid,
                sourceConnectionId: RandomBytes(random, 4),
                token,
                packetNumber,
                payload);

            byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
            Assert.True(senderProtection.TryProtect(plaintextPacket, protectedPacket, out int bytesWritten));
            Assert.Equal(protectedPacket.Length, bytesWritten);

            byte[] recoveredPacket = new byte[plaintextPacket.Length];
            Assert.True(receiverProtection.TryOpen(protectedPacket, recoveredPacket, out int openedBytes));
            Assert.Equal(plaintextPacket.Length, openedBytes);
            Assert.True(plaintextPacket.AsSpan().SequenceEqual(recoveredPacket));
        }
    }

    private static byte[] BuildVersion2InitialPlaintextPacket(
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> sourceConnectionId,
        ReadOnlySpan<byte> token,
        ReadOnlySpan<byte> packetNumber,
        ReadOnlySpan<byte> plaintextPayload)
    {
        byte[] versionSpecificData = BuildVersion2InitialVersionSpecificData(token, packetNumber, plaintextPayload);
        return QuicHeaderTestData.BuildLongHeader(
            headerControlBits: (byte)(QuicPacketHeaderBits.FixedBitMask
                | (QuicVersionNegotiation.GetLongHeaderPacketTypeBits(
                    QuicVersionNegotiation.Version2,
                    QuicLongPacketType.Initial) << QuicPacketHeaderBits.LongPacketTypeBitsShift)
                | ((packetNumber.Length - 1) & QuicPacketHeaderBits.PacketNumberLengthBitsMask)),
            version: QuicVersionNegotiation.Version2,
            destinationConnectionId,
            sourceConnectionId,
            versionSpecificData);
    }

    private static byte[] BuildVersion2InitialVersionSpecificData(
        ReadOnlySpan<byte> token,
        ReadOnlySpan<byte> packetNumber,
        ReadOnlySpan<byte> plaintextPayload)
    {
        byte[] tokenLengthBytes = EncodeVarint((ulong)token.Length);
        byte[] lengthBytes = EncodeVarint((ulong)(packetNumber.Length + plaintextPayload.Length + QuicInitialPacketProtection.AuthenticationTagLength));
        byte[] versionSpecificData = new byte[
            tokenLengthBytes.Length
            + token.Length
            + lengthBytes.Length
            + packetNumber.Length
            + plaintextPayload.Length];

        int offset = 0;
        tokenLengthBytes.CopyTo(versionSpecificData, offset);
        offset += tokenLengthBytes.Length;
        token.CopyTo(versionSpecificData.AsSpan(offset));
        offset += token.Length;
        lengthBytes.CopyTo(versionSpecificData, offset);
        offset += lengthBytes.Length;
        packetNumber.CopyTo(versionSpecificData.AsSpan(offset));
        offset += packetNumber.Length;
        plaintextPayload.CopyTo(versionSpecificData.AsSpan(offset));

        return versionSpecificData;
    }

    private static byte[] EncodeVarint(ulong value)
    {
        Span<byte> buffer = stackalloc byte[8];
        Assert.True(QuicVariableLengthInteger.TryFormat(value, buffer, out int bytesWritten));
        return buffer[..bytesWritten].ToArray();
    }

    private static byte[] RandomBytes(Random random, int length)
    {
        byte[] bytes = new byte[length];
        random.NextBytes(bytes);
        return bytes;
    }
}
