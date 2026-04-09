using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks the Initial-only packet protection helper.
/// </summary>
[MemoryDiagnoser]
public class QuicInitialPacketProtectionBenchmarks
{
    private static readonly byte[] ClientInitialDcid =
    [
        0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
    ];

    private QuicInitialPacketProtection senderProtection = default!;
    private QuicInitialPacketProtection receiverProtection = default!;
    private byte[] plaintextPacket = [];
    private byte[] protectedPacket = [];
    private byte[] recoveredPacket = [];

    /// <summary>
    /// Prepares representative Initial packet inputs and reusable buffers.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        if (!QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            ClientInitialDcid,
            out senderProtection))
        {
            throw new InvalidOperationException("Failed to create a representative Initial sender protector.");
        }

        if (!QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            ClientInitialDcid,
            out receiverProtection))
        {
            throw new InvalidOperationException("Failed to create a representative Initial receiver protector.");
        }

        plaintextPacket = BuildInitialPlaintextPacket(
            destinationConnectionId: ClientInitialDcid,
            sourceConnectionId: [0x01, 0x02, 0x03, 0x04],
            token: [0xAA, 0xBB],
            packetNumber: [0x01],
            plaintextPayload:
            [
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
            ]);

        protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        recoveredPacket = new byte[plaintextPacket.Length];

        if (!senderProtection.TryProtect(plaintextPacket, protectedPacket, out int bytesWritten)
            || bytesWritten != protectedPacket.Length)
        {
            throw new InvalidOperationException("Failed to produce a representative protected Initial packet.");
        }
    }

    /// <summary>
    /// Measures Initial secret and key-material derivation.
    /// </summary>
    [Benchmark]
    public int DeriveInitialKeyMaterial()
    {
        return QuicInitialPacketProtection.TryDeriveInitialKeyMaterial(
            ClientInitialDcid,
            out QuicInitialPacketProtectionMaterial clientMaterial,
            out QuicInitialPacketProtectionMaterial serverMaterial)
            ? clientMaterial.AeadKey.Length + serverMaterial.AeadKey.Length
            : -1;
    }

    /// <summary>
    /// Measures Initial packet protection.
    /// </summary>
    [Benchmark]
    public int ProtectInitialPacket()
    {
        return senderProtection.TryProtect(plaintextPacket, protectedPacket, out int bytesWritten)
            ? bytesWritten
            : -1;
    }

    /// <summary>
    /// Measures Initial packet opening.
    /// </summary>
    [Benchmark]
    public int OpenInitialPacket()
    {
        return receiverProtection.TryOpen(protectedPacket, recoveredPacket, out int bytesWritten)
            ? bytesWritten
            : -1;
    }

    private static byte[] BuildInitialPlaintextPacket(
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> sourceConnectionId,
        ReadOnlySpan<byte> token,
        ReadOnlySpan<byte> packetNumber,
        ReadOnlySpan<byte> plaintextPayload)
    {
        byte[] versionSpecificData = BuildInitialVersionSpecificData(token, packetNumber, plaintextPayload);
        return BuildLongHeader(
            headerControlBits: (byte)(QuicPacketHeaderBits.FixedBitMask
                | ((packetNumber.Length - 1) & QuicPacketHeaderBits.PacketNumberLengthBitsMask)),
            version: 1,
            destinationConnectionId,
            sourceConnectionId,
            versionSpecificData);
    }

    private static byte[] BuildInitialVersionSpecificData(
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

    private static byte[] BuildLongHeader(
        byte headerControlBits,
        uint version,
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> sourceConnectionId,
        ReadOnlySpan<byte> versionSpecificData)
    {
        byte[] packet = new byte[1 + sizeof(uint) + 1 + destinationConnectionId.Length + 1 + sourceConnectionId.Length + versionSpecificData.Length];
        packet[0] = (byte)(0x80 | (headerControlBits & 0x7F));
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(1, sizeof(uint)), version);
        packet[5] = (byte)destinationConnectionId.Length;

        int sourceConnectionIdLengthOffset = 6 + destinationConnectionId.Length;
        destinationConnectionId.CopyTo(packet.AsSpan(6));
        packet[sourceConnectionIdLengthOffset] = (byte)sourceConnectionId.Length;

        int versionSpecificDataOffset = sourceConnectionIdLengthOffset + 1 + sourceConnectionId.Length;
        sourceConnectionId.CopyTo(packet.AsSpan(sourceConnectionIdLengthOffset + 1));
        versionSpecificData.CopyTo(packet.AsSpan(versionSpecificDataOffset));

        return packet;
    }

    private static byte[] EncodeVarint(ulong value)
    {
        Span<byte> buffer = stackalloc byte[8];
        if (!QuicVariableLengthInteger.TryFormat(value, buffer, out int bytesWritten))
        {
            throw new InvalidOperationException("Failed to encode a representative QUIC varint.");
        }

        return buffer[..bytesWritten].ToArray();
    }
}
