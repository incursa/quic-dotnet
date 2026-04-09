using BenchmarkDotNet.Attributes;
using System.Buffers.Binary;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks the Handshake packet protection helper.
/// </summary>
[MemoryDiagnoser]
public class QuicHandshakePacketProtectionBenchmarks
{
    private static readonly byte[] DestinationConnectionId =
    [
        0x10, 0x11, 0x12, 0x13,
    ];

    private static readonly byte[] SourceConnectionId =
    [
        0x20, 0x21,
    ];

    private QuicHandshakePacketProtection senderProtection = default!;
    private QuicHandshakePacketProtection receiverProtection = default!;
    private byte[] plaintextPacket = [];
    private byte[] protectedPacket = [];
    private byte[] recoveredPacket = [];

    /// <summary>
    /// Prepares representative Handshake packet inputs and reusable buffers.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        byte[] aeadKey = CreateSequentialBytes(0x11, 32);
        byte[] aeadIv = CreateSequentialBytes(0x21, 12);
        byte[] headerProtectionKey = CreateSequentialBytes(0x31, 32);

        if (!QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.Handshake,
            QuicAeadAlgorithm.Aes256Gcm,
            aeadKey,
            aeadIv,
            headerProtectionKey,
            new QuicAeadUsageLimits(64, 128),
            out QuicTlsPacketProtectionMaterial material))
        {
            throw new InvalidOperationException("Failed to create representative Handshake packet protection material.");
        }

        if (!QuicHandshakePacketProtection.TryCreate(material, out senderProtection))
        {
            throw new InvalidOperationException("Failed to create a representative Handshake sender protector.");
        }

        if (!QuicHandshakePacketProtection.TryCreate(material, out receiverProtection))
        {
            throw new InvalidOperationException("Failed to create a representative Handshake receiver protector.");
        }

        plaintextPacket = BuildHandshakePlaintextPacket(
            DestinationConnectionId,
            SourceConnectionId,
            packetNumber: [0x01, 0x02],
            plaintextPayload:
            [
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
                0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B,
                0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51,
                0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
                0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D,
            ]);

        protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        recoveredPacket = new byte[plaintextPacket.Length];

        if (!senderProtection.TryProtect(plaintextPacket, protectedPacket, out int bytesWritten)
            || bytesWritten != protectedPacket.Length)
        {
            throw new InvalidOperationException("Failed to produce a representative protected Handshake packet.");
        }
    }

    /// <summary>
    /// Measures Handshake packet protection.
    /// </summary>
    [Benchmark]
    public int ProtectHandshakePacket()
    {
        return senderProtection.TryProtect(plaintextPacket, protectedPacket, out int bytesWritten)
            ? bytesWritten
            : -1;
    }

    /// <summary>
    /// Measures Handshake packet opening.
    /// </summary>
    [Benchmark]
    public int OpenHandshakePacket()
    {
        return receiverProtection.TryOpen(protectedPacket, recoveredPacket, out int bytesWritten)
            ? bytesWritten
            : -1;
    }

    private static byte[] BuildHandshakePlaintextPacket(
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> sourceConnectionId,
        ReadOnlySpan<byte> packetNumber,
        ReadOnlySpan<byte> plaintextPayload)
    {
        byte[] versionSpecificData = BuildHandshakeVersionSpecificData(packetNumber, plaintextPayload);
        return BuildLongHeader(
            headerControlBits: (byte)(0x60 | ((packetNumber.Length - 1) & QuicPacketHeaderBits.PacketNumberLengthBitsMask)),
            version: 1,
            destinationConnectionId,
            sourceConnectionId,
            versionSpecificData);
    }

    private static byte[] BuildHandshakeVersionSpecificData(
        ReadOnlySpan<byte> packetNumber,
        ReadOnlySpan<byte> plaintextPayload)
    {
        byte[] lengthBytes = EncodeVarint((ulong)(packetNumber.Length + plaintextPayload.Length + QuicInitialPacketProtection.AuthenticationTagLength));
        byte[] versionSpecificData = new byte[lengthBytes.Length + packetNumber.Length + plaintextPayload.Length];

        int offset = 0;
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
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(1, sizeof(uint)), version);
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

    private static byte[] CreateSequentialBytes(byte startValue, int length)
    {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++)
        {
            bytes[i] = unchecked((byte)(startValue + i));
        }

        return bytes;
    }
}
