using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks the Retry integrity tag generation and validation helpers.
/// </summary>
[MemoryDiagnoser]
public class QuicRetryIntegrityBenchmarks
{
    private static readonly byte[] ClientInitialDestinationConnectionId =
    [
        0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
    ];

    private static readonly byte[] RetrySourceConnectionId =
    [
        0xF0, 0x67, 0xA5, 0x50, 0x2A, 0x42, 0x62, 0xB5,
    ];

    private static readonly byte[] RetryToken =
    [
        0x74, 0x6F, 0x6B, 0x65, 0x6E,
    ];

    private static readonly byte[] RetryIntegrityTag =
    [
        0x04, 0xA2, 0x65, 0xBA, 0x2E, 0xFF, 0x4D, 0x82,
        0x90, 0x58, 0xFB, 0x3F, 0x0F, 0x24, 0x96, 0xBA,
    ];

    private byte[] retryPacketWithoutIntegrityTag = [];
    private byte[] retryPacket = [];

    /// <summary>
    /// Prepares representative Retry packet inputs and reusable buffers.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        retryPacketWithoutIntegrityTag = BuildRetryPacket(
            destinationConnectionId: [],
            sourceConnectionId: RetrySourceConnectionId,
            retryToken: RetryToken,
            retryIntegrityTag: [],
            unusedBits: 0x0F);

        retryPacket = BuildRetryPacket(
            destinationConnectionId: [],
            sourceConnectionId: RetrySourceConnectionId,
            retryToken: RetryToken,
            retryIntegrityTag: RetryIntegrityTag,
            unusedBits: 0x0F);

        Span<byte> generatedRetryIntegrityTag = stackalloc byte[QuicRetryIntegrity.RetryIntegrityTagLength];
        if (!QuicRetryIntegrity.TryGenerateRetryIntegrityTag(
            ClientInitialDestinationConnectionId,
            retryPacketWithoutIntegrityTag,
            generatedRetryIntegrityTag,
            out int bytesWritten)
            || bytesWritten != QuicRetryIntegrity.RetryIntegrityTagLength)
        {
            throw new InvalidOperationException("Failed to prepare a representative Retry integrity tag.");
        }
    }

    /// <summary>
    /// Measures Retry integrity tag generation.
    /// </summary>
    [Benchmark]
    public int GenerateRetryIntegrityTag()
    {
        Span<byte> destination = stackalloc byte[QuicRetryIntegrity.RetryIntegrityTagLength];
        return QuicRetryIntegrity.TryGenerateRetryIntegrityTag(
            ClientInitialDestinationConnectionId,
            retryPacketWithoutIntegrityTag,
            destination,
            out int bytesWritten)
            ? bytesWritten
            : -1;
    }

    /// <summary>
    /// Measures Retry integrity tag validation.
    /// </summary>
    [Benchmark]
    public int ValidateRetryPacketIntegrity()
    {
        return QuicRetryIntegrity.TryValidateRetryPacketIntegrity(
            ClientInitialDestinationConnectionId,
            retryPacket)
            ? retryPacket.Length
            : -1;
    }

    private static byte[] BuildRetryPacket(
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> sourceConnectionId,
        ReadOnlySpan<byte> retryToken,
        ReadOnlySpan<byte> retryIntegrityTag,
        byte unusedBits = 0x00)
    {
        byte[] versionSpecificData = new byte[retryToken.Length + retryIntegrityTag.Length];
        retryToken.CopyTo(versionSpecificData);
        retryIntegrityTag.CopyTo(versionSpecificData.AsSpan(retryToken.Length));

        return BuildLongHeader(
            headerControlBits: BuildRetryHeaderControlBits(unusedBits),
            version: 1,
            destinationConnectionId,
            sourceConnectionId,
            versionSpecificData);
    }

    private static byte BuildRetryHeaderControlBits(byte unusedBits = 0x00)
    {
        return (byte)(0x70 | (unusedBits & 0x0F));
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
}
