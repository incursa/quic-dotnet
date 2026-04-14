using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks 1-RTT application packet formatting and opening when the short-header Key Phase bit is preserved.
/// </summary>
[MemoryDiagnoser]
public class QuicApplicationPacketKeyPhaseBenchmarks
{
    private static readonly byte[] DestinationConnectionId =
    [
        0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
    ];

    private readonly byte[] applicationPayload = new byte[1];
    private QuicHandshakeFlowCoordinator packetCoordinator = default!;
    private QuicTlsPacketProtectionMaterial oneRttPacketProtectionMaterial;
    private byte[] protectedPacket = [];

    /// <summary>
    /// Prepares representative 1-RTT packet-protection material and the protected packet used by the open benchmark.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        if (!QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.OneRtt,
            QuicAeadAlgorithm.Aes128Gcm,
            CreateSequentialBytes(0x41, 16),
            CreateSequentialBytes(0x51, 12),
            CreateSequentialBytes(0x61, 16),
            new QuicAeadUsageLimits(64, 128),
            out oneRttPacketProtectionMaterial))
        {
            throw new InvalidOperationException("Failed to prepare representative 1-RTT packet-protection material.");
        }

        if (!QuicFrameCodec.TryFormatPingFrame(applicationPayload, out int bytesWritten) || bytesWritten <= 0)
        {
            throw new InvalidOperationException("Failed to prepare representative 1-RTT application payload.");
        }

        packetCoordinator = new QuicHandshakeFlowCoordinator(DestinationConnectionId);
        if (!packetCoordinator.TrySetDestinationConnectionId(DestinationConnectionId))
        {
            throw new InvalidOperationException("Failed to configure the packet coordinator destination connection ID.");
        }

        if (!packetCoordinator.TryBuildProtectedApplicationDataPacket(
            applicationPayload,
            oneRttPacketProtectionMaterial,
            keyPhase: true,
            out protectedPacket))
        {
            throw new InvalidOperationException("Failed to prepare representative 1-RTT protected packet.");
        }
    }

    /// <summary>
    /// Measures 1-RTT short-header packet formatting with an explicit Key Phase bit.
    /// </summary>
    [Benchmark]
    public int BuildProtectedApplicationPacketWithKeyPhaseBit()
    {
        QuicHandshakeFlowCoordinator coordinator = new(DestinationConnectionId);
        if (!coordinator.TrySetDestinationConnectionId(DestinationConnectionId)
            || !coordinator.TryBuildProtectedApplicationDataPacket(
                applicationPayload,
                oneRttPacketProtectionMaterial,
                keyPhase: true,
                out byte[] packet))
        {
            return -1;
        }

        return packet.Length;
    }

    /// <summary>
    /// Measures 1-RTT short-header packet opening while surfacing the observed Key Phase bit.
    /// </summary>
    [Benchmark]
    public int OpenProtectedApplicationPacketAndReadKeyPhaseBit()
    {
        return packetCoordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            oneRttPacketProtectionMaterial,
            out byte[] openedPacket,
            out _,
            out _,
            out bool keyPhase)
            ? openedPacket.Length + (keyPhase ? 1 : 0)
            : -1;
    }

    private static byte[] CreateSequentialBytes(byte startValue, int length)
    {
        byte[] buffer = new byte[length];
        for (int index = 0; index < buffer.Length; index++)
        {
            buffer[index] = unchecked((byte)(startValue + index));
        }

        return buffer;
    }
}
