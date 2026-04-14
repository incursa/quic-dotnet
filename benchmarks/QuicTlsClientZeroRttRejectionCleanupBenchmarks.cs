using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks the client-side 0-RTT rejection cleanup branch that discards dormant ZeroRtt material.
/// </summary>
[MemoryDiagnoser]
public class QuicTlsClientZeroRttRejectionCleanupBenchmarks
{
    private static readonly QuicTlsPacketProtectionMaterial ZeroRttPacketProtectionMaterial = CreateZeroRttMaterial(0x41);
    private static readonly QuicTlsStateUpdate RejectedDispositionUpdate = new(
        QuicTlsUpdateKind.ResumptionAttemptDispositionAvailable,
        ResumptionAttemptDisposition: QuicTlsResumptionAttemptDisposition.Rejected);
    private static readonly QuicTlsStateUpdate AcceptedDispositionUpdate = new(
        QuicTlsUpdateKind.ResumptionAttemptDispositionAvailable,
        ResumptionAttemptDisposition: QuicTlsResumptionAttemptDisposition.Accepted);

    private QuicTransportTlsBridgeState bridge = default!;

    /// <summary>
    /// Rebuilds the deterministic bridge state and seeds dormant ZeroRtt material before each benchmark iteration.
    /// </summary>
    [IterationSetup]
    public void IterationSetup()
    {
        bridge = new QuicTransportTlsBridgeState(QuicTlsRole.Client);
        if (!bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
            PacketProtectionMaterial: ZeroRttPacketProtectionMaterial)))
        {
            throw new InvalidOperationException("Failed to seed the bridge with dormant ZeroRtt material.");
        }
    }

    /// <summary>
    /// Measures the rejected-branch cleanup that discards dormant ZeroRtt material.
    /// </summary>
    [Benchmark]
    public bool DiscardRejectedResumptionAttemptDisposition()
    {
        return bridge.TryApply(RejectedDispositionUpdate);
    }

    /// <summary>
    /// Measures the accepted-branch retention path that leaves dormant ZeroRtt material intact.
    /// </summary>
    [Benchmark]
    public bool RetainAcceptedResumptionAttemptDisposition()
    {
        return bridge.TryApply(AcceptedDispositionUpdate);
    }

    private static QuicTlsPacketProtectionMaterial CreateZeroRttMaterial(byte startValue)
    {
        if (!QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.ZeroRtt,
            QuicAeadAlgorithm.Aes128Gcm,
            CreateSequentialBytes(startValue, 16),
            CreateSequentialBytes(unchecked((byte)(startValue + 0x10)), 12),
            CreateSequentialBytes(unchecked((byte)(startValue + 0x20)), 16),
            new QuicAeadUsageLimits(64, 128),
            out QuicTlsPacketProtectionMaterial material))
        {
            throw new InvalidOperationException("Failed to create dormant ZeroRtt packet-protection material.");
        }

        return material;
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
