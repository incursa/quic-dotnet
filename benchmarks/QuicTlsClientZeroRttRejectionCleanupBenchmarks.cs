using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks the client-side 0-RTT cleanup branches that discard dormant ZeroRtt material on rejected disposition updates.
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
    private static readonly QuicTlsStateUpdate RejectedEarlyDataDispositionUpdate = new(
        QuicTlsUpdateKind.PeerEarlyDataDispositionAvailable,
        PeerEarlyDataDisposition: QuicTlsEarlyDataDisposition.Rejected);
    private static readonly QuicTlsStateUpdate AcceptedEarlyDataDispositionUpdate = new(
        QuicTlsUpdateKind.PeerEarlyDataDispositionAvailable,
        PeerEarlyDataDisposition: QuicTlsEarlyDataDisposition.Accepted);

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

    /// <summary>
    /// Measures the rejected peer early-data disposition cleanup that discards dormant ZeroRtt material.
    /// </summary>
    [Benchmark]
    public bool DiscardRejectedPeerEarlyDataDisposition()
    {
        return bridge.TryApply(RejectedEarlyDataDispositionUpdate);
    }

    /// <summary>
    /// Measures the accepted peer early-data disposition retention path that leaves dormant ZeroRtt material intact.
    /// </summary>
    [Benchmark]
    public bool RetainAcceptedPeerEarlyDataDisposition()
    {
        return bridge.TryApply(AcceptedEarlyDataDispositionUpdate);
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
