using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks representative DPLPMTUD probe-tracking helper paths.
/// </summary>
[MemoryDiagnoser]
public class QuicDplpmtudStateBenchmarks
{
    private static readonly QuicConnectionPathIdentity ActivePath = new(
        "203.0.113.20",
        "192.0.2.20",
        443,
        55555);

    private static readonly QuicConnectionPathIdentity AlternatePath = new(
        "203.0.113.21",
        "192.0.2.20",
        443,
        55555);

    /// <summary>
    /// Measures tracking a padding-based probe and applying an acknowledgment.
    /// </summary>
    [Benchmark]
    public ulong TrackAndAcknowledgePaddingProbe()
    {
        QuicDplpmtudState state = new();
        state.TryTrackPaddingProbe(
            ActivePath,
            packetNumber: 1,
            probeSizeBytes: 1_300,
            ackElicitingPayloadSizeBytes: 37,
            out _);
        state.TryRegisterProbeAcknowledged(ActivePath, packetNumber: 1);
        return state.GetPathSnapshot(ActivePath).MaximumPacketSizeBytes;
    }

    /// <summary>
    /// Measures tracking a padding-based probe and applying a loss outcome.
    /// </summary>
    [Benchmark]
    public ulong TrackAndLosePaddingProbe()
    {
        QuicDplpmtudState state = new();
        state.TryTrackPaddingProbe(
            ActivePath,
            packetNumber: 1,
            probeSizeBytes: 1_300,
            ackElicitingPayloadSizeBytes: 37,
            out _);
        state.TryRegisterProbeLost(ActivePath, packetNumber: 1);
        return state.GetPathSnapshot(ActivePath).MaximumPacketSizeBytes;
    }

    /// <summary>
    /// Measures independent per-address-pair probe tracking and lookup.
    /// </summary>
    [Benchmark]
    public ulong TrackIndependentPathProbes()
    {
        QuicDplpmtudState state = new();
        state.TryTrackProbe(ActivePath, packetNumber: 1, probeSizeBytes: 1_300);
        state.TryTrackProbe(AlternatePath, packetNumber: 1, probeSizeBytes: 1_450);
        state.TryRegisterProbeAcknowledged(AlternatePath, packetNumber: 1);

        QuicDplpmtudPathSnapshot activeSnapshot = state.GetPathSnapshot(ActivePath);
        QuicDplpmtudPathSnapshot alternateSnapshot = state.GetPathSnapshot(AlternatePath);
        return activeSnapshot.MaximumPacketSizeBytes
            + alternateSnapshot.MaximumPacketSizeBytes
            + (ulong)activeSnapshot.OutstandingProbeCount;
    }
}
