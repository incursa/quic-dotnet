using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks representative RFC 9002 congestion-control update paths.
/// </summary>
[MemoryDiagnoser]
public class QuicCongestionControlBenchmarks
{
    private QuicPersistentCongestionPacket[] persistentCongestionPackets = [];

    /// <summary>
    /// Prepares representative packet histories for persistent congestion evaluation.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        persistentCongestionPackets =
        [
            new(QuicPacketNumberSpace.Initial, 2_000, 1_200, true, true, acknowledged: false, lost: true),
            new(QuicPacketNumberSpace.ApplicationData, 9_000, 1_200, true, true, acknowledged: false, lost: true),
        ];
    }

    /// <summary>
    /// Measures the initial congestion-window formula.
    /// </summary>
    [Benchmark]
    public ulong ComputeInitialCongestionWindow()
    {
        return QuicCongestionControlState.ComputeInitialCongestionWindowBytes(1_500);
    }

    /// <summary>
    /// Measures slow-start growth after a non-underutilized acknowledgment.
    /// </summary>
    [Benchmark]
    public ulong GrowInSlowStart()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);
        state.RegisterPacketSent(1_200, isProbePacket: true);
        state.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true);

        return state.CongestionWindowBytes;
    }

    /// <summary>
    /// Measures recovery entry on a loss signal.
    /// </summary>
    [Benchmark]
    public ulong EnterRecoveryOnLoss()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);
        state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 2_000,
            packetInFlight: true);

        return state.CongestionWindowBytes;
    }

    /// <summary>
    /// Measures ECN-triggered recovery on a validated path.
    /// </summary>
    [Benchmark]
    public ulong ProcessValidatedEcn()
    {
        QuicCongestionControlState state = new();
        state.TryProcessEcn(
            QuicPacketNumberSpace.ApplicationData,
            reportedEcnCeCount: 1,
            largestAcknowledgedPacketSentAtMicros: 1_500,
            pathValidated: true);

        return state.CongestionWindowBytes;
    }

    /// <summary>
    /// Measures persistent-congestion detection and collapse.
    /// </summary>
    [Benchmark]
    public ulong DetectPersistentCongestion()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);
        state.TryDetectPersistentCongestion(
            persistentCongestionPackets,
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out _);

        return state.CongestionWindowBytes;
    }
}
