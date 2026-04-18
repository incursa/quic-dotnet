using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks representative RFC 9002 RTT-estimation update paths, including cold-start,
/// ACK-delay-adjusted, and persistent min-RTT refresh flows.
/// </summary>
[MemoryDiagnoser]
public class QuicRttEstimatorBenchmarks
{
    private ulong initialSampleAckReceivedAtMicros;
    private ulong initialSampleSentAtMicros;
    private ulong adjustedSampleAckReceivedAtMicros;
    private ulong adjustedSampleSentAtMicros;
    private ulong adjustedSampleAckDelayMicros;
    private ulong adjustedSamplePeerMaxAckDelayMicros;
    private ulong persistentRefreshMinRttMicros;
    private ulong persistentUpdateSampleAckReceivedAtMicros;
    private ulong persistentUpdateSampleSentAtMicros;
    private ulong persistentUpdateSampleAckDelayMicros;
    private ulong persistentUpdateSamplePeerMaxAckDelayMicros;

    /// <summary>
    /// Prepares representative timestamps for the benchmark cases.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        initialSampleSentAtMicros = 0;
        initialSampleAckReceivedAtMicros = 1_000;
        adjustedSampleSentAtMicros = 500;
        adjustedSampleAckReceivedAtMicros = 2_000;
        adjustedSampleAckDelayMicros = 50;
        adjustedSamplePeerMaxAckDelayMicros = 200;
        persistentRefreshMinRttMicros = 900;
        persistentUpdateSampleSentAtMicros = 1_100;
        persistentUpdateSampleAckReceivedAtMicros = 2_800;
        persistentUpdateSampleAckDelayMicros = 100;
        persistentUpdateSamplePeerMaxAckDelayMicros = 200;
    }

    /// <summary>
    /// Measures the first RTT sample after estimator initialization.
    /// </summary>
    [Benchmark]
    public ulong ProcessInitialRttSample()
    {
        QuicRttEstimator estimator = new();
        estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: initialSampleSentAtMicros,
            ackReceivedAtMicros: initialSampleAckReceivedAtMicros,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true);
        return estimator.SmoothedRttMicros;
    }

    /// <summary>
    /// Measures a steady-state application-data update that subtracts ACK delay.
    /// </summary>
    [Benchmark]
    public ulong ProcessAckDelayAdjustedSample()
    {
        QuicRttEstimator estimator = CreatePrimedEstimator();
        estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: adjustedSampleSentAtMicros,
            ackReceivedAtMicros: adjustedSampleAckReceivedAtMicros,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            ackDelayMicros: adjustedSampleAckDelayMicros,
            handshakeConfirmed: true,
            peerMaxAckDelayMicros: adjustedSamplePeerMaxAckDelayMicros);
        return estimator.SmoothedRttMicros;
    }

    /// <summary>
    /// Measures explicit min-RTT reestablishment after a persistent refresh.
    /// </summary>
    [Benchmark]
    public ulong RefreshMinRttAfterPersistentCongestion()
    {
        QuicRttEstimator estimator = CreatePrimedEstimator();
        estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: adjustedSampleSentAtMicros,
            ackReceivedAtMicros: adjustedSampleAckReceivedAtMicros,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            ackDelayMicros: adjustedSampleAckDelayMicros,
            handshakeConfirmed: true,
            peerMaxAckDelayMicros: adjustedSamplePeerMaxAckDelayMicros);
        estimator.RefreshMinRttFromLatestSample(persistentRefreshMinRttMicros);
        return estimator.MinRttMicros;
    }

    /// <summary>
    /// Measures a persistent update that follows a min-RTT refresh.
    /// </summary>
    [Benchmark]
    public ulong ProcessPersistentRttUpdate()
    {
        QuicRttEstimator estimator = CreatePrimedEstimator();
        estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: adjustedSampleSentAtMicros,
            ackReceivedAtMicros: adjustedSampleAckReceivedAtMicros,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            ackDelayMicros: adjustedSampleAckDelayMicros,
            handshakeConfirmed: true,
            peerMaxAckDelayMicros: adjustedSamplePeerMaxAckDelayMicros);
        estimator.RefreshMinRttFromLatestSample(persistentRefreshMinRttMicros);
        estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: persistentUpdateSampleSentAtMicros,
            ackReceivedAtMicros: persistentUpdateSampleAckReceivedAtMicros,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            ackDelayMicros: persistentUpdateSampleAckDelayMicros,
            handshakeConfirmed: true,
            peerMaxAckDelayMicros: persistentUpdateSamplePeerMaxAckDelayMicros);
        return estimator.SmoothedRttMicros;
    }

    private QuicRttEstimator CreatePrimedEstimator()
    {
        QuicRttEstimator estimator = new();
        estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: initialSampleSentAtMicros,
            ackReceivedAtMicros: initialSampleAckReceivedAtMicros,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true);
        return estimator;
    }
}
