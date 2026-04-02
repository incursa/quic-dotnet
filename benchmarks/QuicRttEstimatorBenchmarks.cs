using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks representative RFC 9002 RTT-estimation update paths.
/// </summary>
[MemoryDiagnoser]
public class QuicRttEstimatorBenchmarks
{
    private ulong initialSampleAckReceivedAtMicros;
    private ulong initialSampleSentAtMicros;
    private ulong confirmedSampleAckReceivedAtMicros;
    private ulong confirmedSampleSentAtMicros;
    private ulong confirmedSampleAckDelayMicros;
    private ulong confirmedSamplePeerMaxAckDelayMicros;

    /// <summary>
    /// Prepares representative timestamps for the benchmark cases.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        initialSampleSentAtMicros = 0;
        initialSampleAckReceivedAtMicros = 1_000;
        confirmedSampleSentAtMicros = 500;
        confirmedSampleAckReceivedAtMicros = 2_000;
        confirmedSampleAckDelayMicros = 300;
        confirmedSamplePeerMaxAckDelayMicros = 200;
    }

    /// <summary>
    /// Measures the first RTT sample after estimator initialization.
    /// </summary>
    [Benchmark]
    public ulong ProcessFirstRttSample()
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
    /// Measures a handshake-confirmed application-data update with an ACK delay clamp.
    /// </summary>
    [Benchmark]
    public ulong ProcessConfirmedApplicationSample()
    {
        QuicRttEstimator estimator = new();
        estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: initialSampleSentAtMicros,
            ackReceivedAtMicros: initialSampleAckReceivedAtMicros,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true);
        estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: confirmedSampleSentAtMicros,
            ackReceivedAtMicros: confirmedSampleAckReceivedAtMicros,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            ackDelayMicros: confirmedSampleAckDelayMicros,
            handshakeConfirmed: true,
            peerMaxAckDelayMicros: confirmedSamplePeerMaxAckDelayMicros);
        return estimator.SmoothedRttMicros;
    }

    /// <summary>
    /// Measures explicit min-RTT reestablishment after persistent congestion.
    /// </summary>
    [Benchmark]
    public ulong RefreshMinRttAfterPersistentCongestion()
    {
        QuicRttEstimator estimator = new();
        estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: initialSampleSentAtMicros,
            ackReceivedAtMicros: initialSampleAckReceivedAtMicros,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true);
        estimator.RefreshMinRttFromLatestSample(900);
        return estimator.MinRttMicros;
    }
}
