using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks the ACK scheduling checks used before active-path 1-RTT ACK piggybacking.
/// </summary>
[MemoryDiagnoser]
public class QuicAckPiggybackPolicyBenchmarks
{
    private QuicSenderFlowController pendingAck = null!;
    private QuicSenderFlowController alreadyPiggybackedAck = null!;

    [GlobalSetup]
    public void GlobalSetup()
    {
        pendingAck = new QuicSenderFlowController();
        pendingAck.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 31,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        alreadyPiggybackedAck = new QuicSenderFlowController();
        alreadyPiggybackedAck.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 31,
            ackEliciting: true,
            receivedAtMicros: 1_000);
        if (!alreadyPiggybackedAck.TryBuildAckFrame(
                QuicPacketNumberSpace.ApplicationData,
                nowMicros: 1_000,
                out QuicAckFrame ackFrame))
        {
            throw new InvalidOperationException("The benchmark could not build the ACK frame.");
        }

        alreadyPiggybackedAck.MarkAckFrameSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 9,
            ackFrame,
            sentAtMicros: 1_000,
            ackOnlyPacket: false);
    }

    [Benchmark]
    public bool PendingAckShouldPiggyback()
    {
        return pendingAck.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_000,
            maxAckDelayMicros: 0);
    }

    [Benchmark]
    public bool AlreadyPiggybackedAckSuppressesAckOnlyTrigger()
    {
        return alreadyPiggybackedAck.CanSendAckOnlyPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_001,
            maxAckDelayMicros: 0);
    }
}
