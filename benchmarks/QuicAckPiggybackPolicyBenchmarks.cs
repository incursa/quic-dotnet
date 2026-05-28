// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

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
    private QuicSenderFlowController singleDelayedAck = null!;
    private byte[] periodicAckProbePayload = null!;

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

        singleDelayedAck = new QuicSenderFlowController();
        singleDelayedAck.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 41,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        periodicAckProbePayload = new byte[32];
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

    [Benchmark]
    public bool SingleAckWaitsBeforeMaxAckDelay()
    {
        return singleDelayedAck.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 25_999,
            maxAckDelayMicros: 25_000);
    }

    [Benchmark]
    public bool SingleAckSendsAtMaxAckDelay()
    {
        return singleDelayedAck.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 26_000,
            maxAckDelayMicros: 25_000);
    }

    [Benchmark]
    public int FormatPeriodicAckElicitingPingProbeFrame()
    {
        periodicAckProbePayload.AsSpan().Clear();
        if (!QuicFrameCodec.TryFormatPingFrame(periodicAckProbePayload, out int bytesWritten))
        {
            throw new InvalidOperationException("Could not format the periodic ack-eliciting PING probe.");
        }

        return bytesWritten;
    }
}
