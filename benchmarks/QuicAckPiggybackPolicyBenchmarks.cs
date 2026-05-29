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

/// <summary>
/// Benchmarks the payload construction path used when application data piggybacks a pending 1-RTT ACK.
/// </summary>
[MemoryDiagnoser]
public class QuicAckPiggybackPayloadBenchmarks
{
    private QuicSenderFlowController pendingAck = null!;
    private byte[] payload = null!;

    [Params(32, 1024)]
    public int PayloadLength { get; set; }

    [GlobalSetup]
    public void GlobalSetup()
    {
        pendingAck = new QuicSenderFlowController();
        pendingAck.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 31,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        payload = new byte[PayloadLength];
        new Random(42).NextBytes(payload);
    }

    [Benchmark]
    public int BuildApplicationAckPiggybackPayload()
    {
        byte[]? piggybackedPayload = null;
        try
        {
            if (!QuicConnectionAckHelpers.TryBuildApplicationAckPiggybackPayload(
                    payload,
                    pendingAck,
                    nowMicros: 1_000,
                    out piggybackedPayload,
                    out int piggybackedPayloadLength,
                    out QuicAckFrame ackFrame))
            {
                throw new InvalidOperationException("The benchmark could not build the ACK piggyback payload.");
            }

            return piggybackedPayloadLength ^ ackFrame.FrameType ^ piggybackedPayload[0];
        }
        finally
        {
            QuicBufferPool.ReturnBytes(piggybackedPayload);
        }
    }
}
