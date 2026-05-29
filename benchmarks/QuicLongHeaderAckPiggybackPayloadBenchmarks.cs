// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks the long-header ACK piggyback payload construction used for Initial and Handshake retransmissions.
/// </summary>
[MemoryDiagnoser]
public class QuicLongHeaderAckPiggybackPayloadBenchmarks
{
    private const ulong NowMicros = 1_000;
    private const int MinimumAckPayloadBufferLength = 512;

    private QuicSenderFlowController flowController = null!;

    /// <summary>
    /// Gets or sets the long-header packet-number space to benchmark.
    /// </summary>
    [Params(0, 1)]
    public int PacketNumberSpaceValue { get; set; }

    [GlobalSetup]
    public void GlobalSetup()
    {
        flowController = new QuicSenderFlowController();
        flowController.RecordIncomingPacket(
            QuicPacketNumberSpace.Initial,
            packetNumber: 1,
            ackEliciting: true,
            receivedAtMicros: NowMicros);
        flowController.RecordIncomingPacket(
            QuicPacketNumberSpace.Handshake,
            packetNumber: 1,
            ackEliciting: true,
            receivedAtMicros: NowMicros);
    }

    /// <summary>
    /// Baseline shape: format the ACK frame and materialize it into a fresh array.
    /// </summary>
    [Benchmark(Baseline = true)]
    public int BuildLongHeaderAckPiggybackPayloadWithArrayCopy()
    {
        QuicPacketNumberSpace packetNumberSpace = GetPacketNumberSpace();
        if (!flowController.TryBuildAckFrame(packetNumberSpace, NowMicros, out QuicAckFrame ackFrame))
        {
            throw new InvalidOperationException("The benchmark could not build the ACK frame.");
        }

        Span<byte> framePayloadBuffer = stackalloc byte[MinimumAckPayloadBufferLength];
        if (!QuicConnectionAckHelpers.TryFormatOutboundAckFramePayload(ackFrame, framePayloadBuffer, out int frameBytesWritten))
        {
            throw new InvalidOperationException("The benchmark could not format the ACK frame payload.");
        }

        byte[] ackFramePayload = new byte[frameBytesWritten];
        framePayloadBuffer.Slice(0, frameBytesWritten).CopyTo(ackFramePayload);
        return frameBytesWritten ^ ackFrame.FrameType ^ ackFramePayload[0];
    }

    /// <summary>
    /// Measures the pooled-lease shape used by the fixed implementation.
    /// </summary>
    [Benchmark]
    public int BuildLongHeaderAckPiggybackPayloadWithLease()
    {
        QuicPacketNumberSpace packetNumberSpace = GetPacketNumberSpace();
        QuicBufferLease ackFramePayload = default;
        try
        {
            if (!QuicConnectionAckHelpers.TryBuildLongHeaderAckPiggybackFramePayload(
                    packetNumberSpace,
                    flowController,
                    NowMicros,
                    out ackFramePayload,
                    out int ackFramePayloadLength,
                    out QuicAckFrame ackFrame))
            {
                throw new InvalidOperationException("The benchmark could not build the ACK frame payload.");
            }

            return ackFramePayloadLength ^ ackFrame.FrameType ^ ackFramePayload.Span[0];
        }
        finally
        {
            ackFramePayload.Dispose();
        }
    }

    private QuicPacketNumberSpace GetPacketNumberSpace()
    {
        return PacketNumberSpaceValue == 0
            ? QuicPacketNumberSpace.Initial
            : QuicPacketNumberSpace.Handshake;
    }
}
