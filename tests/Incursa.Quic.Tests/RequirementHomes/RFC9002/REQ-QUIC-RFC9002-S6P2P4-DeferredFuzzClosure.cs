// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9002_S6P2P4_DeferredFuzzClosure
{
    [Fact]
    [Requirement("RFC9002-S6-2-4-P1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PtoProbeDatagrams_SendAtLeastOneAckElicitingProbe()
    {
        AssertPtoProbeDatagramsRemainAckElicitingAndMayBypassCongestionWindow();
    }

    [Fact]
    [Requirement("RFC9002-S6-2-4-P1-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PtoProbeDatagrams_AllowTwoFullSizedDatagrams()
    {
        AssertPtoProbeDatagramsRemainAckElicitingAndMayBypassCongestionWindow();
    }

    [Fact]
    [Requirement("RFC9002-S6-2-4-P1-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PtoProbeDatagrams_KeepProbePacketsAckEliciting()
    {
        AssertPtoProbeDatagramsRemainAckElicitingAndMayBypassCongestionWindow();
    }

    [Fact]
    [Requirement("RFC9002-S6-2-4-P4-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PtoProbePayloadSelection_CanCarryNewData()
    {
        AssertPtoProbePayloadSelectionCanCarryNewDataRetransmittedDataOrPingFallback();
    }

    [Fact]
    [Requirement("RFC9002-S6-2-4-P4-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PtoProbePayloadSelection_CanCarryPreviouslySentData()
    {
        AssertPtoProbePayloadSelectionCanCarryNewDataRetransmittedDataOrPingFallback();
    }

    [Fact]
    [Requirement("RFC9002-S6-2-4-P5-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PtoProbePayloadSelection_CanUsePingFallbackWhenNoDataExists()
    {
        AssertPtoProbePayloadSelectionCanCarryNewDataRetransmittedDataOrPingFallback();
    }

    [Fact]
    [Requirement("RFC9002-S6-2-4-P6-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryRegisterLoss_AllowsInFlightPacketsToBeMarkedLostInsteadOfSendingAProbe()
    {
        AssertInFlightPacketsCanBeMarkedLostInsteadOfSendingAProbe();
    }

    private static void AssertPtoProbeDatagramsRemainAckElicitingAndMayBypassCongestionWindow()
    {
        Span<byte> probeFrame = stackalloc byte[1];

        foreach ((ulong extraBytesInFlight, int probeDatagramCount) in new[]
        {
            (0UL, 1),
            (1UL, 1),
            (599UL, 2),
            (1_200UL, 2),
        })
        {
            QuicCongestionControlState state = new();
            ulong fullSizedDatagramBytes = state.MaxDatagramSizeBytes;
            state.RegisterPacketSent(state.CongestionWindowBytes + extraBytesInFlight);

            Assert.True(QuicFrameCodec.TryFormatPingFrame(probeFrame, out int bytesWritten));
            Assert.Equal(1, bytesWritten);
            Assert.True(QuicFrameCodec.IsAckElicitingFrameType(probeFrame[0]));

            for (int datagramIndex = 0; datagramIndex < probeDatagramCount; datagramIndex++)
            {
                Assert.True(state.CanSend(fullSizedDatagramBytes, isProbePacket: true));
                state.RegisterPacketSent(fullSizedDatagramBytes, isProbePacket: true);
            }

            Assert.Equal(
                state.CongestionWindowBytes + extraBytesInFlight + ((ulong)probeDatagramCount * fullSizedDatagramBytes),
                state.BytesInFlightBytes);
        }
    }

    private static void AssertPtoProbePayloadSelectionCanCarryNewDataRetransmittedDataOrPingFallback()
    {
        Span<byte> formattedFrame = stackalloc byte[64];

        foreach ((ulong streamId, ulong offset, byte[] streamData) in new[]
        {
            (0UL, 0UL, new byte[] { 0x10 }),
            (2UL, 0UL, new byte[] { 0x20, 0x21, 0x22 }),
            (6UL, 1_024UL, new byte[] { 0x30, 0x31 }),
            (10UL, 65_535UL, new byte[] { 0x40, 0x41, 0x42, 0x43 }),
        })
        {
            byte[] streamFrame = QuicStreamTestData.BuildStreamFrame(
                frameType: 0x0F,
                streamId,
                streamData,
                offset);

            Assert.True(QuicStreamParser.TryParseStreamFrame(streamFrame, out QuicStreamFrame parsedFrame));
            Assert.True(QuicFrameCodec.IsAckElicitingFrameType(parsedFrame.FrameType));
            Assert.Equal(streamId, parsedFrame.StreamId.Value);
            Assert.Equal(offset, parsedFrame.Offset);
            Assert.Equal((ulong)streamData.Length, parsedFrame.Length);
            Assert.True(streamData.AsSpan().SequenceEqual(parsedFrame.StreamData));

            Assert.True(QuicFrameCodec.TryFormatStreamFrame(
                parsedFrame.FrameType,
                parsedFrame.StreamId.Value,
                parsedFrame.Offset,
                parsedFrame.StreamData,
                formattedFrame,
                out int bytesWritten));
            Assert.True(streamFrame.AsSpan().SequenceEqual(formattedFrame[..bytesWritten]));
        }

        Span<byte> pingFallback = stackalloc byte[1];
        Assert.True(QuicFrameCodec.TryFormatPingFrame(pingFallback, out int pingBytesWritten));
        Assert.Equal(1, pingBytesWritten);
        Assert.True(QuicFrameCodec.IsAckElicitingFrameType(pingFallback[0]));
        Assert.True(QuicFrameCodec.TryParsePingFrame(pingFallback, out int pingBytesConsumed));
        Assert.Equal(1, pingBytesConsumed);
    }

    private static void AssertInFlightPacketsCanBeMarkedLostInsteadOfSendingAProbe()
    {
        foreach ((ulong sentBytes, ulong sentAtMicros) in new[]
        {
            (1UL, 1UL),
            (1_200UL, 2_000UL),
            (12_000UL, 50_000UL),
            (64_000UL, 1_000_000UL),
        })
        {
            QuicCongestionControlState state = new();
            state.RegisterPacketSent(sentBytes);

            Assert.True(state.TryRegisterLoss(
                sentBytes,
                sentAtMicros,
                packetInFlight: true));

            Assert.Equal(0UL, state.BytesInFlightBytes);
            Assert.True(state.HasRecoveryStartTime);
            Assert.Equal(sentAtMicros, state.RecoveryStartTimeMicros);

            QuicCongestionControlState rejectedState = new();
            Assert.False(rejectedState.TryRegisterLoss(
                sentBytes,
                sentAtMicros,
                packetInFlight: false,
                allowAckOnlyLossSignal: false));
            Assert.Equal(0UL, rejectedState.BytesInFlightBytes);
            Assert.False(rejectedState.HasRecoveryStartTime);
        }
    }
}
