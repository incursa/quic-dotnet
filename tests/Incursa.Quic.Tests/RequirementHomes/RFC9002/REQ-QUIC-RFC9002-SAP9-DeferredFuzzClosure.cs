// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9002_SAP9_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP9-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TimeoutHandlingPrefersEarliestLossDetectionBeforePtoWork()
    {
        foreach ((ulong? initialLoss, ulong? handshakeLoss, ulong? applicationLoss, ulong pto, QuicPacketNumberSpace expectedSpace, ulong expectedLoss) in new[]
        {
            ((ulong?)4_500UL, (ulong?)1_800UL, (ulong?)3_000UL, 2_500UL, QuicPacketNumberSpace.Handshake, 1_800UL),
            ((ulong?)900UL, (ulong?)1_800UL, (ulong?)3_000UL, 500UL, QuicPacketNumberSpace.Initial, 900UL),
            ((ulong?)null, (ulong?)4_000UL, (ulong?)3_000UL, 1_000UL, QuicPacketNumberSpace.ApplicationData, 3_000UL),
            ((ulong?)0UL, (ulong?)1UL, (ulong?)2UL, 0UL, QuicPacketNumberSpace.Handshake, 1UL),
        })
        {
            Assert.True(QuicRecoveryTiming.TrySelectLossTimeAndSpaceMicros(
                initialLoss,
                handshakeLoss,
                applicationLoss,
                out ulong selectedLossTimeMicros,
                out QuicPacketNumberSpace selectedPacketNumberSpace));

            Assert.Equal(expectedLoss, selectedLossTimeMicros);
            Assert.Equal(expectedSpace, selectedPacketNumberSpace);

            Assert.True(QuicRecoveryTiming.TrySelectRecoveryTimerMicros(
                selectedLossTimeMicros,
                pto,
                out ulong selectedTimerMicros));

            Assert.Equal(selectedLossTimeMicros, selectedTimerMicros);
        }

        Assert.False(QuicRecoveryTiming.TrySelectLossTimeAndSpaceMicros(
            initialLossTimeMicros: null,
            handshakeLossTimeMicros: null,
            applicationDataLossTimeMicros: null,
            out _,
            out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP9-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AntiDeadlockPtoSelectionUsesHandshakeWhenKeysExistOtherwiseInitial()
    {
        foreach ((ulong nowMicros, ulong initialPto, ulong? handshakePto, bool handshakeKeysAvailable, QuicPacketNumberSpace expectedSpace, ulong expectedTime) in new[]
        {
            (0UL, 0UL, (ulong?)1_000UL, false, QuicPacketNumberSpace.Initial, 0UL),
            (1_000UL, 2_500UL, (ulong?)1_800UL, false, QuicPacketNumberSpace.Initial, 3_500UL),
            (1_000UL, 2_500UL, (ulong?)1_800UL, true, QuicPacketNumberSpace.Handshake, 2_800UL),
            (2_000UL, 5_000UL, (ulong?)0UL, true, QuicPacketNumberSpace.Handshake, 2_000UL),
            (2_000UL, 5_000UL, null, true, QuicPacketNumberSpace.Initial, 7_000UL),
        })
        {
            Assert.True(QuicRecoveryTiming.TrySelectPtoTimeAndSpaceMicros(
                nowMicros,
                initialPto,
                handshakePto,
                handshakeKeysAvailable,
                out ulong selectedPtoTimeMicros,
                out QuicPacketNumberSpace selectedPacketNumberSpace));

            Assert.Equal(expectedTime, selectedPtoTimeMicros);
            Assert.Equal(expectedSpace, selectedPacketNumberSpace);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP9-0004")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PtoProbeCanSendOneOrTwoAckElicitingPacketsPastCongestionWindow()
    {
        Span<byte> pingFrame = stackalloc byte[1];
        Assert.True(QuicFrameCodec.TryFormatPingFrame(pingFrame, out int bytesWritten));
        Assert.Equal(1, bytesWritten);
        Assert.True(QuicFrameCodec.IsAckElicitingFrameType(pingFrame[0]));

        foreach ((ulong existingBytesInFlight, int probeDatagramCount) in new[]
        {
            (0UL, 1),
            (1_200UL, 1),
            (12_000UL, 2),
            (24_000UL, 2),
        })
        {
            QuicCongestionControlState state = new();
            state.RegisterPacketSent(existingBytesInFlight);
            ulong fullSizedDatagramBytes = state.MaxDatagramSizeBytes;

            for (int index = 0; index < probeDatagramCount; index++)
            {
                Assert.True(state.CanSend(fullSizedDatagramBytes, isProbePacket: true));
                state.RegisterPacketSent(fullSizedDatagramBytes, isProbePacket: true);
            }

            Assert.Equal(
                existingBytesInFlight + ((ulong)probeDatagramCount * fullSizedDatagramBytes),
                state.BytesInFlightBytes);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP9-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PtoTimeoutBackoffRefreshesTheLossDetectionTimer()
    {
        foreach ((ulong baseProbeTimeoutMicros, int ptoCount, ulong expectedBackoff) in new[]
        {
            (1UL, 0, 1UL),
            (2_500UL, 1, 5_000UL),
            (2_500UL, 2, 10_000UL),
            (7_500UL, 3, 60_000UL),
            ((ulong.MaxValue / 2) + 1, 1, ulong.MaxValue),
        })
        {
            ulong refreshedProbeTimeoutMicros = QuicRecoveryTiming.ComputeProbeTimeoutWithBackoffMicros(
                baseProbeTimeoutMicros,
                ptoCount);

            Assert.Equal(expectedBackoff, refreshedProbeTimeoutMicros);
            Assert.True(QuicRecoveryTiming.TrySelectLossDetectionTimerMicros(
                earliestPendingLossTimeMicros: null,
                probeTimeoutMicros: refreshedProbeTimeoutMicros,
                serverAtAntiAmplificationLimit: false,
                noAckElicitingPacketsInFlight: false,
                peerAddressValidationComplete: false,
                out ulong selectedTimerMicros));

            Assert.Equal(refreshedProbeTimeoutMicros, selectedTimerMicros);
        }
    }
}
