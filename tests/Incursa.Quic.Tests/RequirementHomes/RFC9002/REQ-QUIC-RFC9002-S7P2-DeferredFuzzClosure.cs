// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9002_S7P2_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S7P2-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NewAndResetCongestionStatesBeginInSlowStartWithInitialWindow()
    {
        foreach (ulong maxDatagramSizeBytes in RepresentativeMaxDatagramSizes())
        {
            QuicCongestionControlState state = new(maxDatagramSizeBytes);

            AssertInitialSlowStartState(state, maxDatagramSizeBytes);

            state.RegisterPacketSent(state.CongestionWindowBytes);
            Assert.False(state.CanSend(1));

            state.Reset();

            AssertInitialSlowStartState(state, maxDatagramSizeBytes);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S7P2-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InitialCongestionWindowUsesTenDatagramsWithRfcBounds()
    {
        foreach (ulong maxDatagramSizeBytes in RepresentativeMaxDatagramSizes())
        {
            ulong tenDatagrams = checked(maxDatagramSizeBytes * 10);
            ulong twoDatagrams = checked(maxDatagramSizeBytes * 2);
            ulong expectedInitialWindowBytes = Math.Min(tenDatagrams, Math.Max(14_720UL, twoDatagrams));

            Assert.Equal(
                expectedInitialWindowBytes,
                QuicCongestionControlState.ComputeInitialCongestionWindowBytes(maxDatagramSizeBytes));
            Assert.Equal(
                twoDatagrams,
                QuicCongestionControlState.ComputeMinimumCongestionWindowBytes(maxDatagramSizeBytes));

            QuicCongestionControlState state = new(maxDatagramSizeBytes);
            Assert.Equal(expectedInitialWindowBytes, state.CongestionWindowBytes);
            Assert.Equal(twoDatagrams, state.MinimumCongestionWindowBytes);
        }
    }

    private static void AssertInitialSlowStartState(
        QuicCongestionControlState state,
        ulong maxDatagramSizeBytes)
    {
        Assert.Equal(maxDatagramSizeBytes, state.MaxDatagramSizeBytes);
        Assert.Equal(
            QuicCongestionControlState.ComputeInitialCongestionWindowBytes(maxDatagramSizeBytes),
            state.CongestionWindowBytes);
        Assert.Equal(ulong.MaxValue, state.SlowStartThresholdBytes);
        Assert.Equal(0UL, state.BytesInFlightBytes);
        Assert.True(state.IsInSlowStart);
        Assert.False(state.IsInCongestionAvoidance);
    }

    private static ulong[] RepresentativeMaxDatagramSizes()
    {
        return
        [
            QuicVersionNegotiation.Version1MinimumDatagramPayloadSize,
            1_472,
            1_473,
            7_360,
            7_361,
            9_000,
        ];
    }
}
