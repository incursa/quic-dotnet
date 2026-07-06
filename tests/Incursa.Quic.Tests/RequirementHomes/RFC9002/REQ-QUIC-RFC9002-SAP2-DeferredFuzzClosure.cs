// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9002_SAP2_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP2-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RecommendedPacketThresholdUsesThreePackets()
    {
        Assert.Equal(3, QuicRecoveryTiming.RecommendedPacketThreshold);

        foreach ((ulong packetNumber, ulong largestAcknowledgedPacketNumber, bool expectedLost) in new[]
        {
            (0UL, 2UL, false),
            (0UL, 3UL, true),
            (8UL, 10UL, false),
            (8UL, 11UL, true),
            (100UL, 103UL, true),
        })
        {
            Assert.Equal(expectedLost, QuicRecoveryTiming.ShouldDeclarePacketLostByPacketThreshold(
                packetNumber,
                largestAcknowledgedPacketNumber));
        }

        foreach (int invalidThreshold in new[] { 0, 1, 2 })
        {
            ArgumentOutOfRangeException exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
                QuicRecoveryTiming.ShouldDeclarePacketLostByPacketThreshold(
                    packetNumber: 8,
                    largestAcknowledgedPacketNumber: 11,
                    packetThreshold: invalidThreshold));

            Assert.Equal("packetThreshold", exception.ParamName);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP2-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RecommendedTimerGranularityUsesOneMillisecond()
    {
        Assert.Equal(1_000UL, QuicRecoveryTiming.RecommendedTimerGranularityMicros);

        foreach ((ulong latestRttMicros, ulong smoothedRttMicros) in new[]
        {
            (0UL, 0UL),
            (1UL, 1UL),
            (100UL, 200UL),
            (800UL, 1_000UL),
        })
        {
            Assert.True(QuicRecoveryTiming.ComputeLossDelayMicros(
                    latestRttMicros,
                    smoothedRttMicros)
                >= QuicRecoveryTiming.RecommendedTimerGranularityMicros);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP2-0004")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RecommendedInitialRttSeedsDefaultEstimator()
    {
        Assert.Equal(333_000UL, QuicRttEstimator.DefaultInitialRttMicros);

        QuicRttEstimator defaultEstimator = new();
        Assert.Equal(333_000UL, defaultEstimator.InitialRttMicros);
        Assert.Equal(333_000UL, defaultEstimator.SmoothedRttMicros);
        Assert.Equal(166_500UL, defaultEstimator.RttVarMicros);
        Assert.False(defaultEstimator.HasRttSample);

        foreach (ulong customInitialRttMicros in new[] { 1UL, 123_000UL, 1_000_000UL })
        {
            QuicRttEstimator customEstimator = new(customInitialRttMicros);
            Assert.Equal(customInitialRttMicros, customEstimator.InitialRttMicros);
            Assert.Equal(customInitialRttMicros, customEstimator.SmoothedRttMicros);
            Assert.Equal(customInitialRttMicros / 2, customEstimator.RttVarMicros);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP2-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PacketNumberSpaceEnumerationContainsOnlyTheThreeSpaces()
    {
        QuicPacketNumberSpace[] values = Enum.GetValues<QuicPacketNumberSpace>();

        Assert.Equal(
            [QuicPacketNumberSpace.Initial, QuicPacketNumberSpace.Handshake, QuicPacketNumberSpace.ApplicationData],
            values);

        foreach ((QuicPacketNumberSpace packetNumberSpace, int expectedValue) in new[]
        {
            (QuicPacketNumberSpace.Initial, 0),
            (QuicPacketNumberSpace.Handshake, 1),
            (QuicPacketNumberSpace.ApplicationData, 2),
        })
        {
            Assert.True(Enum.IsDefined(packetNumberSpace));
            Assert.Equal(expectedValue, (int)packetNumberSpace);
        }

        Assert.False(Enum.IsDefined(typeof(QuicPacketNumberSpace), 3));
    }
}
