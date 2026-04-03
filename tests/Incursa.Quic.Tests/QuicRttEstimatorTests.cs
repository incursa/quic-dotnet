namespace Incursa.Quic.Tests;

public sealed class QuicRttEstimatorTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S5P3-0005")]
    [Requirement("REQ-QUIC-RFC9002-S5P3-0006")]
    [Requirement("REQ-QUIC-RFC9002-S5P3-0007")]
    [Requirement("REQ-QUIC-RFC9002-S6P2P2-0001")]
    [Requirement("REQ-QUIC-RFC9002-S6P2P2-0002")]
    [Trait("Category", "Positive")]
    public void ConstructorAndReset_SeedTheEstimatorWithTheInitialRtt()
    {
        QuicRttEstimator estimator = new();

        Assert.False(estimator.HasRttSample);
        Assert.Equal(QuicRttEstimator.DefaultInitialRttMicros, estimator.InitialRttMicros);
        Assert.Equal(0UL, estimator.LatestRttMicros);
        Assert.Equal(0UL, estimator.MinRttMicros);
        Assert.Equal(QuicRttEstimator.DefaultInitialRttMicros, estimator.SmoothedRttMicros);
        Assert.Equal(QuicRttEstimator.DefaultInitialRttMicros / 2, estimator.RttVarMicros);

        QuicRttEstimator resumedEstimator = new(initialRttMicros: 123_000);
        Assert.False(resumedEstimator.HasRttSample);
        Assert.Equal(123_000UL, resumedEstimator.InitialRttMicros);
        Assert.Equal(0UL, resumedEstimator.LatestRttMicros);
        Assert.Equal(0UL, resumedEstimator.MinRttMicros);
        Assert.Equal(123_000UL, resumedEstimator.SmoothedRttMicros);
        Assert.Equal(61_500UL, resumedEstimator.RttVarMicros);

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 1_000,
            ackReceivedAtMicros: 1_900,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        estimator.Reset();

        Assert.False(estimator.HasRttSample);
        Assert.Equal(0UL, estimator.LatestRttMicros);
        Assert.Equal(0UL, estimator.MinRttMicros);
        Assert.Equal(QuicRttEstimator.DefaultInitialRttMicros, estimator.SmoothedRttMicros);
        Assert.Equal(QuicRttEstimator.DefaultInitialRttMicros / 2, estimator.RttVarMicros);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S5-0001")]
    [Requirement("REQ-QUIC-RFC9002-S5P1-0001")]
    [Requirement("REQ-QUIC-RFC9002-S5P1-0002")]
    [Requirement("REQ-QUIC-RFC9002-S5P1-0003")]
    [Requirement("REQ-QUIC-RFC9002-S5P1-0005")]
    [Requirement("REQ-QUIC-RFC9002-S5P2-0001")]
    [Requirement("REQ-QUIC-RFC9002-S5P2-0003")]
    [Requirement("REQ-QUIC-RFC9002-S5P2-0004")]
    [Requirement("REQ-QUIC-RFC9002-S5P3-0008")]
    [Trait("Category", "Positive")]
    public void TryUpdateFromAck_UsesTheLargestNewlyAcknowledgedAckElicitingPacketAsTheFirstSample()
    {
        QuicRttEstimator estimator = new();

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 1_000,
            ackReceivedAtMicros: 2_500,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            ackDelayMicros: 400,
            handshakeConfirmed: true,
            peerMaxAckDelayMicros: 250));

        Assert.True(estimator.HasRttSample);
        Assert.Equal(1_500UL, estimator.LatestRttMicros);
        Assert.Equal(1_500UL, estimator.MinRttMicros);
        Assert.Equal(1_500UL, estimator.SmoothedRttMicros);
        Assert.Equal(750UL, estimator.RttVarMicros);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S5P1-0001")]
    [Requirement("REQ-QUIC-RFC9002-S5P1-0004")]
    [Requirement("REQ-QUIC-RFC9002-S5P1-0005")]
    [Trait("Category", "Negative")]
    public void TryUpdateFromAck_RejectsDuplicateLargestAcknowledgmentsAndAckOnlyProgress()
    {
        QuicRttEstimator estimator = new();

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 1_000,
            ackReceivedAtMicros: 2_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        Assert.False(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 1_100,
            ackReceivedAtMicros: 2_300,
            largestAcknowledgedPacketNewlyAcknowledged: false,
            newlyAcknowledgedAckElicitingPacket: true));

        Assert.False(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 1_200,
            ackReceivedAtMicros: 2_400,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: false));

        Assert.Equal(1_000UL, estimator.LatestRttMicros);
        Assert.Equal(1_000UL, estimator.MinRttMicros);
        Assert.Equal(1_000UL, estimator.SmoothedRttMicros);
        Assert.Equal(500UL, estimator.RttVarMicros);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S5P2-0002")]
    [Requirement("REQ-QUIC-RFC9002-S5P3-0001")]
    [Requirement("REQ-QUIC-RFC9002-S5P3-0002")]
    [Trait("Category", "Positive")]
    public void TryUpdateFromAck_AdjustsForAckDelayBeforeHandshakeConfirmationWithoutClampingToPeerMax()
    {
        QuicRttEstimator estimator = new();
        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 0,
            ackReceivedAtMicros: 1_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 500,
            ackReceivedAtMicros: 2_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            ackDelayMicros: 300,
            handshakeConfirmed: false,
            peerMaxAckDelayMicros: 200));

        Assert.Equal(1_500UL, estimator.LatestRttMicros);
        Assert.Equal(1_000UL, estimator.MinRttMicros);
        Assert.Equal(1_025UL, estimator.SmoothedRttMicros);
        Assert.Equal(425UL, estimator.RttVarMicros);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S5P3-0009")]
    [Requirement("REQ-QUIC-RFC9002-S5P3-0010")]
    [Requirement("REQ-QUIC-RFC9002-S5P3-0012")]
    [Trait("Category", "Positive")]
    public void TryUpdateFromAck_ClampsAckDelayAfterHandshakeConfirmationAndDoesNotReduceAdjustedRttBelowMinRtt()
    {
        QuicRttEstimator clampedEstimator = new();
        Assert.True(clampedEstimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 0,
            ackReceivedAtMicros: 1_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        Assert.True(clampedEstimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 500,
            ackReceivedAtMicros: 2_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            ackDelayMicros: 600,
            handshakeConfirmed: true,
            peerMaxAckDelayMicros: 300));

        Assert.Equal(1_500UL, clampedEstimator.LatestRttMicros);
        Assert.Equal(1_000UL, clampedEstimator.MinRttMicros);
        Assert.Equal(1_025UL, clampedEstimator.SmoothedRttMicros);
        Assert.Equal(425UL, clampedEstimator.RttVarMicros);

        QuicRttEstimator boundedEstimator = new();
        Assert.True(boundedEstimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 0,
            ackReceivedAtMicros: 1_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        Assert.True(boundedEstimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 600,
            ackReceivedAtMicros: 2_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            ackDelayMicros: 500,
            handshakeConfirmed: true,
            peerMaxAckDelayMicros: 500));

        Assert.Equal(1_400UL, boundedEstimator.LatestRttMicros);
        Assert.Equal(1_000UL, boundedEstimator.MinRttMicros);
        Assert.Equal(1_050UL, boundedEstimator.SmoothedRttMicros);
        Assert.Equal(475UL, boundedEstimator.RttVarMicros);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S5P3-0009")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryUpdateFromAck_LeavesAckDelayUnclampedBeforeHandshakeConfirmation()
    {
        QuicRttEstimator estimator = new();
        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 0,
            ackReceivedAtMicros: 1_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 500,
            ackReceivedAtMicros: 2_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            ackDelayMicros: 600,
            handshakeConfirmed: false,
            peerMaxAckDelayMicros: 300));

        Assert.Equal(1_500UL, estimator.LatestRttMicros);
        Assert.Equal(1_000UL, estimator.MinRttMicros);
        Assert.Equal(1_062UL, estimator.SmoothedRttMicros);
        Assert.Equal(500UL, estimator.RttVarMicros);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S5P3-0004")]
    [Trait("Category", "Positive")]
    public void TryUpdateFromAck_SubtractsLocalProcessingDelayBeforeHandshakeConfirmationOnSubsequentSamples()
    {
        QuicRttEstimator estimator = new();
        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 0,
            ackReceivedAtMicros: 1_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 500,
            ackReceivedAtMicros: 2_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            ackDelayMicros: 100,
            handshakeConfirmed: false,
            localProcessingDelayMicros: 200));

        Assert.Equal(1_500UL, estimator.LatestRttMicros);
        Assert.Equal(1_000UL, estimator.MinRttMicros);
        Assert.Equal(1_025UL, estimator.SmoothedRttMicros);
        Assert.Equal(425UL, estimator.RttVarMicros);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S5P3-0011")]
    [Trait("Category", "Positive")]
    public void TryUpdateFromAck_CanIgnoreAckDelayForInitialPackets()
    {
        QuicRttEstimator estimator = new();
        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 0,
            ackReceivedAtMicros: 1_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            isInitialPacket: true,
            ignoreAckDelayForInitialPacket: true));

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 500,
            ackReceivedAtMicros: 2_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            ackDelayMicros: 400,
            handshakeConfirmed: false,
            isInitialPacket: true,
            ignoreAckDelayForInitialPacket: true));

        Assert.Equal(1_500UL, estimator.LatestRttMicros);
        Assert.Equal(1_000UL, estimator.MinRttMicros);
        Assert.Equal(1_062UL, estimator.SmoothedRttMicros);
        Assert.Equal(500UL, estimator.RttVarMicros);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S5P2-0005")]
    [Requirement("REQ-QUIC-RFC9002-S5P2-0006")]
    [Trait("Category", "Positive")]
    public void RefreshMinRttFromLatestSample_AllowsExplicitMinRttReestablishment()
    {
        QuicRttEstimator estimator = new();
        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 0,
            ackReceivedAtMicros: 1_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        estimator.RefreshMinRttFromLatestSample(1_800);
        Assert.Equal(1_800UL, estimator.MinRttMicros);

        estimator.RefreshMinRttFromLatestSample(900);
        Assert.Equal(900UL, estimator.MinRttMicros);
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9002-S5P2-0005")]
    [InlineData(1_800UL)]
    [InlineData(900UL)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void RefreshMinRttFromLatestSample_ReestablishesTheMinimumRtt(ulong latestRttMicros)
    {
        QuicRttEstimator estimator = new();
        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 0,
            ackReceivedAtMicros: 1_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        Assert.Equal(1_000UL, estimator.LatestRttMicros);
        Assert.Equal(1_000UL, estimator.MinRttMicros);
        Assert.Equal(1_000UL, estimator.SmoothedRttMicros);
        Assert.Equal(500UL, estimator.RttVarMicros);
        Assert.True(estimator.HasRttSample);

        estimator.RefreshMinRttFromLatestSample(latestRttMicros);

        Assert.Equal(latestRttMicros, estimator.MinRttMicros);
        Assert.Equal(1_000UL, estimator.LatestRttMicros);
        Assert.Equal(1_000UL, estimator.SmoothedRttMicros);
        Assert.Equal(500UL, estimator.RttVarMicros);
        Assert.True(estimator.HasRttSample);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S5P2-0005")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RefreshMinRttFromLatestSample_DoesNotInventAnRttSampleOnAColdEstimator()
    {
        QuicRttEstimator estimator = new();

        estimator.RefreshMinRttFromLatestSample(1_800);

        Assert.False(estimator.HasRttSample);
        Assert.Equal(1_800UL, estimator.MinRttMicros);
        Assert.Equal(0UL, estimator.LatestRttMicros);
        Assert.Equal(333_000UL, estimator.SmoothedRttMicros);
        Assert.Equal(166_500UL, estimator.RttVarMicros);
    }

    [Fact]
    [Trait("Category", "Negative")]
    public void Constructor_RejectsZeroInitialRtt()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new QuicRttEstimator(initialRttMicros: 0));
    }
}
