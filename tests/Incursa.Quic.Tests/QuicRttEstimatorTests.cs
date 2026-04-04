namespace Incursa.Quic.Tests;

public sealed class QuicRttEstimatorTests
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P3-0005">An endpoint MUST initialize the RTT estimator during connection establishment and when the estimator is reset during connection migration.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P3-0006">Before any RTT samples are available for a new path, or when the estimator is reset, the RTT estimator MUST be initialized using the initial RTT.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P3-0007">When the RTT estimator is initialized, `smoothed_rtt` MUST be set to `kInitialRtt` and `rttvar` to `kInitialRtt / 2`.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P2-0001">Resumed connections over the same network MAY use the previous connection&apos;s final smoothed RTT value as the resumed connection&apos;s initial RTT.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P2-0002">When no previous RTT is available, the initial RTT SHOULD be set to 333 milliseconds.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9002-S5P3-0005")]
    [Requirement("REQ-QUIC-RFC9002-S5P3-0006")]
    [Requirement("REQ-QUIC-RFC9002-S5P3-0007")]
    [Requirement("REQ-QUIC-RFC9002-S6P2P2-0001")]
    [Requirement("REQ-QUIC-RFC9002-S6P2P2-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5-0001">An endpoint MUST compute min_rtt, smoothed_rtt, and rttvar for each path.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P1-0001">An endpoint MUST generate an RTT sample on receiving an ACK frame only if the largest acknowledged packet number is newly acknowledged and at least one newly acknowledged packet was ack-eliciting.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P1-0002">latest_rtt MUST equal the time elapsed between when the largest acknowledged packet was sent and when the corresponding ACK was received.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P1-0003">An RTT sample MUST use only the largest acknowledged packet in the received ACK frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P1-0005">An RTT sample MUST NOT be generated on receiving an ACK frame that does not newly acknowledge at least one ack-eliciting packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P2-0001">min_rtt MUST be set to latest_rtt on the first RTT sample.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P2-0003">An endpoint MUST use only locally observed times when computing min_rtt.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P2-0004">An endpoint MUST NOT adjust min_rtt for acknowledgment delays reported by the peer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P3-0008">On the first RTT sample after initialization, `smoothed_rtt` MUST be set to `latest_rtt` and `rttvar` to `latest_rtt / 2`.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9002-S5-0001")]
    [Requirement("REQ-QUIC-RFC9002-S5P1-0001")]
    [Requirement("REQ-QUIC-RFC9002-S5P1-0002")]
    [Requirement("REQ-QUIC-RFC9002-S5P1-0003")]
    [Requirement("REQ-QUIC-RFC9002-S5P1-0005")]
    [Requirement("REQ-QUIC-RFC9002-S5P2-0001")]
    [Requirement("REQ-QUIC-RFC9002-S5P2-0003")]
    [Requirement("REQ-QUIC-RFC9002-S5P2-0004")]
    [Requirement("REQ-QUIC-RFC9002-S5P3-0008")]
    [CoverageType(RequirementCoverageType.Positive)]
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P1-0001">An endpoint MUST generate an RTT sample on receiving an ACK frame only if the largest acknowledged packet number is newly acknowledged and at least one newly acknowledged packet was ack-eliciting.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P1-0004">An ACK frame SHOULD NOT be used to update RTT estimates if it does not newly acknowledge the largest acknowledged packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P1-0005">An RTT sample MUST NOT be generated on receiving an ACK frame that does not newly acknowledge at least one ack-eliciting packet.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9002-S5P1-0001")]
    [Requirement("REQ-QUIC-RFC9002-S5P1-0004")]
    [Requirement("REQ-QUIC-RFC9002-S5P1-0005")]
    [CoverageType(RequirementCoverageType.Negative)]
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P2-0002">On all RTT samples after the first, min_rtt MUST be set to the lesser of min_rtt and latest_rtt.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P3-0001">The calculation of smoothed_rtt MUST use RTT samples after adjusting them for acknowledgment delays.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P3-0002">The endpoint SHOULD ignore max_ack_delay until the handshake is confirmed.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9002-S5P2-0002")]
    [Requirement("REQ-QUIC-RFC9002-S5P3-0001")]
    [Requirement("REQ-QUIC-RFC9002-S5P3-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P3-0009">After the handshake is confirmed, an endpoint MUST use the lesser of the acknowledgment delay and the peer&apos;s max_ack_delay.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P3-0010">On subsequent RTT samples, an endpoint MUST set adjusted_rtt to latest_rtt - ack_delay when latest_rtt is at least min_rtt + ack_delay and otherwise set adjusted_rtt to latest_rtt, then update smoothed_rtt to 7/8 of its prior value plus 1/8 of adjusted_rtt and update rttvar to 3/4 of its prior value plus 1/4 of abs(smoothed_rtt - adjusted_rtt).</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P3-0012">An endpoint MUST NOT subtract the acknowledgment delay from the RTT sample if the resulting value would be smaller than min_rtt.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9002-S5P3-0009")]
    [Requirement("REQ-QUIC-RFC9002-S5P3-0010")]
    [Requirement("REQ-QUIC-RFC9002-S5P3-0012")]
    [CoverageType(RequirementCoverageType.Positive)]
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P3-0009">After the handshake is confirmed, an endpoint MUST use the lesser of the acknowledgment delay and the peer&apos;s max_ack_delay.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9002-S5P3-0009")]
    [CoverageType(RequirementCoverageType.Negative)]
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P3-0004">When acknowledgment processing is postponed because the corresponding decryption keys are not immediately available, an endpoint SHOULD subtract that local delay from its RTT sample until the handshake is confirmed.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9002-S5P3-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P3-0011">An endpoint MAY ignore the acknowledgment delay for Initial packets.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9002-S5P3-0011")]
    [CoverageType(RequirementCoverageType.Positive)]
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P2-0005">Endpoints SHOULD set min_rtt to the newest RTT sample after persistent congestion is established.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P2-0006">Endpoints MAY reestablish min_rtt at other times in the connection, such as when traffic volume is low and an acknowledgment is received with a low acknowledgment delay.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9002-S5P2-0005")]
    [Requirement("REQ-QUIC-RFC9002-S5P2-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P2-0005">Endpoints SHOULD set min_rtt to the newest RTT sample after persistent congestion is established.</workbench-requirement>
    /// </workbench-requirements>
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P2-0005">Endpoints SHOULD set min_rtt to the newest RTT sample after persistent congestion is established.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9002-S5P2-0005")]
    [CoverageType(RequirementCoverageType.Negative)]
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
    [CoverageType(RequirementCoverageType.Negative)]
    public void Constructor_RejectsZeroInitialRtt()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new QuicRttEstimator(initialRttMicros: 0));
    }
}
