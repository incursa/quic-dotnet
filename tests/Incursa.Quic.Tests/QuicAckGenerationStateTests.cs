namespace Incursa.Quic.Tests;

public sealed class QuicAckGenerationStateTests
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P4P1-0004">On receiving an IP packet with an ECT(0), ECT(1), or ECN-CE codepoint, an ECN-enabled endpoint MUST access the ECN field and increase the corresponding ECT(0), ECT(1), or ECN-CE count.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P4P1-0005">These ECN counts MUST be included in subsequent ACK frames.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P1-0003">Once the packet has been fully processed, a receiver MUST acknowledge receipt by sending one or more ACK frames containing the packet number of the received packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2-0001">Endpoints MUST acknowledge all packets they receive and process.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P1-0002">Every packet SHOULD be acknowledged at least once.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P1-0008">Non-ack-eliciting packets are eventually MUST acknowledged when the endpoint sends an ACK frame in response to other events.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P3-0001">When an ACK frame is sent, one or more ranges of acknowledged packets MUST be included.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P3-0002">ACK frames SHOULD always acknowledge the most recently received packets.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P3-0012">A receiver SHOULD include an ACK Range containing the largest received packet number in every ACK frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P5-0001">An endpoint MUST measure the delays intentionally introduced between the time the packet with the largest packet number is received and the time an acknowledgment is sent.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P5-0002">The endpoint MUST encode this acknowledgment delay in the ACK Delay field of an ACK frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P5-0003">An endpoint MUST NOT include delays that it does not control when populating the ACK Delay field in an ACK frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S2-0003">Packets that contain ack-eliciting frames MUST elicit an ACK from the receiver within the maximum acknowledgment delay.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S3-0011">All packets MUST be acknowledged.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0010">ACK frames MUST carry the most recent set of acknowledgments and the acknowledgment delay from the largest acknowledged packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S9P4-0004">A receiver of packets on multiple paths MUST still send ACK frames covering all received packets.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S9P4-0006">A receiver of packets on multiple paths MUST send ACK frames covering all received packets.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S13P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S13P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P1-0002")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0001")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0002")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0012")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P5-0001")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P5-0002")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P5-0003")]
    [Requirement("REQ-QUIC-RFC9002-S2-0003")]
    [Requirement("REQ-QUIC-RFC9002-S3-0011")]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0010")]
    [Requirement("REQ-QUIC-RFC9000-S9P4-0004")]
    [Requirement("REQ-QUIC-RFC9000-S9P4-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryBuildAckFrame_RoundsTripProcessedPacketsAndReportsAckDelay()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 1, ackEliciting: false, receivedAtMicros: 1000);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 2, ackEliciting: true, receivedAtMicros: 1100);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 4, ackEliciting: true, receivedAtMicros: 1200);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 5, ackEliciting: false, receivedAtMicros: 1300);

        Assert.True(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
        Assert.True(tracker.TryBuildAckFrame(QuicPacketNumberSpace.ApplicationData, nowMicros: 1600, out QuicAckFrame frame));

        Assert.Equal((byte)0x02, frame.FrameType);
        Assert.Equal(5UL, frame.LargestAcknowledged);
        Assert.Equal(300UL, frame.AckDelay);
        Assert.Equal(1UL, frame.FirstAckRange);
        Assert.Single(frame.AdditionalRanges);
        Assert.Equal(0UL, frame.AdditionalRanges[0].Gap);
        Assert.Equal(1UL, frame.AdditionalRanges[0].AckRangeLength);
        Assert.Equal(1UL, frame.AdditionalRanges[0].SmallestAcknowledged);
        Assert.Equal(2UL, frame.AdditionalRanges[0].LargestAcknowledged);
        Assert.Null(frame.EcnCounts);

        Span<byte> encoded = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatAckFrame(frame, encoded, out int bytesWritten));
        Assert.True(QuicFrameCodec.TryParseAckFrame(encoded[..bytesWritten], out QuicAckFrame parsed, out int bytesConsumed));

        Assert.Equal(bytesWritten, bytesConsumed);
        Assert.Equal(frame.FrameType, parsed.FrameType);
        Assert.Equal(frame.LargestAcknowledged, parsed.LargestAcknowledged);
        Assert.Equal(frame.AckDelay, parsed.AckDelay);
        Assert.Equal(frame.FirstAckRange, parsed.FirstAckRange);
        Assert.Equal(frame.AdditionalRanges.Length, parsed.AdditionalRanges.Length);
        Assert.Equal(frame.AdditionalRanges[0].Gap, parsed.AdditionalRanges[0].Gap);
        Assert.Equal(frame.AdditionalRanges[0].AckRangeLength, parsed.AdditionalRanges[0].AckRangeLength);
        Assert.Equal(frame.AdditionalRanges[0].SmallestAcknowledged, parsed.AdditionalRanges[0].SmallestAcknowledged);
        Assert.Equal(frame.AdditionalRanges[0].LargestAcknowledged, parsed.AdditionalRanges[0].LargestAcknowledged);
        Assert.Null(parsed.EcnCounts);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P1-0001">Ack-eliciting packets MUST be acknowledged at least once within the maximum delay the endpoint communicated using the max_ack_delay transport parameter.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P1-0005">An endpoint MUST acknowledge all ack-eliciting Initial and Handshake packets immediately.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S2-0003">Packets that contain ack-eliciting frames MUST elicit an ACK from the receiver within the maximum acknowledgment delay.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S13P2P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P1-0005")]
    [Requirement("REQ-QUIC-RFC9002-S2-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ShouldSendAckImmediately_ForInitialAndHandshakePackets()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(QuicPacketNumberSpace.Initial, 1, ackEliciting: true, receivedAtMicros: 1000);
        Assert.True(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.Initial));

        tracker.MarkAckFrameSent(QuicPacketNumberSpace.Initial, sentAtMicros: 1100, ackOnlyPacket: true);

        tracker.RecordProcessedPacket(QuicPacketNumberSpace.Handshake, 1, ackEliciting: true, receivedAtMicros: 1200);
        Assert.True(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.Handshake));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P1-0013">To assist loss detection at the sender, an endpoint SHOULD generate and send an ACK frame without delay when it receives an ack-eliciting packet that has a packet number less than another ack-eliciting packet that has been received, or when the packet has a packet number larger than the highest-numbered ack-eliciting packet that has been received and there are missing packets between that packet and this packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P1-0014">Packets marked with the ECN Congestion Experienced (CE) codepoint in the IP header SHOULD be acknowledged immediately.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S13P2P1-0013")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P1-0014")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ShouldSendAckImmediately_ForOutOfOrderAndCePackets()
    {
        QuicAckGenerationState outOfOrderTracker = new();
        outOfOrderTracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 1, ackEliciting: true, receivedAtMicros: 1000);
        outOfOrderTracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 3, ackEliciting: true, receivedAtMicros: 1100);
        Assert.True(outOfOrderTracker.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));

        QuicAckGenerationState ceTracker = new();
        ceTracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            7,
            ackEliciting: true,
            receivedAtMicros: 1000,
            congestionExperienced: true,
            ecnCounts: new QuicEcnCounts(11, 12, 13));

        Assert.True(ceTracker.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2-0002">Only ack-eliciting packets MUST cause an ACK frame to be sent within the maximum ack delay.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2-0003">Packets that are not ack-eliciting MUST only be acknowledged when an ACK frame is sent for other reasons.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2-0004">When sending a packet for any reason, an endpoint SHOULD attempt to include an ACK frame if one has not been sent recently.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P1-0001">Ack-eliciting packets MUST be acknowledged at least once within the maximum delay the endpoint communicated using the max_ack_delay transport parameter.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P1-0004">An endpoint MUST acknowledge all ack-eliciting 0-RTT and 1-RTT packets within its advertised max_ack_delay.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P2-0001">A receiver determines how MUST frequently to send acknowledgments in response to ack-eliciting packets.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P2-0002">A receiver SHOULD send an ACK frame after receiving at least two ack-eliciting packets.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P2-0003">A receiver MAY process multiple available packets before determining whether to send an ACK frame in response.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P1-0010">An endpoint SHOULD send an ACK frame with other frames when there are new ack-eliciting packets to acknowledge.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P1-0011">When only non-ack-eliciting packets need to be acknowledged, an endpoint MAY choose not to send an ACK frame with outgoing frames until an ack-eliciting packet has been received.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S2-0003">Packets that contain ack-eliciting frames MUST elicit an ACK from the receiver within the maximum acknowledgment delay.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S3-0012">Packets that contain no ack-eliciting frames MUST be acknowledged only along with ack-eliciting packets.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S13P2-0002")]
    [Requirement("REQ-QUIC-RFC9000-S13P2-0003")]
    [Requirement("REQ-QUIC-RFC9000-S13P2-0004")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P2-0002")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P2-0003")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P1-0010")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P1-0011")]
    [Requirement("REQ-QUIC-RFC9002-S2-0003")]
    [Requirement("REQ-QUIC-RFC9002-S3-0012")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ShouldDelayAckUntilSecondAckElicitingPacketOrMaxAckDelay()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 1, ackEliciting: false, receivedAtMicros: 1000);
        Assert.False(tracker.ShouldIncludeAckFrameWithOutgoingPacket(QuicPacketNumberSpace.ApplicationData, nowMicros: 1200, maxAckDelayMicros: 1000));

        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 2, ackEliciting: true, receivedAtMicros: 1300);
        Assert.False(tracker.ShouldIncludeAckFrameWithOutgoingPacket(QuicPacketNumberSpace.ApplicationData, nowMicros: 1400, maxAckDelayMicros: 1000));

        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 3, ackEliciting: true, receivedAtMicros: 1500);
        Assert.True(tracker.ShouldIncludeAckFrameWithOutgoingPacket(QuicPacketNumberSpace.ApplicationData, nowMicros: 1600, maxAckDelayMicros: 1000));

        tracker.MarkAckFrameSent(QuicPacketNumberSpace.ApplicationData, sentAtMicros: 1650, ackOnlyPacket: false);
        Assert.False(tracker.ShouldIncludeAckFrameWithOutgoingPacket(QuicPacketNumberSpace.ApplicationData, nowMicros: 1700, maxAckDelayMicros: 1000));
        Assert.True(tracker.ShouldIncludeAckFrameWithOutgoingPacket(QuicPacketNumberSpace.ApplicationData, nowMicros: 2700, maxAckDelayMicros: 1000));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P1-0006">Since packets containing only ACK frames are not congestion controlled, an endpoint MUST NOT send more than one such packet in response to receiving an ack-eliciting packet.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S13P2P1-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void CanSendOnlyOneAckOnlyPacketPerAckElicitingPacket()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 1, ackEliciting: true, receivedAtMicros: 1000);
        Assert.True(tracker.CanSendAckOnlyPacket(QuicPacketNumberSpace.ApplicationData, nowMicros: 1500, maxAckDelayMicros: 1000));

        tracker.MarkAckFrameSent(QuicPacketNumberSpace.ApplicationData, sentAtMicros: 1500, ackOnlyPacket: true);
        Assert.False(tracker.CanSendAckOnlyPacket(QuicPacketNumberSpace.ApplicationData, nowMicros: 1600, maxAckDelayMicros: 1000));

        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 2, ackEliciting: true, receivedAtMicros: 1700);
        Assert.True(tracker.CanSendAckOnlyPacket(QuicPacketNumberSpace.ApplicationData, nowMicros: 1800, maxAckDelayMicros: 1000));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P3-0003">If it MUST NOT, then older ranges (those with the smallest packet numbers) are omitted.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P3-0004">A receiver MUST limit the number of ACK Ranges it remembers and sends in ACK frames.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P3-0007">A receiver MAY discard unacknowledged ACK Ranges to limit ACK frame size.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P3-0008">A receiver MUST discard unacknowledged ACK Ranges if an ACK frame would be too large to fit in a packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P3-0009">Receivers MAY also limit ACK frame size further to preserve space for other frames or to limit the capacity that acknowledgments consume.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P3-0010">A receiver MUST retain an ACK Range unless it can ensure that it will not subsequently accept packets with numbers in that range.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P3-0011">Receivers MAY discard all ACK Ranges if they retain the largest packet number that has been successfully processed.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0003")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0004")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0007")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0008")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0009")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0010")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0011")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryBuildAckFrame_TrimsOldestRangesWhenLimitReached()
    {
        QuicAckGenerationState keepTwoRanges = new(maximumRetainedAckRanges: 2);
        RecordAckedRanges(keepTwoRanges);

        Assert.True(keepTwoRanges.TryBuildAckFrame(QuicPacketNumberSpace.ApplicationData, nowMicros: 2000, out QuicAckFrame frame));
        Assert.Equal(10UL, frame.LargestAcknowledged);
        Assert.Equal(1UL, frame.FirstAckRange);
        Assert.Single(frame.AdditionalRanges);
        Assert.Equal(1UL, frame.AdditionalRanges[0].Gap);
        Assert.Equal(1UL, frame.AdditionalRanges[0].AckRangeLength);
        Assert.Equal(5UL, frame.AdditionalRanges[0].SmallestAcknowledged);
        Assert.Equal(6UL, frame.AdditionalRanges[0].LargestAcknowledged);

        QuicAckGenerationState keepOnlyLargestRange = new(maximumRetainedAckRanges: 1);
        RecordAckedRanges(keepOnlyLargestRange);

        Assert.True(keepOnlyLargestRange.TryBuildAckFrame(QuicPacketNumberSpace.ApplicationData, nowMicros: 2000, out QuicAckFrame compactFrame));
        Assert.Equal(10UL, compactFrame.LargestAcknowledged);
        Assert.Equal(1UL, compactFrame.FirstAckRange);
        Assert.Empty(compactFrame.AdditionalRanges);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P4P1-0006">Each packet number space MUST maintain separate acknowledgment state and separate ECN counts.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P6-0001">ACK frames MUST only be carried in a packet that has the same packet number space as the packet being acknowledged.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P6-0002">Packets that are protected with 1-RTT keys MUST be acknowledged in packets that are also protected with 1-RTT keys.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S3-0004">The encryption level MUST indicate the packet number space.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P6-0001")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P6-0002")]
    [Requirement("REQ-QUIC-RFC9002-S3-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void PacketNumberSpaces_AreTrackedIndependently()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.Initial,
            1,
            ackEliciting: true,
            receivedAtMicros: 1000,
            ecnCounts: new QuicEcnCounts(1, 0, 0));
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.Initial,
            2,
            ackEliciting: true,
            receivedAtMicros: 1010,
            ecnCounts: new QuicEcnCounts(2, 0, 0));
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.Handshake,
            7,
            ackEliciting: true,
            receivedAtMicros: 1020,
            ecnCounts: new QuicEcnCounts(0, 1, 0));
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            4,
            ackEliciting: true,
            receivedAtMicros: 1030,
            ecnCounts: new QuicEcnCounts(0, 0, 2));

        Assert.True(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.Initial));
        Assert.True(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.Handshake));
        Assert.False(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));

        Assert.True(tracker.TryBuildAckFrame(QuicPacketNumberSpace.Initial, nowMicros: 1100, out QuicAckFrame initialFrame));
        Assert.True(tracker.TryBuildAckFrame(QuicPacketNumberSpace.Handshake, nowMicros: 1100, out QuicAckFrame handshakeFrame));
        Assert.True(tracker.TryBuildAckFrame(QuicPacketNumberSpace.ApplicationData, nowMicros: 1100, out QuicAckFrame applicationFrame));

        Assert.Equal(2UL, initialFrame.LargestAcknowledged);
        Assert.Equal(2UL, initialFrame.EcnCounts!.Value.Ect0Count);
        Assert.Equal(0UL, initialFrame.EcnCounts!.Value.Ect1Count);
        Assert.Equal(0UL, initialFrame.EcnCounts!.Value.EcnCeCount);
        Assert.Equal(7UL, handshakeFrame.LargestAcknowledged);
        Assert.Equal(0UL, handshakeFrame.EcnCounts!.Value.Ect0Count);
        Assert.Equal(1UL, handshakeFrame.EcnCounts!.Value.Ect1Count);
        Assert.Equal(0UL, handshakeFrame.EcnCounts!.Value.EcnCeCount);
        Assert.Equal(4UL, applicationFrame.LargestAcknowledged);
        Assert.Equal(0UL, applicationFrame.EcnCounts!.Value.Ect0Count);
        Assert.Equal(0UL, applicationFrame.EcnCounts!.Value.Ect1Count);
        Assert.Equal(2UL, applicationFrame.EcnCounts!.Value.EcnCeCount);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P4P1-0004">On receiving an IP packet with an ECT(0), ECT(1), or ECN-CE codepoint, an ECN-enabled endpoint MUST access the ECN field and increase the corresponding ECT(0), ECT(1), or ECN-CE count.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P4P1-0005">These ECN counts MUST be included in subsequent ACK frames.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P1-0014">Packets marked with the ECN Congestion Experienced (CE) codepoint in the IP header SHOULD be acknowledged immediately.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P5-0005">When the measured acknowledgment delay is larger than its max_ack_delay, an endpoint SHOULD report the measured delay.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S3-0011">All packets MUST be acknowledged.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0010">ACK frames MUST carry the most recent set of acknowledgments and the acknowledgment delay from the largest acknowledged packet.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P1-0014")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P5-0005")]
    [Requirement("REQ-QUIC-RFC9002-S3-0011")]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0010")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryBuildAckFrame_UsesEcnCountsAndReportsMeasuredDelayWhenDelayed()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            8,
            ackEliciting: true,
            receivedAtMicros: 1000,
            congestionExperienced: true,
            ecnCounts: new QuicEcnCounts(11, 12, 13));

        Assert.True(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
        Assert.True(tracker.TryBuildAckFrame(QuicPacketNumberSpace.ApplicationData, nowMicros: 4000, out QuicAckFrame frame));

        Assert.Equal((byte)0x03, frame.FrameType);
        Assert.Equal(8UL, frame.LargestAcknowledged);
        Assert.Equal(3000UL, frame.AckDelay);
        Assert.NotNull(frame.EcnCounts);
        Assert.Equal(11UL, frame.EcnCounts!.Value.Ect0Count);
        Assert.Equal(12UL, frame.EcnCounts!.Value.Ect1Count);
        Assert.Equal(13UL, frame.EcnCounts!.Value.EcnCeCount);
        Assert.True(frame.AckDelay > 1000UL);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void SenderFlowController_UsesAckGenerationStateForImmediateAndScheduledAckFrames()
    {
        QuicSenderFlowController sender = new();

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            ackEliciting: true,
            receivedAtMicros: 1000);

        Assert.False(sender.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 3,
            ackEliciting: true,
            receivedAtMicros: 1100);

        Assert.True(sender.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
        Assert.True(sender.CanSendAckOnlyPacket(QuicPacketNumberSpace.ApplicationData, nowMicros: 1200, maxAckDelayMicros: 1000));

        Assert.True(sender.TryBuildAckFrame(QuicPacketNumberSpace.ApplicationData, nowMicros: 1200, out QuicAckFrame ackFrame));
        Assert.Equal(3UL, ackFrame.LargestAcknowledged);
        Assert.Equal(0UL, ackFrame.FirstAckRange);

        sender.MarkAckFrameSent(QuicPacketNumberSpace.ApplicationData, sentAtMicros: 1300, ackOnlyPacket: true);
        Assert.False(sender.CanSendAckOnlyPacket(QuicPacketNumberSpace.ApplicationData, nowMicros: 1400, maxAckDelayMicros: 1000));
        Assert.True(sender.ShouldIncludeAckFrameWithOutgoingPacket(QuicPacketNumberSpace.ApplicationData, nowMicros: 3400, maxAckDelayMicros: 1000));
    }

    private static void RecordAckedRanges(QuicAckGenerationState tracker)
    {
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 1, ackEliciting: true, receivedAtMicros: 1000);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 2, ackEliciting: true, receivedAtMicros: 1010);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 5, ackEliciting: true, receivedAtMicros: 1020);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 6, ackEliciting: true, receivedAtMicros: 1030);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 9, ackEliciting: true, receivedAtMicros: 1040);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 10, ackEliciting: true, receivedAtMicros: 1050);
    }
}
