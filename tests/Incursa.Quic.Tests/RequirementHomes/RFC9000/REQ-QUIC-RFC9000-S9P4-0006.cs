namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P4-0006")]
public sealed class REQ_QUIC_RFC9000_S9P4_0006
{
    private static readonly QuicConnectionPathIdentity ActivePath = new("203.0.113.12", RemotePort: 443);
    private static readonly QuicConnectionPathIdentity MigratedPath = new("203.0.113.13", RemotePort: 443);

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P4-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ValidatedPathMigrationKeepsAckFramesCoveringPacketsFromBothPaths()
    {
        (QuicConnectionRuntime runtime, QuicSenderFlowController sender) = CreateRuntime();

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        PromoteMigratedPath(runtime);

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 4,
            ackEliciting: true,
            receivedAtMicros: 2_000);

        Assert.True(sender.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 2_100,
            out QuicAckFrame frame));

        Assert.Equal(4UL, frame.LargestAcknowledged);
        Assert.Equal(0UL, frame.FirstAckRange);
        Assert.Single(frame.AdditionalRanges);
        Assert.Equal(1UL, frame.AdditionalRanges[0].Gap);
        Assert.Equal(0UL, frame.AdditionalRanges[0].AckRangeLength);
        Assert.Equal(1UL, frame.AdditionalRanges[0].SmallestAcknowledged);
        Assert.Equal(1UL, frame.AdditionalRanges[0].LargestAcknowledged);
        Assert.Equal(100UL, frame.AckDelay);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P4-0006")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ValidatedPathMigrationDoesNotInventAckCoverageForTheNewPath()
    {
        (QuicConnectionRuntime runtime, QuicSenderFlowController sender) = CreateRuntime();

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        PromoteMigratedPath(runtime);

        Assert.True(sender.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_500,
            out QuicAckFrame frame));

        Assert.Equal(1UL, frame.LargestAcknowledged);
        Assert.Equal(0UL, frame.FirstAckRange);
        Assert.Empty(frame.AdditionalRanges);
        Assert.Equal(500UL, frame.AckDelay);
    }

    private static (QuicConnectionRuntime Runtime, QuicSenderFlowController Sender) CreateRuntime()
    {
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(ActivePath);
        return (runtime, runtime.SendRuntime.FlowController);
    }

    private static void PromoteMigratedPath(QuicConnectionRuntime runtime)
    {
        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                MigratedPath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 10).StateChanged);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            MigratedPath,
            observedAtTicks: 20);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(MigratedPath, runtime.ActivePath!.Value.Identity);
        Assert.Equal(MigratedPath.RemoteAddress, runtime.LastValidatedRemoteAddress);
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == MigratedPath
            && !promote.RestoreSavedState);
    }
}
