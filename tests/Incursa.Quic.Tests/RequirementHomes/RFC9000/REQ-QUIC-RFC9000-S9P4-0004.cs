namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P4-0004")]
public sealed class REQ_QUIC_RFC9000_S9P4_0004
{
    private static readonly QuicConnectionPathIdentity ActivePath = new("203.0.113.10", RemotePort: 443);
    private static readonly QuicConnectionPathIdentity MigratedPath = new("203.0.113.11", RemotePort: 443);

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P4-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ValidatedPathMigrationKeepsOutgoingAckCoverageEligible()
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
            packetNumber: 2,
            ackEliciting: true,
            receivedAtMicros: 2_000);

        Assert.True(sender.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 2_100,
            maxAckDelayMicros: 1_000));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P4-0004")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ValidatedPathMigrationDoesNotMakeAnAckFrameDueBeforeASecondPacketArrives()
    {
        (QuicConnectionRuntime runtime, QuicSenderFlowController sender) = CreateRuntime();

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        PromoteMigratedPath(runtime);

        Assert.False(sender.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_500,
            maxAckDelayMicros: 1_000));
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
