namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0831")]
public sealed class REQ_QUIC_RFC9000_0831
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Requirement("REQ-QUIC-RFC9000-0831")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2-0005")]
    [Trait("Category", "Positive")]
    public void PathValidationPacketsOnANewPathAreMarkedEct0()
    {
        QuicConnectionPathIdentity activePath = new(
            RemoteAddress: "203.0.113.80",
            LocalAddress: "198.51.100.80",
            RemotePort: 443,
            LocalPort: 61310);
        QuicConnectionPathIdentity newPath = new(
            RemoteAddress: "203.0.113.81",
            LocalAddress: "198.51.100.80",
            RemotePort: 443,
            LocalPort: 61310);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateServerRuntimeWithActivePath(activePath);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                newPath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 20);

        Assert.True(result.StateChanged);
        Assert.Contains(result.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect sendDatagramEffect
            && sendDatagramEffect.PathIdentity == newPath
            && sendDatagramEffect.EcnMarking == QuicEcnMarking.Ect0
            && QuicFrameCodec.TryParsePathChallengeFrame(sendDatagramEffect.Datagram.Span, out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Requirement("REQ-QUIC-RFC9000-0831")]
    [Trait("Category", "Negative")]
    public void ActivePathPacketsDoNotStartAnEct0PathValidationProbe()
    {
        QuicConnectionPathIdentity activePath = new(
            RemoteAddress: "203.0.113.80",
            LocalAddress: "198.51.100.80",
            RemotePort: 443,
            LocalPort: 61310);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateServerRuntimeWithActivePath(activePath);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                activePath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 20);

        Assert.DoesNotContain(result.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect sendDatagramEffect
            && sendDatagramEffect.PathIdentity == activePath
            && sendDatagramEffect.EcnMarking == QuicEcnMarking.Ect0
            && QuicFrameCodec.TryParsePathChallengeFrame(sendDatagramEffect.Datagram.Span, out _, out _));
    }
}
