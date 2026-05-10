namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S13P4P2-0002")]
public sealed class REQ_QUIC_RFC9000_S13P4P2_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2-0002")]
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
}
