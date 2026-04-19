namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P3P2-0003")]
public sealed class REQ_QUIC_RFC9000_S9P3P2_0003
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P3P2-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DiscardedConnectionsCanStillCreateStatelessResetDatagrams()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.130", RemotePort: 443);
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0xB0);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 301UL, token));

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPathValidationFailedEvent(
                ObservedAtTicks: 10,
                new QuicConnectionPathIdentity("203.0.113.131", RemotePort: 443),
                IsAbandoned: true),
            nowTicks: 10);

        QuicConnectionDiscardConnectionStateEffect discard = Assert.Single(
            result.Effects.OfType<QuicConnectionDiscardConnectionStateEffect>());
        Assert.Equal(QuicConnectionPhase.Discarded, runtime.Phase);
        Assert.True(runtime.TerminalState.HasValue);
        Assert.True(endpoint.TryApplyEffect(handle, discard));

        QuicConnectionStatelessResetEmissionResult emissionResult = endpoint.TryCreateStatelessResetDatagram(
            handle,
            301UL,
            triggeringPacketLength: 100,
            hasLoopPreventionState: true);

        Assert.True(emissionResult.Emitted);
        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.Emitted, emissionResult.Disposition);
        Assert.Equal(pathIdentity, emissionResult.PathIdentity);
        Assert.Equal(99, emissionResult.Datagram.Length);
        Assert.True(QuicStatelessReset.IsPotentialStatelessReset(emissionResult.Datagram.Span));
        QuicStatelessResetRequirementTestData.AssertTailTokenMatches(emissionResult.Datagram.Span, token);
    }
}
