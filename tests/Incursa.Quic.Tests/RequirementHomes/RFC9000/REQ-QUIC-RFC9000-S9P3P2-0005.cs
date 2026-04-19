namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P3P2-0005")]
public sealed class REQ_QUIC_RFC9000_S9P3P2_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DiscardedConnectionsWithoutAStatelessResetTokenCannotCreateADatagram()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.132", RemotePort: 443);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPathValidationFailedEvent(
                ObservedAtTicks: 10,
                new QuicConnectionPathIdentity("203.0.113.133", RemotePort: 443),
                IsAbandoned: true),
            nowTicks: 10);

        QuicConnectionDiscardConnectionStateEffect discard = Assert.Single(
            result.Effects.OfType<QuicConnectionDiscardConnectionStateEffect>());
        Assert.Equal(QuicConnectionPhase.Discarded, runtime.Phase);
        Assert.True(runtime.TerminalState.HasValue);
        Assert.True(endpoint.TryApplyEffect(handle, discard));

        QuicConnectionStatelessResetEmissionResult emissionResult = endpoint.TryCreateStatelessResetDatagram(
            handle,
            302UL,
            triggeringPacketLength: 100,
            hasLoopPreventionState: true);

        Assert.False(emissionResult.Emitted);
        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.TokenUnavailable, emissionResult.Disposition);
        Assert.Null(emissionResult.PathIdentity);
        Assert.True(emissionResult.Datagram.IsEmpty);
    }
}
