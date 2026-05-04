namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P1P1-0018")]
public sealed class REQ_QUIC_RFC9000_S5P1P1_0018
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ConnectionIdIssuanceLimit_AvoidsAdditionalEndpointRouteAndTokenState()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            maximumLocallyIssuedConnectionIds: 1);
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.185", RemotePort: 443);
        byte[] firstConnectionId = [0xD0, 0xD1, 0xD2];
        byte[] secondConnectionId = [0xD3, 0xD4, 0xD5];

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));

        QuicConnectionTransitionResult firstIssue = runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 0,
                ConnectionId: 1UL,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0xD0),
                ConnectionIdBytes: firstConnectionId),
            nowTicks: 0);

        Assert.True(firstIssue.StateChanged);
        ApplyEndpointEffects(endpoint, handle, firstIssue.Effects);

        QuicConnectionIngressResult firstRoute = endpoint.ReceiveDatagram(
            QuicHeaderTestData.BuildShortHeader(0x00, [0xD0, 0xD1, 0xD2, 0xA1]),
            pathIdentity);

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, firstRoute.Disposition);
        Assert.Equal(handle, firstRoute.Handle);

        QuicConnectionTransitionResult retirement = runtime.Transition(
            new QuicConnectionConnectionIdRetiredEvent(
                ObservedAtTicks: 1,
                ConnectionId: 1UL),
            nowTicks: 1);

        Assert.True(retirement.StateChanged);
        ApplyEndpointEffects(endpoint, handle, retirement.Effects);

        QuicConnectionTransitionResult secondIssue = runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 2,
                ConnectionId: 2UL,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0xE0),
                ConnectionIdBytes: secondConnectionId),
            nowTicks: 2);

        Assert.False(secondIssue.StateChanged);
        Assert.DoesNotContain(
            secondIssue.Effects,
            effect => effect is QuicConnectionRegisterConnectionIdRouteEffect);
        Assert.DoesNotContain(
            secondIssue.Effects,
            effect => effect is QuicConnectionRegisterStatelessResetTokenEffect);

        QuicConnectionIngressResult secondRoute = endpoint.ReceiveDatagram(
            QuicHeaderTestData.BuildShortHeader(0x00, [0xD3, 0xD4, 0xD5, 0xA2]),
            pathIdentity);

        Assert.Equal(QuicConnectionIngressDisposition.Unroutable, secondRoute.Disposition);
        Assert.Null(secondRoute.Handle);
    }

    private static void ApplyEndpointEffects(
        QuicConnectionRuntimeEndpoint endpoint,
        QuicConnectionHandle handle,
        IEnumerable<QuicConnectionEffect> effects)
    {
        foreach (QuicConnectionEffect effect in effects)
        {
            Assert.True(endpoint.TryApplyEffect(handle, effect));
        }
    }
}
