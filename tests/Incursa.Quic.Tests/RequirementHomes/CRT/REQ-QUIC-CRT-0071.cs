namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0071")]
public sealed class REQ_QUIC_CRT_0071
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActivePathPromotionEmitsAnEndpointApplicableBindingEffect()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(
            new QuicConnectionPathIdentity("203.0.113.171", RemotePort: 443));
        QuicConnectionPathIdentity candidatePath = new("203.0.113.172", RemotePort: 443);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, runtime.ActivePath!.Value.Identity));
        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 20, candidatePath, datagram),
            nowTicks: 20).StateChanged);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            candidatePath,
            observedAtTicks: 30);

        QuicConnectionPromoteActivePathEffect promote = Assert.Single(
            validationResult.Effects.OfType<QuicConnectionPromoteActivePathEffect>());
        Assert.Equal(candidatePath, promote.PathIdentity);
        Assert.False(promote.RestoreSavedState);
        Assert.True(endpoint.TryApplyEffect(handle, promote));
        Assert.Equal(candidatePath, runtime.ActivePath!.Value.Identity);
    }
}
