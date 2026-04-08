namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0086")]
public sealed class REQ_QUIC_CRT_0086
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimeRetiresAssociatedStatelessResetTokensWhenConnectionIdsAreRetired()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.90");
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x90);
        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(token);
        datagram[0] = 0x40;

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));

        QuicConnectionTransitionResult issued = runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 0,
                ConnectionId: 281UL,
                StatelessResetToken: token),
            nowTicks: 0);

        foreach (QuicConnectionEffect effect in issued.Effects)
        {
            Assert.True(endpoint.TryApplyEffect(handle, effect));
        }

        QuicConnectionIngressResult beforeRetirement = endpoint.ReceiveDatagram(datagram, pathIdentity);

        QuicConnectionTransitionResult retired = runtime.Transition(
            new QuicConnectionConnectionIdRetiredEvent(
                ObservedAtTicks: 0,
                ConnectionId: 281UL),
            nowTicks: 0);

        Assert.Contains(retired.Effects, effect => effect is QuicConnectionRetireStatelessResetTokenEffect retire && retire.ConnectionId == 281UL);
        foreach (QuicConnectionEffect effect in retired.Effects)
        {
            Assert.True(endpoint.TryApplyEffect(handle, effect));
        }

        QuicConnectionIngressResult afterRetirement = endpoint.ReceiveDatagram(datagram, pathIdentity);

        Assert.Equal(QuicConnectionIngressDisposition.EndpointHandling, beforeRetirement.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.StatelessReset, beforeRetirement.HandlingKind);
        Assert.Equal(handle, beforeRetirement.Handle);
        Assert.Equal(QuicConnectionIngressDisposition.Unroutable, afterRetirement.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.None, afterRetirement.HandlingKind);
        Assert.Null(afterRetirement.Handle);
    }
}
