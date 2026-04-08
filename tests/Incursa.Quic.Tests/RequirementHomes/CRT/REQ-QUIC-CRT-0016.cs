namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0016")]
public sealed class REQ_QUIC_CRT_0016
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EndpointAppliesBindingEffectsAndRetiresThemExplicitly()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.20");
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken();
        byte[] routeDatagram = QuicHeaderTestData.BuildShortHeader(0x00, [0x10, 0x11, 0x22]);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryRegisterConnectionId(handle, [0x10, 0x11]));
        Assert.True(endpoint.TryApplyEffect(handle, new QuicConnectionUpdateEndpointBindingsEffect(pathIdentity)));
        Assert.True(endpoint.TryApplyEffect(handle, new QuicConnectionRegisterStatelessResetTokenEffect(71UL, token)));

        byte[] resetDatagram = QuicStatelessResetRequirementTestData.FormatDatagram(token);
        resetDatagram[0] = 0x40;
        resetDatagram[1] = 0xAA;
        resetDatagram[2] = 0xBB;

        QuicConnectionIngressResult routedBeforeRetirement = endpoint.ReceiveDatagram(routeDatagram, pathIdentity);
        QuicConnectionIngressResult resetBeforeRetirement = endpoint.ReceiveDatagram(resetDatagram, pathIdentity);

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, routedBeforeRetirement.Disposition);
        Assert.Equal(handle, routedBeforeRetirement.Handle);
        Assert.Equal(QuicConnectionIngressDisposition.EndpointHandling, resetBeforeRetirement.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.StatelessReset, resetBeforeRetirement.HandlingKind);
        Assert.Equal(handle, resetBeforeRetirement.Handle);

        Assert.True(endpoint.TryApplyEffect(handle, new QuicConnectionRetireStatelessResetTokenEffect(71UL)));
        Assert.True(endpoint.TryApplyEffect(handle, new QuicConnectionDiscardConnectionStateEffect()));

        QuicConnectionIngressResult routedAfterRetirement = endpoint.ReceiveDatagram(routeDatagram, pathIdentity);
        QuicConnectionIngressResult resetAfterRetirement = endpoint.ReceiveDatagram(resetDatagram, pathIdentity);

        Assert.Equal(QuicConnectionIngressDisposition.Unroutable, routedAfterRetirement.Disposition);
        Assert.Equal(QuicConnectionIngressDisposition.Unroutable, resetAfterRetirement.Disposition);
        Assert.Null(resetAfterRetirement.Handle);
        Assert.Equal(0UL, runtime.TransitionSequence);
    }
}
