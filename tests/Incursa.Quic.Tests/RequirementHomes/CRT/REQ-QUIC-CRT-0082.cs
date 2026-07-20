namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0082")]
public sealed class REQ_QUIC_CRT_0082
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EndpointRetargetsResetMatchingWhenTheBindingChanges()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity firstPath = new("203.0.113.40");
        QuicConnectionPathIdentity secondPath = new("203.0.113.41");
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken();

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, firstPath));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 81UL, token));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, secondPath));

        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(token);
        datagram[0] = 0x40;

        QuicConnectionIngressResult firstAddressResult = endpoint.ReceiveDatagram(datagram, firstPath);
        QuicConnectionIngressResult secondAddressResult = endpoint.ReceiveDatagram(datagram, secondPath);

        Assert.Equal(QuicConnectionIngressDisposition.Unroutable, firstAddressResult.Disposition);
        Assert.Equal(QuicConnectionIngressDisposition.EndpointHandling, secondAddressResult.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.StatelessReset, secondAddressResult.HandlingKind);
        Assert.Equal(handle, secondAddressResult.Handle);
        Assert.Equal(0UL, runtime.TransitionSequence);
    }
}
