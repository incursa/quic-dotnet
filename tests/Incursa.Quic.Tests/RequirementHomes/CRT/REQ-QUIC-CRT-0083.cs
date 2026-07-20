namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0083")]
public sealed class REQ_QUIC_CRT_0083
{
    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void EndpointExcludesRetiredStatelessResetTokensFromMatching()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.50");
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken();
        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(token);
        datagram[0] = 0x40;

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 91UL, token));
        Assert.True(endpoint.TryRetireStatelessResetToken(handle, 91UL));

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(datagram, pathIdentity);

        Assert.Equal(QuicConnectionIngressDisposition.Unroutable, result.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.None, result.HandlingKind);
        Assert.Null(result.Handle);
        Assert.Equal(0UL, runtime.TransitionSequence);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void EndpointDoesNotMatchTokensForNeverUsedConnectionIds()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.51");
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken();
        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(token);
        datagram[0] = 0x40;

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(datagram, pathIdentity);

        Assert.Equal(QuicConnectionIngressDisposition.Unroutable, result.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.None, result.HandlingKind);
        Assert.Null(result.Handle);
        Assert.Equal(0UL, runtime.TransitionSequence);
    }
}
