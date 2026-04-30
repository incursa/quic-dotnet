namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0009")]
public sealed class REQ_QUIC_CRT_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EndpointRouteKeyChurnDoesNotChangeTheStableConnectionHandle()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(3);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        byte[] oldRoute = [0x10, 0x11];
        byte[] newRoute = [0x20, 0x21];

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        int shardIndex = endpoint.GetShardIndex(handle);
        Assert.True(endpoint.TryRegisterConnectionId(handle, oldRoute));

        QuicConnectionIngressResult oldRouteResult = endpoint.ReceiveDatagram(
            QuicHeaderTestData.BuildShortHeader(0x00, [0x10, 0x11, 0x99]),
            new QuicConnectionPathIdentity("203.0.113.130"));

        Assert.True(endpoint.TryRetireConnectionId(handle, oldRoute));
        Assert.True(endpoint.TryRegisterConnectionId(handle, newRoute));

        QuicConnectionIngressResult retiredRouteResult = endpoint.ReceiveDatagram(
            QuicHeaderTestData.BuildShortHeader(0x00, [0x10, 0x11, 0x99]),
            new QuicConnectionPathIdentity("203.0.113.130"));
        QuicConnectionIngressResult newRouteResult = endpoint.ReceiveDatagram(
            QuicHeaderTestData.BuildShortHeader(0x00, [0x20, 0x21, 0x99]),
            new QuicConnectionPathIdentity("203.0.113.130"));

        Assert.Equal(handle, oldRouteResult.Handle);
        Assert.Equal(QuicConnectionIngressDisposition.Unroutable, retiredRouteResult.Disposition);
        Assert.Null(retiredRouteResult.Handle);
        Assert.Equal(handle, newRouteResult.Handle);
        Assert.Equal(shardIndex, endpoint.GetShardIndex(handle));
    }
}
