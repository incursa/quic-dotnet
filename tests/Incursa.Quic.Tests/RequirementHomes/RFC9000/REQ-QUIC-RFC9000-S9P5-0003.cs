namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P5-0003")]
public sealed class REQ_QUIC_RFC9000_S9P5_0003
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P5-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EndpointRejectsConnectionIdReuseAcrossDifferentDestinationAddresses()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime firstRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        using QuicConnectionRuntime secondRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle firstHandle = endpoint.AllocateConnectionHandle();
        QuicConnectionHandle secondHandle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity firstPath = new("203.0.113.170", "198.51.100.170", 443, 61234);
        QuicConnectionPathIdentity secondPath = new("203.0.113.171", "198.51.100.170", 443, 61235);

        Assert.True(endpoint.TryRegisterConnection(firstHandle, firstRuntime));
        Assert.True(endpoint.TryRegisterConnection(secondHandle, secondRuntime));
        Assert.True(endpoint.TryUpdateEndpointBinding(firstHandle, firstPath));
        Assert.True(endpoint.TryRegisterConnectionId(firstHandle, [0x40, 0x41]));
        Assert.True(endpoint.TryUpdateEndpointBinding(secondHandle, secondPath));

        Assert.False(endpoint.TryRegisterConnectionId(secondHandle, [0x40, 0x41]));
    }
}
