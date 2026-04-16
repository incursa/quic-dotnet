namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P5-0002")]
public sealed class REQ_QUIC_RFC9000_S9P5_0002
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P5-0002")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EndpointRejectsConnectionIdReuseAcrossDifferentLocalAddresses()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime firstRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        using QuicConnectionRuntime secondRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle firstHandle = endpoint.AllocateConnectionHandle();
        QuicConnectionHandle secondHandle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity firstPath = new("203.0.113.160", "198.51.100.160", 443, 61234);
        QuicConnectionPathIdentity secondPath = new("203.0.113.160", "198.51.100.161", 443, 61235);

        Assert.True(endpoint.TryRegisterConnection(firstHandle, firstRuntime));
        Assert.True(endpoint.TryRegisterConnection(secondHandle, secondRuntime));
        Assert.True(endpoint.TryUpdateEndpointBinding(firstHandle, firstPath));
        Assert.True(endpoint.TryRegisterConnectionId(firstHandle, [0x30, 0x31]));
        Assert.True(endpoint.TryUpdateEndpointBinding(secondHandle, secondPath));

        Assert.False(endpoint.TryRegisterConnectionId(secondHandle, [0x30, 0x31]));
    }
}
