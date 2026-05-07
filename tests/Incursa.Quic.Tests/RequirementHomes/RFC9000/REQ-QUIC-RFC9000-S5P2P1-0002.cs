namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P2P1-0002")]
public sealed class REQ_QUIC_RFC9000_S5P2P1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EndpointDoesNotMatchZeroLengthConnectionIdPacketsWhenTheLocalEndpointDiffers()
    {
        QuicConnectionPathIdentity registeredPath = new("203.0.113.20", "192.0.2.20", 44331, 4433);
        QuicConnectionPathIdentity mismatchedLocalEndpoint = new("203.0.113.21", "192.0.2.21", 44332, 4433);
        var scenario = QuicS5P2PacketAssociationTestSupport.CreateRegisteredEndpoint(
            ReadOnlySpan<byte>.Empty,
            registeredPath);
        using QuicConnectionRuntime runtime = scenario.Runtime;
        using QuicConnectionRuntimeEndpoint endpoint = scenario.Endpoint;

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            QuicS5P2PacketAssociationTestSupport.BuildShortHeaderDatagram(ReadOnlySpan<byte>.Empty),
            mismatchedLocalEndpoint);

        Assert.Equal(QuicConnectionIngressDisposition.Unroutable, result.Disposition);
        Assert.Null(result.Handle);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void EndpointMatchesZeroLengthConnectionIdPacketsByLocalAddressAndPort()
    {
        QuicConnectionPathIdentity registeredPath = new("203.0.113.20", "192.0.2.20", 44331, 4433);
        QuicConnectionPathIdentity matchingLocalEndpoint = new("203.0.113.21", "192.0.2.20", 44332, 4433);
        var scenario = QuicS5P2PacketAssociationTestSupport.CreateRegisteredEndpoint(
            ReadOnlySpan<byte>.Empty,
            registeredPath);
        using QuicConnectionRuntime runtime = scenario.Runtime;
        using QuicConnectionRuntimeEndpoint endpoint = scenario.Endpoint;

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            QuicS5P2PacketAssociationTestSupport.BuildShortHeaderDatagram(ReadOnlySpan<byte>.Empty),
            matchingLocalEndpoint);

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, result.Disposition);
        Assert.Equal(scenario.Handle, result.Handle);
    }
}
