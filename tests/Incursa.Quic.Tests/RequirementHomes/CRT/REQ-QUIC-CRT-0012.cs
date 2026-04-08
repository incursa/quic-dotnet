namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0012")]
public sealed class REQ_QUIC_CRT_0012
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EndpointClassifiesVersionNegotiationBeforeAnyConnectionMutation()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryRegisterConnectionId(handle, [0x10, 0x11]));

        byte[] datagram = QuicHeaderTestData.BuildVersionNegotiation(
            0x00,
            [0x10, 0x11],
            [0x20],
            1u);

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            datagram,
            new QuicConnectionPathIdentity("203.0.113.1"));

        Assert.Equal(QuicConnectionIngressDisposition.EndpointHandling, result.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.VersionNegotiation, result.HandlingKind);
        Assert.Null(result.Handle);
        Assert.Equal(0UL, runtime.TransitionSequence);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void EndpointMarksEmptyDatagramsAsMalformedWithoutRouting()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            ReadOnlyMemory<byte>.Empty,
            new QuicConnectionPathIdentity("203.0.113.2"));

        Assert.Equal(QuicConnectionIngressDisposition.Malformed, result.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.None, result.HandlingKind);
        Assert.Null(result.Handle);
        Assert.Equal(0UL, runtime.TransitionSequence);
    }
}
