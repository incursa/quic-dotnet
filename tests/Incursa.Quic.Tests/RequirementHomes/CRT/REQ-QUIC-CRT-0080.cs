namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0080")]
public sealed class REQ_QUIC_CRT_0080
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EndpointScreensUnassociatedLongHeadersAsUnroutable()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));

        byte[] datagram = QuicHeaderTestData.BuildShortHeader(0x00, [0x55, 0x56, 0x57]);

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            datagram,
            new QuicConnectionPathIdentity("203.0.113.30"));

        Assert.Equal(QuicConnectionIngressDisposition.Unroutable, result.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.None, result.HandlingKind);
        Assert.Null(result.Handle);
        Assert.Equal(0UL, runtime.TransitionSequence);
    }
}
