namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S11-0005">A stateless reset MUST NOT be used by an endpoint that has the state necessary to send a frame on the connection.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S11-0005")]
public sealed class REQ_QUIC_RFC9000_S11_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ReceiveDatagram_RoutesAssociatedPacketsToTheRuntimeInsteadOfStatelessReset()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.93");
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x93);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 117UL, token));

        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(token);
        datagram[0] = 0x40;

        Assert.True(endpoint.TryRegisterConnectionId(handle, datagram.AsSpan(1, QuicStatelessReset.MinimumUnpredictableBytes)));

        TaskCompletionSource<QuicConnectionHandle> observedHandle = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using CancellationTokenSource cancellation = new();

        Task consumer = endpoint.RunAsync(
            (postedHandle, _, transition) =>
            {
                if (transition.EventKind == QuicConnectionEventKind.PacketReceived)
                {
                    observedHandle.TrySetResult(postedHandle);
                }
            },
            cancellationToken: cancellation.Token);

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(datagram, pathIdentity);

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, result.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.None, result.HandlingKind);
        Assert.Equal(handle, result.Handle);
        Assert.Equal(handle, await observedHandle.Task.WaitAsync(TimeSpan.FromSeconds(5)));

        cancellation.Cancel();
        await consumer;
        await endpoint.DisposeAsync();
        await runtime.DisposeAsync();
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ReceiveDatagram_DoesNotTreatAssociatedPacketsAsStatelessReset()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.94");
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x94);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 118UL, token));

        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(token);
        datagram[0] = 0x40;

        Assert.True(endpoint.TryRegisterConnectionId(handle, datagram.AsSpan(1, QuicStatelessReset.MinimumUnpredictableBytes)));

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(datagram, pathIdentity);

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, result.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.None, result.HandlingKind);
        Assert.Equal(handle, result.Handle);
        Assert.Equal(0UL, runtime.TransitionSequence);
    }
}
