// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S11-P3-S2-R01">A stateless reset MUST NOT be used by an endpoint that has the state necessary to send a frame on the connection.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S11-P3-S2-R01")]
public sealed class REQ_QUIC_RFC9000_0661
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("RFC9000-S5-2-3-P4-R01")]
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
        Assert.True(runtime.CanSendOrdinaryPackets);

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
        Assert.True(runtime.CanSendOrdinaryPackets);

        cancellation.Cancel();
        await consumer;
        await endpoint.DisposeAsync();
        await runtime.DisposeAsync();
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [Requirement("RFC9000-S5-2-3-P4-R01")]
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
        Assert.True(runtime.CanSendOrdinaryPackets);

        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(token);
        datagram[0] = 0x40;

        Assert.True(endpoint.TryRegisterConnectionId(handle, datagram.AsSpan(1, QuicStatelessReset.MinimumUnpredictableBytes)));

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(datagram, pathIdentity);

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, result.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.None, result.HandlingKind);
        Assert.Equal(handle, result.Handle);
        Assert.Equal(0UL, runtime.TransitionSequence);
        Assert.True(runtime.CanSendOrdinaryPackets);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    [Requirement("RFC9000-S5-2-3-P4-R01")]
    public void Fuzz_ReceiveDatagram_RoutesAssociatedPacketsWhenFrameTransmissionStateExists()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(8);

        for (int index = 0; index < 4; index++)
        {
            using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
            QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
            QuicConnectionPathIdentity pathIdentity = new($"203.0.113.{120 + index}", RemotePort: 443 + index);
            byte[] token = QuicStatelessResetRequirementTestData.CreateToken((byte)(0xA0 + index));

            Assert.True(endpoint.TryRegisterConnection(handle, runtime));
            Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
            Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 220UL + (ulong)index, token));
            Assert.True(runtime.CanSendOrdinaryPackets);

            byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(token);
            datagram[0] = 0x40;

            Assert.True(endpoint.TryRegisterConnectionId(
                handle,
                datagram.AsSpan(1, QuicStatelessReset.MinimumUnpredictableBytes)));

            QuicConnectionIngressResult result = endpoint.ReceiveDatagram(datagram, pathIdentity);

            Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, result.Disposition);
            Assert.Equal(QuicConnectionEndpointHandlingKind.None, result.HandlingKind);
            Assert.Equal(handle, result.Handle);
            Assert.Equal(0UL, runtime.TransitionSequence);
            Assert.True(runtime.CanSendOrdinaryPackets);
        }
    }
}
