// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S12-2-P4-R01">Receivers MAY route based on the information in the first packet contained in a UDP datagram.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S12-2-P4-R01")]
public sealed class REQ_QUIC_RFC9000_0684
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Requirement("REQ-QUIC-RFC9000-0851")]
    [Trait("Category", "Positive")]
    public async Task ReceiveDatagram_RoutesBasedOnTheFirstPacketEvenWhenTheTrailingPacketTargetsAnotherConnection()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(1);
        using QuicConnectionRuntime firstRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        using QuicConnectionRuntime secondRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle firstHandle = endpoint.AllocateConnectionHandle();
        QuicConnectionHandle secondHandle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.21");
        byte[] firstDestinationConnectionId = [0x10, 0x11, 0x12, 0x13];
        byte[] secondDestinationConnectionId = [0x20, 0x21, 0x22, 0x23];
        byte[] firstPacket = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(
            packetNumberLength: 1,
            destinationConnectionId: firstDestinationConnectionId,
            sourceConnectionId: [0x30],
            protectedPayload: [0xA1]);
        byte[] secondPacket = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(
            packetNumberLength: 1,
            destinationConnectionId: secondDestinationConnectionId,
            sourceConnectionId: [0x40],
            protectedPayload: [0xB1]);
        byte[] datagram = [.. firstPacket, .. secondPacket];

        Assert.True(endpoint.TryRegisterConnection(firstHandle, firstRuntime));
        Assert.True(endpoint.TryRegisterConnection(secondHandle, secondRuntime));
        Assert.True(endpoint.TryRegisterConnectionId(firstHandle, firstDestinationConnectionId));
        Assert.True(endpoint.TryRegisterConnectionId(secondHandle, secondDestinationConnectionId));

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

        Assert.True(result.RoutedToConnection);
        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, result.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.None, result.HandlingKind);
        Assert.Equal(firstHandle, result.Handle);
        Assert.Equal(firstHandle, await observedHandle.Task.WaitAsync(TimeSpan.FromSeconds(5)));

        cancellation.Cancel();
        await consumer;
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ReceiveDatagram_DoesNotUseTheTrailingPacketToRecoverARouteWhenTheFirstPacketMisses()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(1);
        using QuicConnectionRuntime trailingRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle trailingHandle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.22");
        byte[] missingDestinationConnectionId = [0x50, 0x51, 0x52, 0x53];
        byte[] trailingDestinationConnectionId = [0x60, 0x61, 0x62, 0x63];
        byte[] firstPacket = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(
            packetNumberLength: 1,
            destinationConnectionId: missingDestinationConnectionId,
            sourceConnectionId: [0x70],
            protectedPayload: [0xC1]);
        byte[] trailingPacket = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(
            packetNumberLength: 1,
            destinationConnectionId: trailingDestinationConnectionId,
            sourceConnectionId: [0x80],
            protectedPayload: [0xD1]);
        byte[] datagram = [.. firstPacket, .. trailingPacket];

        Assert.True(endpoint.TryRegisterConnection(trailingHandle, trailingRuntime));
        Assert.True(endpoint.TryRegisterConnectionId(trailingHandle, trailingDestinationConnectionId));

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(datagram, pathIdentity);

        Assert.Equal(QuicConnectionIngressDisposition.Unroutable, result.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.None, result.HandlingKind);
        Assert.Null(result.Handle);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ReceiveDatagram_RoutesTheSmallestValidLeadingPacketBeforeAnyTrailingPacket()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(1);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.23");
        byte[] destinationConnectionId = [0x90];
        byte[] firstPacket = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(
            packetNumberLength: 1,
            destinationConnectionId: destinationConnectionId,
            sourceConnectionId: [0xA0],
            protectedPayload: []);
        byte[] trailingPacket = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(
            packetNumberLength: 1,
            destinationConnectionId: [0xB0],
            sourceConnectionId: [0xC0],
            protectedPayload: [0xE1]);
        byte[] datagram = [.. firstPacket, .. trailingPacket];

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryRegisterConnectionId(handle, destinationConnectionId));

        Assert.True(QuicPacketParser.TryGetPacketLength(datagram, out int firstPacketLength));
        Assert.Equal(firstPacket.Length, firstPacketLength);

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(datagram, pathIdentity);

        Assert.True(result.RoutedToConnection);
        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, result.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.None, result.HandlingKind);
        Assert.Equal(handle, result.Handle);
    }
}
