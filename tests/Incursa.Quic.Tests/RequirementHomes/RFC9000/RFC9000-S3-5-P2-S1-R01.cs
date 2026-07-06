// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S3-5-P2-S1-R01">If the stream is in the Recv or Size Known state, the transport SHOULD signal aborting reading by sending a STOP_SENDING frame to prompt closure of the stream in the opposite direction.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S3-5-P2-S1-R01")]
public sealed class REQ_QUIC_RFC9000_S3P5_0002
{
    private static readonly byte[] PacketConnectionId =
    [
        0x0A, 0x0B, 0x0C,
    ];

    [Fact]
    [Requirement("RFC9000-S3-5-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task AbortStreamReadsAsync_EmitsStopSendingAndRaisesReadAbortedNotification()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        List<QuicConnectionEffect> outboundEffects = [];
        List<QuicStreamNotification> notifications = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        runtime.RegisterStreamObserver(0, notifications.Add);

        await runtime.AbortStreamReadsAsync(0, 0x99);

        QuicConnectionSendDatagramEffect stopSendingEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());

        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            stopSendingEffect.Datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        Assert.True(QuicStreamControlFrameTestSupport.TryFindStopSendingFrame(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            out QuicStopSendingFrame stopSendingFrame,
            out _,
            out _));
        Assert.Equal(0UL, stopSendingFrame.StreamId);
        Assert.Equal(0x99UL, stopSendingFrame.ApplicationProtocolErrorCode);

        QuicStreamNotification notification = Assert.Single(notifications);
        Assert.Equal(QuicStreamNotificationKind.ReadAborted, notification.Kind);

        QuicException exception = Assert.IsType<QuicException>(notification.Exception);
        Assert.Equal(QuicError.OperationAborted, exception.QuicError);
        Assert.Null(exception.ApplicationErrorCode);
    }

    [Fact]
    [Requirement("RFC9000-S3-5-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task AbortStreamReadsAsync_EmitsStopSendingFromSizeKnownState()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        List<QuicConnectionEffect> outboundEffects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream targetStream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        Assert.Equal(0L, targetStream.Id);
        outboundEffects.Clear();

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, (ulong)targetStream.Id, [], offset: 4),
            out QuicStreamFrame finalSizeFrame));
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryReceiveStreamFrame(finalSizeFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot((ulong)targetStream.Id, out QuicConnectionStreamSnapshot sizeKnownSnapshot));
        Assert.Equal(QuicStreamReceiveState.SizeKnown, sizeKnownSnapshot.ReceiveState);

        await runtime.AbortStreamReadsAsync((ulong)targetStream.Id, 0x77);

        QuicConnectionSendDatagramEffect stopSendingEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());

        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            stopSendingEffect.Datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        Assert.True(QuicStreamControlFrameTestSupport.TryFindStopSendingFrame(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            out QuicStopSendingFrame stopSendingFrame,
            out _,
            out _));
        Assert.Equal((ulong)targetStream.Id, stopSendingFrame.StreamId);
        Assert.Equal(0x77UL, stopSendingFrame.ApplicationProtocolErrorCode);

        await targetStream.DisposeAsync();
    }

    [Fact]
    [Requirement("RFC9000-S3-5-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task AbortStreamReadsAsync_DoesNotEmitResetStreamOrWriteAbortedNotification()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        List<QuicConnectionEffect> outboundEffects = [];
        List<QuicStreamNotification> notifications = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        runtime.RegisterStreamObserver(0, notifications.Add);

        await runtime.AbortStreamReadsAsync(0, 0x99);

        QuicConnectionSendDatagramEffect stopSendingEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());

        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            stopSendingEffect.Datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        Assert.False(QuicStreamControlFrameTestSupport.TryFindResetStreamFrame(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            out _,
            out _,
            out _));
        Assert.DoesNotContain(notifications, notification => notification.Kind == QuicStreamNotificationKind.WriteAborted);
    }

    [Fact]
    [Requirement("RFC9000-S3-5-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public async Task Fuzz_AbortStreamReadsAsync_EmitsStopSendingForAbortErrorCodes()
    {
        ulong[] applicationErrorCodes =
        [
            0,
            0x77,
            0x99,
            QuicVariableLengthInteger.MaxValue,
        ];

        foreach (ulong applicationErrorCode in applicationErrorCodes)
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            List<QuicConnectionEffect> outboundEffects = [];
            runtime.SetLocalApiEventDispatcher(connectionEvent =>
            {
                QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
                outboundEffects.AddRange(transition.Effects);
                return true;
            });

            await runtime.AbortStreamReadsAsync(0, applicationErrorCode);

            QuicStopSendingFrame stopSendingFrame = OpenSingleStopSendingFrame(runtime, outboundEffects);
            Assert.Equal(0UL, stopSendingFrame.StreamId);
            Assert.Equal(applicationErrorCode, stopSendingFrame.ApplicationProtocolErrorCode);
        }
    }

    private static QuicStopSendingFrame OpenSingleStopSendingFrame(
        QuicConnectionRuntime runtime,
        IReadOnlyCollection<QuicConnectionEffect> outboundEffects)
    {
        QuicConnectionSendDatagramEffect stopSendingEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());

        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            stopSendingEffect.Datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        Assert.True(QuicStreamControlFrameTestSupport.TryFindStopSendingFrame(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            out QuicStopSendingFrame stopSendingFrame,
            out _,
            out _));

        return stopSendingFrame;
    }
}
