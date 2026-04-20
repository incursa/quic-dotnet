namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P5-0002">If the stream is in the Recv or Size Known state, the transport SHOULD signal aborting reading by sending a STOP_SENDING frame to prompt closure of the stream in the opposite direction.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S3P5-0002")]
public sealed class REQ_QUIC_RFC9000_S3P5_0002
{
    private static readonly byte[] PacketConnectionId =
    [
        0x0A, 0x0B, 0x0C,
    ];

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P5-0002")]
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

        Assert.True(QuicFrameCodec.TryParseStopSendingFrame(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            out QuicStopSendingFrame stopSendingFrame,
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
    [Requirement("REQ-QUIC-RFC9000-S3P5-0002")]
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

        Assert.False(QuicFrameCodec.TryParseResetStreamFrame(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            out _,
            out _));
        Assert.DoesNotContain(notifications, notification => notification.Kind == QuicStreamNotificationKind.WriteAborted);
    }
}
