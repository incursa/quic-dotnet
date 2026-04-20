namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P5-0001">If an application is no longer interested in the data it is receiving on a stream, it MAY abort reading the stream and specify an application error code.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S3P5-0001")]
public sealed class REQ_QUIC_RFC9000_S3P5_0001
{
    private static readonly byte[] PacketConnectionId =
    [
        0x0A, 0x0B, 0x0C,
    ];

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P5-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task AbortRead_UsesThePublicAbortApiWithAnApplicationErrorCode()
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

        QuicStream targetStream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        runtime.RegisterStreamObserver((ulong)targetStream.Id, notifications.Add);
        outboundEffects.Clear();

        targetStream.Abort(QuicAbortDirection.Read, 0x66);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());

        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            sendEffect.Datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        Assert.True(QuicFrameCodec.TryParseStopSendingFrame(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            out QuicStopSendingFrame stopSendingFrame,
            out _));
        Assert.Equal((ulong)targetStream.Id, stopSendingFrame.StreamId);
        Assert.Equal(0x66UL, stopSendingFrame.ApplicationProtocolErrorCode);

        QuicStreamNotification notification = Assert.Single(notifications);
        Assert.Equal(QuicStreamNotificationKind.ReadAborted, notification.Kind);

        QuicException exception = Assert.IsType<QuicException>(notification.Exception);
        Assert.Equal(QuicError.OperationAborted, exception.QuicError);
        Assert.Null(exception.ApplicationErrorCode);

        Assert.False(targetStream.CanRead);
        Assert.True(targetStream.CanWrite);

        await targetStream.DisposeAsync();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P5-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task AbortRead_RejectsStreamsWithoutReadableSides()
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

        QuicStream targetStream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Unidirectional);
        runtime.RegisterStreamObserver((ulong)targetStream.Id, notifications.Add);
        outboundEffects.Clear();

        Assert.Throws<InvalidOperationException>(
            () => targetStream.Abort(QuicAbortDirection.Read, 0x66));

        Assert.Empty(outboundEffects);
        Assert.Empty(notifications);

        await targetStream.DisposeAsync();
    }
}
