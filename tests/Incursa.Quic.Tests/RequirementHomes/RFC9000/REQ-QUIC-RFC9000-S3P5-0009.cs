namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P5-0009">An endpoint that sends a STOP_SENDING frame MAY ignore the error code in any RESET_STREAM frames subsequently received for that stream.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S3P5-0009")]
public sealed class REQ_QUIC_RFC9000_S3P5_0009
{
    private static readonly byte[] PacketConnectionId = [0x0A, 0x0B, 0x0C];

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P5-0009")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task AbortStreamReadsAsync_IgnoresSubsequentResetStreamErrorCode()
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

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        runtime.RegisterStreamObserver((ulong)stream.Id, notifications.Add);
        outboundEffects.Clear();

        await runtime.AbortStreamReadsAsync((ulong)stream.Id, 0x66);

        QuicConnectionSendDatagramEffect stopSendingEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.True(TryOpenStopSendingFrame(
            runtime,
            stopSendingEffect,
            out QuicStopSendingFrame stopSendingFrame));
        Assert.Equal((ulong)stream.Id, stopSendingFrame.StreamId);
        Assert.Equal(0x66UL, stopSendingFrame.ApplicationProtocolErrorCode);

        QuicStreamNotification localNotification = Assert.Single(notifications);
        Assert.Equal(QuicStreamNotificationKind.ReadAborted, localNotification.Kind);
        QuicException localException = Assert.IsType<QuicException>(localNotification.Exception);
        Assert.Equal(QuicError.OperationAborted, localException.QuicError);
        Assert.Null(localException.ApplicationErrorCode);

        notifications.Clear();
        outboundEffects.Clear();

        QuicConnectionTransitionResult resetResult = ReceiveProtectedApplicationPayload(
            runtime,
            QuicFrameTestData.BuildResetStreamFrame(new QuicResetStreamFrame(
                (ulong)stream.Id,
                applicationProtocolErrorCode: 0x99,
                finalSize: 0)));
        Assert.True(resetResult.StateChanged);

        Assert.DoesNotContain(
            notifications,
            notification => notification.Kind == QuicStreamNotificationKind.ReadAborted);
        Assert.False(runtime.StreamRegistry.Bookkeeping.TryGetReceiveAbortErrorCode((ulong)stream.Id, out _));

        Assert.True(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot(
            (ulong)stream.Id,
            out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.ResetRead, snapshot.ReceiveState);
        Assert.False(snapshot.HasReceiveAbortErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P5-0009")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveResetStreamFrame_RejectsFinalSizeChangesAfterStopSendingIsSent()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState();

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryMarkLocalStopSendingFrameSent(
            streamId.Value,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId.Value, 0x99, 0),
            out QuicMaxDataFrame maxDataFrame,
            out errorCode));
        Assert.Equal(default, maxDataFrame);
        Assert.Equal(default, errorCode);

        Assert.False(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId.Value, 0x99, 1),
            out maxDataFrame,
            out errorCode));
        Assert.Equal(default, maxDataFrame);
        Assert.Equal(QuicTransportErrorCode.FinalSizeError, errorCode);

        Assert.False(state.TryGetReceiveAbortErrorCode(streamId.Value, out _));
    }

    private static bool TryOpenStopSendingFrame(
        QuicConnectionRuntime runtime,
        QuicConnectionSendDatagramEffect effect,
        out QuicStopSendingFrame stopSendingFrame)
    {
        stopSendingFrame = default;
        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        return coordinator.TryOpenProtectedApplicationDataPacket(
            effect.Datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength)
            && QuicStreamControlFrameTestSupport.TryFindStopSendingFrame(
                openedPacket.AsSpan(payloadOffset, payloadLength),
                out stopSendingFrame,
                out _,
                out _);
    }

    private static QuicConnectionTransitionResult ReceiveProtectedApplicationPayload(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> payload)
    {
        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            out byte[] protectedPacket));

        Assert.NotNull(runtime.ActivePath);
        return runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                runtime.ActivePath.Value.Identity,
                protectedPacket),
            nowTicks: 1);
    }
}
