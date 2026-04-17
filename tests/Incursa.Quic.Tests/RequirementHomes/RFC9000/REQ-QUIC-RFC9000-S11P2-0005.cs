namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S11P2-0005">Application protocols SHOULD define rules for handling streams that are prematurely canceled by either endpoint.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S11P2-0005")]
public sealed class REQ_QUIC_RFC9000_S11P2_0005
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S11P2-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task AbortDirections_ExposeApplicationVisibleCancellationNotifications()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        List<QuicStreamNotification> notifications = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            _ = runtime.Transition(connectionEvent);
            return true;
        });

        QuicStream writeStream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        QuicStream readStream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);

        runtime.RegisterStreamObserver((ulong)writeStream.Id, notifications.Add);
        runtime.RegisterStreamObserver((ulong)readStream.Id, notifications.Add);

        writeStream.Abort(QuicAbortDirection.Write, 0x11);
        readStream.Abort(QuicAbortDirection.Read, 0x22);

        Assert.Equal(2, notifications.Count);
        Assert.Collection(
            notifications,
            notification =>
            {
                Assert.Equal(QuicStreamNotificationKind.WriteAborted, notification.Kind);
                QuicException exception = Assert.IsType<QuicException>(notification.Exception);
                Assert.Equal(QuicError.OperationAborted, exception.QuicError);
                Assert.Null(exception.ApplicationErrorCode);
            },
            notification =>
            {
                Assert.Equal(QuicStreamNotificationKind.ReadAborted, notification.Kind);
                QuicException exception = Assert.IsType<QuicException>(notification.Exception);
                Assert.Equal(QuicError.OperationAborted, exception.QuicError);
                Assert.Null(exception.ApplicationErrorCode);
            });

        Assert.True(writeStream.CanRead);
        Assert.False(writeStream.CanWrite);
        Assert.False(readStream.CanRead);
        Assert.True(readStream.CanWrite);

        await writeStream.DisposeAsync();
        await readStream.DisposeAsync();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S11P2-0005")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task AbortDirections_DoNotEscalateToConnectionTermination()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        List<QuicStreamNotification> notifications = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            _ = runtime.Transition(connectionEvent);
            return true;
        });

        QuicStream writeStream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        QuicStream readStream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);

        runtime.RegisterStreamObserver((ulong)writeStream.Id, notifications.Add);
        runtime.RegisterStreamObserver((ulong)readStream.Id, notifications.Add);

        writeStream.Abort(QuicAbortDirection.Write, 0x11);
        readStream.Abort(QuicAbortDirection.Read, 0x22);

        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.DoesNotContain(
            notifications,
            notification => notification.Kind == QuicStreamNotificationKind.ConnectionTerminated);

        await writeStream.DisposeAsync();
        await readStream.DisposeAsync();
    }
}
