// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S11-2-P4-S1-R01">Application protocols SHOULD define rules for handling streams that are prematurely canceled by either endpoint.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S11-2-P4-S1-R01")]
public sealed class REQ_QUIC_RFC9000_0674
{
    [Fact]
    [Requirement("RFC9000-S11-2-P4-S1-R01")]
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
    [Requirement("RFC9000-S11-2-P4-S1-R01")]
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

    [Fact]
    [Requirement("RFC9000-S11-2-P4-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public async Task AbortDirectionsFuzz_RemainStreamScopedAcrossDirectionsAndApplicationCodes()
    {
        (QuicAbortDirection Direction, long ErrorCode, QuicStreamNotificationKind ExpectedNotification)[] cases =
        [
            (QuicAbortDirection.Write, 0x00, QuicStreamNotificationKind.WriteAborted),
            (QuicAbortDirection.Read, 0x01, QuicStreamNotificationKind.ReadAborted),
            (QuicAbortDirection.Write, 0x11, QuicStreamNotificationKind.WriteAborted),
            (QuicAbortDirection.Read, 0x22, QuicStreamNotificationKind.ReadAborted),
            (QuicAbortDirection.Write, 0x3fff, QuicStreamNotificationKind.WriteAborted),
            (QuicAbortDirection.Read, 0x4000, QuicStreamNotificationKind.ReadAborted),
        ];

        foreach ((QuicAbortDirection direction, long errorCode, QuicStreamNotificationKind expectedNotification) in cases)
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            List<QuicStreamNotification> notifications = [];

            runtime.SetLocalApiEventDispatcher(connectionEvent =>
            {
                _ = runtime.Transition(connectionEvent);
                return true;
            });

            QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
            runtime.RegisterStreamObserver((ulong)stream.Id, notifications.Add);

            stream.Abort(direction, errorCode);

            QuicStreamNotification notification = Assert.Single(notifications);
            Assert.Equal(expectedNotification, notification.Kind);
            QuicException exception = Assert.IsType<QuicException>(notification.Exception);
            Assert.Equal(QuicError.OperationAborted, exception.QuicError);
            Assert.Null(exception.ApplicationErrorCode);
            Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
            Assert.DoesNotContain(
                notifications,
                observed => observed.Kind == QuicStreamNotificationKind.ConnectionTerminated);

            if (direction == QuicAbortDirection.Write)
            {
                Assert.True(stream.CanRead);
                Assert.False(stream.CanWrite);
            }
            else
            {
                Assert.False(stream.CanRead);
                Assert.True(stream.CanWrite);
            }

            await stream.DisposeAsync();
        }
    }
}
