namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S14P2-0007">If a QUIC endpoint determines that the PMTU between any pair of local and remote IP addresses cannot support the smallest allowed maximum datagram size of 1200 bytes, it MUST immediately cease sending QUIC packets on the affected path except for those in PMTU probes or those containing CONNECTION_CLOSE frames.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S14P2-0007")]
public sealed class REQ_QUIC_RFC9000_S14P2_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task WriteAsync_SucceedsWhenTheActivePathSupportsTheRFCMinimum()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        Assert.True(runtime.ActivePath.HasValue);

        ulong minimumAllowedMaximumDatagramSizeBytes = QuicConnectionPathMaximumDatagramSizeState.MinimumAllowedMaximumDatagramSizeBytes;
        Assert.True(runtime.TrySetActivePathMaximumDatagramSize(minimumAllowedMaximumDatagramSizeBytes));
        Assert.Equal(minimumAllowedMaximumDatagramSizeBytes, runtime.ActivePath!.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
        Assert.True(runtime.ActivePath.Value.MaximumDatagramSizeState.CanSendOrdinaryPackets);
        Assert.Equal(minimumAllowedMaximumDatagramSizeBytes, runtime.SendRuntime.FlowController.CongestionControlState.MaxDatagramSizeBytes);

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        outboundEffects.Clear();

        byte[] payload = Enumerable.Range(0, 64).Select(value => (byte)value).ToArray();

        await stream.WriteAsync(payload, 0, payload.Length);

        Assert.Contains(outboundEffects, effect => effect is QuicConnectionSendDatagramEffect);
        await stream.DisposeAsync();
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task WriteAsync_FailsWhenTheActivePathDropsBelowTheRFCMinimum()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        Assert.True(runtime.ActivePath.HasValue);

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        outboundEffects.Clear();

        ulong reducedMaximumDatagramSizeBytes = QuicConnectionPathMaximumDatagramSizeState.MinimumAllowedMaximumDatagramSizeBytes - 1;
        Assert.True(runtime.TrySetActivePathMaximumDatagramSize(reducedMaximumDatagramSizeBytes));
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(reducedMaximumDatagramSizeBytes, runtime.ActivePath!.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
        Assert.False(runtime.ActivePath.Value.MaximumDatagramSizeState.CanSendOrdinaryPackets);
        Assert.Equal(reducedMaximumDatagramSizeBytes, runtime.SendRuntime.FlowController.CongestionControlState.MaxDatagramSizeBytes);

        byte[] payload = Enumerable.Range(0, 64).Select(value => (byte)value).ToArray();
        outboundEffects.Clear();

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => stream.WriteAsync(payload, 0, payload.Length));

        Assert.NotNull(exception.Message);
        Assert.Empty(outboundEffects);
        await stream.DisposeAsync();
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task WriteAsync_DoesNotAdvanceTheStreamOffsetWhenOrdinaryPacketsAreDisabled()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        byte[] payload = Enumerable.Range(0, 64).Select(value => (byte)value).ToArray();
        outboundEffects.Clear();

        ulong reducedMaximumDatagramSizeBytes = QuicConnectionPathMaximumDatagramSizeState.MinimumAllowedMaximumDatagramSizeBytes - 1;
        Assert.True(runtime.TrySetActivePathMaximumDatagramSize(reducedMaximumDatagramSizeBytes));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => stream.WriteAsync(payload, 0, payload.Length));
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot((ulong)stream.Id, out QuicConnectionStreamSnapshot failedSnapshot));
        Assert.Equal(0UL, failedSnapshot.UniqueBytesSent);
        Assert.DoesNotContain(outboundEffects, effect => effect is QuicConnectionSendDatagramEffect);

        ulong minimumAllowedMaximumDatagramSizeBytes = QuicConnectionPathMaximumDatagramSizeState.MinimumAllowedMaximumDatagramSizeBytes;
        Assert.True(runtime.TrySetActivePathMaximumDatagramSize(minimumAllowedMaximumDatagramSizeBytes));
        outboundEffects.Clear();

        await stream.WriteAsync(payload, 0, payload.Length);

        Assert.True(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot((ulong)stream.Id, out QuicConnectionStreamSnapshot successSnapshot));
        Assert.Equal((ulong)payload.Length, successSnapshot.UniqueBytesSent);
        Assert.Contains(outboundEffects, effect => effect is QuicConnectionSendDatagramEffect);
        await stream.DisposeAsync();
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void LocalCloseRequested_StillEmitsConnectionCloseWhenTheActivePathDropsBelowTheRFCMinimum()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);
        QuicConnectionPathIdentity path = runtime.ActivePath.Value.Identity;

        ulong reducedMaximumDatagramSizeBytes = QuicConnectionPathMaximumDatagramSizeState.MinimumAllowedMaximumDatagramSizeBytes - 1;
        Assert.True(runtime.TrySetActivePathMaximumDatagramSize(reducedMaximumDatagramSizeBytes));
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(reducedMaximumDatagramSizeBytes, runtime.ActivePath!.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
        Assert.False(runtime.ActivePath.Value.MaximumDatagramSizeState.CanSendOrdinaryPackets);

        QuicConnectionCloseMetadata closeMetadata = new(
            TransportErrorCode: QuicTransportErrorCode.ProtocolViolation,
            ApplicationErrorCode: null,
            TriggeringFrameType: 0x1c,
            ReasonPhrase: null);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionLocalCloseRequestedEvent(
                ObservedAtTicks: 1,
                closeMetadata),
            nowTicks: 1);

        QuicConnectionCloseFrame expectedClose = new(
            QuicTransportErrorCode.ProtocolViolation,
            triggeringFrameType: 0x1c,
            []);
        byte[] expectedDatagram = QuicFrameTestData.BuildConnectionCloseFrame(expectedClose);
        QuicConnectionSendDatagramEffect send = Assert.IsType<QuicConnectionSendDatagramEffect>(
            Assert.Single(result.Effects, effect => effect is QuicConnectionSendDatagramEffect));

        Assert.Equal(path, send.PathIdentity);
        Assert.True(expectedDatagram.AsSpan().SequenceEqual(send.Datagram.Span));
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.CloseOnly, runtime.SendingMode);
        Assert.False(runtime.CanSendOrdinaryPackets);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState?.Origin);
        Assert.Equal(closeMetadata, runtime.TerminalState?.Close);
        Assert.NotNull(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.CloseLifetime));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TrySetActivePathMaximumDatagramSize_LeavesOrdinaryPacketsEnabledAtTheRFCMinimum()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();

        ulong minimumAllowedMaximumDatagramSizeBytes = QuicConnectionPathMaximumDatagramSizeState.MinimumAllowedMaximumDatagramSizeBytes;

        Assert.True(runtime.TrySetActivePathMaximumDatagramSize(minimumAllowedMaximumDatagramSizeBytes));
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(minimumAllowedMaximumDatagramSizeBytes, runtime.ActivePath!.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
        Assert.True(runtime.ActivePath.Value.MaximumDatagramSizeState.CanSendOrdinaryPackets);
        Assert.Equal(minimumAllowedMaximumDatagramSizeBytes, runtime.SendRuntime.FlowController.CongestionControlState.MaxDatagramSizeBytes);
    }
}
