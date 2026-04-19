namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S14P2-0007">If a QUIC endpoint determines that the PMTU between any pair of local and remote IP addresses cannot support the smallest allowed maximum datagram size of 1200 bytes, it MUST immediately cease sending QUIC packets on the affected path except for those in PMTU probes or those containing CONNECTION_CLOSE frames.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S14P2-0007")]
public sealed class REQ_QUIC_RFC9000_S14P2_0007
{
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

        byte[] payload = Enumerable.Range(0, 21).Select(value => (byte)value).ToArray();
        outboundEffects.Clear();

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => stream.WriteAsync(payload, 0, payload.Length));

        Assert.NotNull(exception.Message);
        Assert.Empty(outboundEffects);
        await stream.DisposeAsync();
    }
}
