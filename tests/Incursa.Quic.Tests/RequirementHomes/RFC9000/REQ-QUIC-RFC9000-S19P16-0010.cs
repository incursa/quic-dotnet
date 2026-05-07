namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P16-0010")]
public sealed class REQ_QUIC_RFC9000_S19P16_0010
{
    private static readonly byte[] HandshakeDestinationConnectionId =
    [
        0x71, 0x72, 0x73,
    ];

    private static readonly byte[] LocalSourceConnectionId =
    [
        0x81, 0x82, 0x83, 0x84,
    ];

    private static readonly byte[] RetiringConnectionId =
    [
        0x91, 0x92, 0x93, 0x94,
    ];

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void NewConnectionIdFrame_WithNonZeroPeerConnectionId_EmitsRetireConnectionIdFrame()
    {
        using QuicConnectionRuntime runtime = CreateRuntime([0x61, 0x62, 0x63]);

        QuicConnectionTransitionResult result = ProcessPeerNewConnectionIdFrame(
            runtime,
            sequenceNumber: 1UL,
            retirePriorTo: 1UL,
            connectionId: RetiringConnectionId,
            observedAtTicks: 10);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Equal([0UL], QuicConnectionIdLifecycleTestSupport.GetRetiredSequenceNumbers(runtime, result));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void NewConnectionIdFrame_WhenPeerRequestedZeroLengthConnectionId_DoesNotEmitRetireConnectionIdFrame()
    {
        using QuicConnectionRuntime runtime = CreateRuntime(ReadOnlySpan<byte>.Empty);

        Assert.True(runtime.CurrentPeerDestinationConnectionId.IsEmpty);

        QuicConnectionTransitionResult result = ProcessPeerNewConnectionIdFrame(
            runtime,
            sequenceNumber: 1UL,
            retirePriorTo: 1UL,
            connectionId: RetiringConnectionId,
            observedAtTicks: 10);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Empty(QuicConnectionIdLifecycleTestSupport.GetRetiredSequenceNumbers(runtime, result));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void NewConnectionIdFrame_WhenPeerRequestedZeroLengthConnectionIdAndRetirePriorToIsZero_DoesNotEmitRetireConnectionIdFrame()
    {
        using QuicConnectionRuntime runtime = CreateRuntime(ReadOnlySpan<byte>.Empty);

        Assert.True(runtime.CurrentPeerDestinationConnectionId.IsEmpty);

        QuicConnectionTransitionResult result = ProcessPeerNewConnectionIdFrame(
            runtime,
            sequenceNumber: 1UL,
            retirePriorTo: 0UL,
            connectionId: RetiringConnectionId,
            observedAtTicks: 10);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Empty(QuicConnectionIdLifecycleTestSupport.GetRetiredSequenceNumbers(runtime, result));
    }

    private static QuicConnectionRuntime CreateRuntime(ReadOnlySpan<byte> peerInitialSourceConnectionId)
    {
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(
            new("203.0.113.210", RemotePort: 443));

        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(HandshakeDestinationConnectionId));
        Assert.True(runtime.TrySetHandshakeSourceConnectionId(LocalSourceConnectionId));

        QuicTransportParameters peerTransportParameters = QuicPostHandshakeTicketTestSupport.CreatePeerTransportParameters();
        peerTransportParameters.InitialSourceConnectionId = peerInitialSourceConnectionId.ToArray();
        peerTransportParameters.ActiveConnectionIdLimit = 3UL;

        QuicPathMigrationRecoveryTestSupport.CommitPeerTransportParametersAndSeedOneRttPacketProtectionMaterial(
            runtime,
            peerTransportParameters);

        return runtime;
    }

    private static QuicConnectionTransitionResult ProcessPeerNewConnectionIdFrame(
        QuicConnectionRuntime runtime,
        ulong sequenceNumber,
        ulong retirePriorTo,
        ReadOnlySpan<byte> connectionId,
        long observedAtTicks)
    {
        byte[] payload = QuicFrameTestData.BuildNewConnectionIdFrame(new QuicNewConnectionIdFrame(
            sequenceNumber,
            retirePriorTo,
            connectionId,
            QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x60)));

        return QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            runtime.ActivePath!.Value.Identity,
            runtime.CurrentHandshakeSourceConnectionId.Span,
            payload,
            observedAtTicks);
    }
}
