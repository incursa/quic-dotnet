namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P16-0003")]
public sealed class REQ_QUIC_RFC9000_S19P16_0003
{
    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P16-0003">New connection IDs MAY be delivered to a peer using the NEW_CONNECTION_ID frame (Section 19.15).</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P16-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryHandleApplicationPacketReceived_UsesNewConnectionIdFramesToInstallThePeerConnectionId()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        byte[] firstConnectionId = [0x40, 0x41, 0x42];
        byte[] secondConnectionId = [0x50, 0x51, 0x52];
        byte[] statelessResetToken = CreateStatelessResetToken(0x60);

        Assert.True(ProcessNewConnectionIdFrame(runtime, 0x01, 0x00, firstConnectionId, statelessResetToken, observedAtTicks: 8).StateChanged);
        Assert.True(firstConnectionId.AsSpan().SequenceEqual(runtime.CurrentPeerDestinationConnectionId.Span));
        Assert.Null(runtime.TerminalState);

        Assert.True(ProcessNewConnectionIdFrame(runtime, 0x02, 0x01, secondConnectionId, statelessResetToken, observedAtTicks: 9).StateChanged);
        Assert.True(secondConnectionId.AsSpan().SequenceEqual(runtime.CurrentPeerDestinationConnectionId.Span));
        Assert.Null(runtime.TerminalState);
    }

    private static QuicConnectionTransitionResult ProcessNewConnectionIdFrame(
        QuicConnectionRuntime runtime,
        ulong sequenceNumber,
        ulong retirePriorTo,
        ReadOnlySpan<byte> connectionId,
        ReadOnlySpan<byte> statelessResetToken,
        long observedAtTicks)
    {
        byte[] payload = QuicFrameTestData.BuildNewConnectionIdFrame(new QuicNewConnectionIdFrame(
            sequenceNumber,
            retirePriorTo,
            connectionId,
            statelessResetToken));

        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        byte[] protectedPacket = QuicS17P2P3TestSupport.BuildExpectedOneRttPacket(
            payload,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            keyPhase: false);

        return runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: observedAtTicks,
                runtime.ActivePath!.Value.Identity,
                protectedPacket),
            nowTicks: observedAtTicks);
    }

    private static byte[] CreateStatelessResetToken(byte startValue)
    {
        byte[] token = new byte[QuicStatelessReset.StatelessResetTokenLength];
        for (int index = 0; index < token.Length; index++)
        {
            token[index] = unchecked((byte)(startValue + index));
        }

        return token;
    }
}
