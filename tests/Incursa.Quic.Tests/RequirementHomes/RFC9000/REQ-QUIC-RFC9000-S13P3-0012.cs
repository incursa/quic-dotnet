namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0012">The content of a RESET_STREAM frame MUST NOT change when it is sent again.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0012")]
public sealed class REQ_QUIC_RFC9000_S13P3_0012
{
    private static readonly byte[] PacketConnectionId = [0x0A, 0x0B, 0x0C];

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0012")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ResetStreamContentIsPreservedWhenTheSameFrameIsReprotected()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        List<QuicConnectionEffect> outboundEffects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        await runtime.AbortStreamWritesAsync(0, 0x99);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());

        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> resetPacket = Assert.Single(
            runtime.SendRuntime.SentPackets,
            entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
                && entry.Value.PacketBytes.Span.SequenceEqual(sendEffect.Datagram.Span));

        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            sendEffect.Datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        Assert.True(QuicFrameCodec.TryParseResetStreamFrame(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            out QuicResetStreamFrame parsedResetFrame,
            out int parsedBytesConsumed));

        Span<byte> reformattedFrame = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatResetStreamFrame(
            parsedResetFrame,
            reformattedFrame,
            out int reformattedBytesWritten));
        Assert.True(reformattedFrame[..reformattedBytesWritten].SequenceEqual(
            openedPacket.AsSpan(payloadOffset, parsedBytesConsumed)));

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            resetPacket.Key.PacketNumberSpace,
            resetPacket.Key.PacketNumber,
            handshakeConfirmed: true));
        Assert.True(runtime.SendRuntime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission));
        Assert.True(retransmission.PacketBytes.Span.SequenceEqual(sendEffect.Datagram.Span));

        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            retransmission.PacketBytes.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] retransmissionOpenedPacket,
            out int retransmissionPayloadOffset,
            out int retransmissionPayloadLength));

        Assert.True(QuicFrameCodec.TryParseResetStreamFrame(
            retransmissionOpenedPacket.AsSpan(retransmissionPayloadOffset, retransmissionPayloadLength),
            out QuicResetStreamFrame retransmissionFrame,
            out _));
        Assert.Equal(parsedResetFrame.StreamId, retransmissionFrame.StreamId);
        Assert.Equal(parsedResetFrame.ApplicationProtocolErrorCode, retransmissionFrame.ApplicationProtocolErrorCode);
        Assert.Equal(parsedResetFrame.FinalSize, retransmissionFrame.FinalSize);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0012")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ResetStreamContentChangesWhenTheUnderlyingFrameFieldsChange()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicTlsPacketProtectionMaterial material = runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;

        bool keyPhase = runtime.TlsState.CurrentOneRttKeyPhase == 1;

        byte[] originalPacket = BuildProtectedResetPacket(
            new QuicResetStreamFrame(streamId: 0, applicationProtocolErrorCode: 0x99, finalSize: 0),
            material,
            keyPhase);

        byte[] changedPacket = BuildProtectedResetPacket(
            new QuicResetStreamFrame(streamId: 0, applicationProtocolErrorCode: 0x9A, finalSize: 0),
            material,
            keyPhase);

        Assert.False(originalPacket.AsSpan().SequenceEqual(changedPacket));
    }

    private static byte[] BuildProtectedResetPacket(
        QuicResetStreamFrame frame,
        QuicTlsPacketProtectionMaterial material,
        bool keyPhase)
    {
        Span<byte> frameBuffer = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatResetStreamFrame(frame, frameBuffer, out int frameBytesWritten));

        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            frameBuffer[..frameBytesWritten],
            material,
            keyPhase,
            out byte[] protectedPacket));

        return protectedPacket;
    }
}
