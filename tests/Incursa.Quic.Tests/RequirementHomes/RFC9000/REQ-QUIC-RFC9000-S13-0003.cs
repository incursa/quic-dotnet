namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13-0003">An implementation MAY use knowledge about application sending behavior or heuristics to determine whether and for how long to wait.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13-0003")]
public sealed class REQ_QUIC_RFC9000_S13_0003
{
    private static readonly byte[] PacketConnectionId =
    [
        0x0A, 0x0B, 0x0C,
    ];

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task WriteAsync_UsesTheImmediateSendPathForLargerPayloads()
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
        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 9,
                runtime.ActivePath.Value.Identity,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 9);
        outboundEffects.Clear();

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        outboundEffects.Clear();
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(new QuicConnectionPathIdentity("203.0.113.11", RemotePort: 443), runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.ActivePath.Value.AmplificationState.IsAddressValidated);

        byte[] payload = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();
        await stream.WriteAsync(payload, 0, payload.Length);

        bool sawExpectedStreamFrame = false;
        foreach (QuicConnectionSendDatagramEffect sendEffect in outboundEffects.OfType<QuicConnectionSendDatagramEffect>())
        {
            QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
            if (!coordinator.TryOpenProtectedApplicationDataPacket(
                sendEffect.Datagram.Span,
                runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength,
                out bool keyPhase))
            {
                continue;
            }

            Assert.False(keyPhase);
            ReadOnlySpan<byte> packetPayload = openedPacket.AsSpan(payloadOffset, payloadLength);
            if (TryFindStreamFrame(packetPayload, out QuicStreamFrame frame)
                && frame.StreamId.Value == (ulong)stream.Id
                && frame.Offset == 0UL
                && frame.StreamData.SequenceEqual(payload))
            {
                sawExpectedStreamFrame = true;
                break;
            }
        }

        Assert.True(sawExpectedStreamFrame);
        Assert.DoesNotContain(outboundEffects, effect =>
            effect is QuicConnectionArmTimerEffect arm
            && arm.TimerKind == QuicConnectionTimerKind.ApplicationSendDelay);
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay));
    }

    private static bool TryFindStreamFrame(ReadOnlySpan<byte> payload, out QuicStreamFrame frame)
    {
        frame = default;

        int offset = 0;
        while (offset < payload.Length)
        {
            ReadOnlySpan<byte> remaining = payload[offset..];
            if (QuicFrameCodec.TryParsePaddingFrame(remaining, out int paddingBytesConsumed))
            {
                offset += paddingBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseAckFrame(remaining, out _, out int ackBytesConsumed))
            {
                offset += ackBytesConsumed;
                continue;
            }

            return QuicStreamParser.TryParseStreamFrame(remaining, out frame);
        }

        return false;
    }
}
