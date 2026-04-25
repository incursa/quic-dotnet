namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P18-0003">If the content of a PATH_RESPONSE frame does not match the content of a PATH_CHALLENGE frame previously sent by the endpoint, the endpoint MAY generate a connection error of type PROTOCOL_VIOLATION.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S19P18-0003")]
public sealed class REQ_QUIC_RFC9000_S19P18_0003
{
    private static readonly byte[] PacketConnectionId =
    [
        0x0A, 0x0B, 0x0C,
    ];

    private static readonly QuicConnectionPathIdentity ValidationPath =
        new("203.0.113.112", RemotePort: 443);

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P18-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void MatchingPathResponseCompletesValidationWithoutClosingTheConnection()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                ValidationPath,
                datagram),
            nowTicks: 20).StateChanged);

        Assert.True(runtime.CandidatePaths.TryGetValue(ValidationPath, out QuicConnectionCandidatePathRecord candidatePath));
        byte[] challengeData = candidatePath.Validation.ChallengePayload.ToArray();
        byte[] responsePacket = BuildProtectedPathResponsePacket(runtime, challengeData);

        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            responsePacket,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool observedKeyPhase));
        Assert.Equal(runtime.TlsState.CurrentOneRttKeyPhase == 1, observedKeyPhase);

        Assert.True(QuicFrameCodec.TryParsePathResponseFrame(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            out QuicPathResponseFrame parsedResponse,
            out int bytesConsumed));
        Assert.True(payloadLength >= bytesConsumed);
        Assert.True(openedPacket.AsSpan(payloadOffset + bytesConsumed, payloadLength - bytesConsumed)
            .SequenceEqual(new byte[payloadLength - bytesConsumed]));
        Assert.True(challengeData.AsSpan().SequenceEqual(parsedResponse.Data));

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 21,
                ValidationPath,
                responsePacket),
            nowTicks: 21);

        Assert.True(result.StateChanged);
        Assert.DoesNotContain(result.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && QuicFrameCodec.TryParsePathResponseFrame(send.Datagram.Span, out _, out _));
        Assert.Contains(result.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == ValidationPath);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Null(runtime.TerminalState);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(ValidationPath, runtime.ActivePath!.Value.Identity);
        Assert.False(runtime.CandidatePaths.ContainsKey(ValidationPath));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P18-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [Trait("Category", "Edge")]
    public void MismatchedPathResponseClosesTheConnectionWithProtocolViolation()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                ValidationPath,
                datagram),
            nowTicks: 20).StateChanged);

        Assert.True(runtime.CandidatePaths.TryGetValue(ValidationPath, out QuicConnectionCandidatePathRecord candidatePath));
        byte[] challengeData = candidatePath.Validation.ChallengePayload.ToArray();
        byte[] mismatchedResponseData = challengeData.ToArray();
        mismatchedResponseData[0] ^= 0xFF;
        byte[] responsePacket = BuildProtectedPathResponsePacket(runtime, mismatchedResponseData);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 21,
                ValidationPath,
                responsePacket),
            nowTicks: 21);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.CloseOnly, runtime.SendingMode);
        Assert.NotNull(runtime.TerminalState);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState!.Value.Origin);
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, runtime.TerminalState.Value.Close.TransportErrorCode);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
        Assert.DoesNotContain(result.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == ValidationPath);
        Assert.True(runtime.CandidatePaths.TryGetValue(ValidationPath, out QuicConnectionCandidatePathRecord failedCandidatePath));
        Assert.False(failedCandidatePath.Validation.IsValidated);
        Assert.False(failedCandidatePath.Validation.IsAbandoned);
    }

    private static byte[] BuildProtectedPathResponsePacket(QuicConnectionRuntime runtime, ReadOnlySpan<byte> responseData)
    {
        Span<byte> responseFrameBuffer = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatPathResponseFrame(
            new QuicPathResponseFrame(responseData),
            responseFrameBuffer,
            out int responseFrameBytesWritten));

        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            responseFrameBuffer[..responseFrameBytesWritten],
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            runtime.TlsState.CurrentOneRttKeyPhase == 1,
            out byte[] protectedPacket));

        return protectedPacket;
    }
}
