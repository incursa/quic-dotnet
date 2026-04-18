namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0028">Responses to path validation using PATH_RESPONSE frames MUST be sent just once.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P17-0006">The recipient of this frame MUST generate a PATH_RESPONSE frame (Section 19.18) containing the same Data value.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0028")]
[Requirement("REQ-QUIC-RFC9000-S19P17-0006")]
public sealed class REQ_QUIC_RFC9000_S13P3_0028
{
    private static readonly byte[] PacketConnectionId =
    [
        0x0A, 0x0B, 0x0C,
    ];

    private static readonly QuicConnectionPathIdentity BootstrapPath =
        new("203.0.113.10", RemotePort: 443);

    private static readonly QuicConnectionPathIdentity ChallengePath =
        new("203.0.113.11", RemotePort: 443);

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0028")]
    [Requirement("REQ-QUIC-RFC9000-S19P17-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ReceivedPathChallengeOnACandidatePathEmitsExactlyOnePathResponseDatagram()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();

        byte[] paddingPacket = BuildProtectedPaddingPacket(runtime, payloadLength: 1024 * 1024);
        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                ChallengePath,
                paddingPacket),
            nowTicks: 0);

        Assert.True(runtime.CandidatePaths.TryGetValue(ChallengePath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.True(candidatePath.AmplificationState.RemainingSendBudget >= 9, candidatePath.AmplificationState.RemainingSendBudget.ToString());

        int sentPacketCountBefore = runtime.SendRuntime.SentPackets.Count;
        int pendingRetransmissionsBefore = runtime.SendRuntime.PendingRetransmissionCount;

        byte[] protectedPacket = BuildProtectedPathChallengePacket(runtime, out byte[] challengeData);
        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool observedKeyPhase));
        Assert.Equal(runtime.TlsState.CurrentOneRttKeyPhase == 1, observedKeyPhase);
        Assert.True(QuicFrameCodec.TryParsePathChallengeFrame(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            out QuicPathChallengeFrame parsedChallenge,
            out int challengeBytesConsumed));
        Assert.Equal(QuicPathValidation.PathChallengeDataLength + 1, challengeBytesConsumed);
        Assert.True(openedPacket.AsSpan(payloadOffset + challengeBytesConsumed, payloadLength - challengeBytesConsumed)
            .SequenceEqual(new byte[payloadLength - challengeBytesConsumed]));
        Assert.True(challengeData.AsSpan().SequenceEqual(parsedChallenge.Data));

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                ChallengePath,
                protectedPacket),
            nowTicks: 1);

        Assert.True(result.StateChanged);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(result.Effects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.Equal(ChallengePath, sendEffect.PathIdentity);
        Assert.Equal(sentPacketCountBefore, runtime.SendRuntime.SentPackets.Count);
        Assert.Equal(pendingRetransmissionsBefore, runtime.SendRuntime.PendingRetransmissionCount);

        Assert.True(QuicFrameCodec.TryParsePathResponseFrame(
            sendEffect.Datagram.Span,
            out QuicPathResponseFrame parsedResponse,
            out int bytesConsumed));
        Assert.Equal(sendEffect.Datagram.Length, bytesConsumed);
        Assert.True(challengeData.AsSpan().SequenceEqual(parsedResponse.Data));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0028")]
    [Requirement("REQ-QUIC-RFC9000-S19P17-0006")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [Trait("Category", "Edge")]
    public void TruncatedProtectedPathChallengePacketDoesNotEmitAPathResponse()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();

        int sentPacketCountBefore = runtime.SendRuntime.SentPackets.Count;
        int pendingRetransmissionsBefore = runtime.SendRuntime.PendingRetransmissionCount;

        byte[] protectedPacket = BuildProtectedPathChallengePacket(runtime, out _);
        byte[] truncatedPacket = protectedPacket.AsSpan(0, protectedPacket.Length - 1).ToArray();

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                BootstrapPath,
                truncatedPacket),
            nowTicks: 1);

        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
        Assert.Equal(sentPacketCountBefore, runtime.SendRuntime.SentPackets.Count);
        Assert.Equal(pendingRetransmissionsBefore, runtime.SendRuntime.PendingRetransmissionCount);
    }

    private static byte[] BuildProtectedPathChallengePacket(
        QuicConnectionRuntime runtime,
        out byte[] challengeData)
    {
        challengeData = new byte[QuicPathValidation.PathChallengeDataLength];
        Assert.True(QuicPathValidation.TryGeneratePathChallengeData(challengeData, out int challengeBytesWritten));

        Span<byte> challengeFrameBuffer = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatPathChallengeFrame(
            new QuicPathChallengeFrame(challengeData.AsSpan(0, challengeBytesWritten)),
            challengeFrameBuffer,
            out int challengeFrameBytesWritten));

        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            challengeFrameBuffer[..challengeFrameBytesWritten],
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            runtime.TlsState.CurrentOneRttKeyPhase == 1,
            out byte[] protectedPacket));

        return protectedPacket;
    }

    private static byte[] BuildProtectedPaddingPacket(QuicConnectionRuntime runtime, int payloadLength)
    {
        byte[] payload = new byte[payloadLength];
        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            runtime.TlsState.CurrentOneRttKeyPhase == 1,
            out byte[] protectedPacket));

        return protectedPacket;
    }
}
