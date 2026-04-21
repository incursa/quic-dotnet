namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S14P2-0006">All QUIC packets that are not sent in a PMTU probe SHOULD be sized to fit within the maximum datagram size.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S14P2-0006")]
public sealed class REQ_QUIC_RFC9000_S14P2_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatPathValidationDatagramPadding_ExpandsAPathChallengeDatagramToTheRfcMinimum()
    {
        QuicAntiAmplificationBudget budget = new();
        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(400, uniquelyAttributedToSingleConnection: true));

        Span<byte> challengeData = stackalloc byte[QuicPathValidation.PathChallengeDataLength];
        Assert.True(QuicPathValidation.TryGeneratePathChallengeData(challengeData, out int challengeBytesWritten));

        Span<byte> challengeFrame = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatPathChallengeFrame(
            new QuicPathChallengeFrame(challengeData[..challengeBytesWritten]),
            challengeFrame,
            out int frameBytesWritten));

        byte[] padding = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize - frameBytesWritten];
        Assert.True(QuicPathValidation.TryFormatPathValidationDatagramPadding(
            frameBytesWritten,
            budget,
            padding,
            out int paddingBytesWritten));

        Assert.Equal(QuicVersionNegotiation.Version1MinimumDatagramPayloadSize, frameBytesWritten + paddingBytesWritten);
        Assert.All(padding, static value => Assert.Equal(0, value));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task WriteAsync_ProducesOrdinaryPacketsThatFitWithinTheActivePathMaximumDatagramSize()
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

        ulong maximumDatagramSizeBytes = 1_350;
        Assert.True(runtime.TrySetActivePathMaximumDatagramSize(maximumDatagramSizeBytes));
        Assert.Equal(maximumDatagramSizeBytes, runtime.ActivePath!.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
        Assert.True(runtime.ActivePath.Value.MaximumDatagramSizeState.CanSendOrdinaryPackets);

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        outboundEffects.Clear();

        byte[] payload = new byte[64];

        await stream.WriteAsync(payload, 0, payload.Length);

        IReadOnlyList<QuicConnectionSendDatagramEffect> sendDatagrams = outboundEffects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();

        Assert.NotEmpty(sendDatagrams);
        Assert.All(sendDatagrams, sendDatagram =>
        {
            Assert.Equal(runtime.ActivePath!.Value.Identity, sendDatagram.PathIdentity);
            Assert.True((ulong)sendDatagram.Datagram.Length <= maximumDatagramSizeBytes);
        });

        await stream.DisposeAsync();
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryFormatPathValidationDatagramPadding_RejectsNegativePayloadLengths()
    {
        QuicAntiAmplificationBudget budget = new();

        Assert.False(QuicPathValidation.TryFormatPathValidationDatagramPadding(
            -1,
            budget,
            stackalloc byte[1],
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryFormatPathValidationDatagramPadding_AllowsAnAlreadyExpandedDatagram()
    {
        QuicAntiAmplificationBudget budget = new();

        Assert.True(QuicPathValidation.TryFormatPathValidationDatagramPadding(
            QuicVersionNegotiation.Version1MinimumDatagramPayloadSize,
            budget,
            Array.Empty<byte>(),
            out int bytesWritten));

        Assert.Equal(0, bytesWritten);
    }
}
