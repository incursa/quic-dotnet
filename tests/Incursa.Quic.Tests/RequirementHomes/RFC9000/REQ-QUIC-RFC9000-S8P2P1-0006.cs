namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P2P1-0006">To ensure that the path MTU is large enough, the endpoint MUST perform a second path validation by sending a PATH_CHALLENGE frame in a datagram of at least 1200 bytes.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S8P2P1-0006")]
public sealed class REQ_QUIC_RFC9000_S8P2P1_0006
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
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryFormatPathValidationDatagramPadding_RejectsExpansionWhenAmplificationBudgetIsTooSmall()
    {
        QuicAntiAmplificationBudget budget = new();

        Assert.False(QuicPathValidation.TryFormatPathValidationDatagramPadding(
            currentPayloadLength: 9,
            budget,
            new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize - 9],
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
