// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S8-2-1-P5-S1-R01")]
public sealed class REQ_QUIC_RFC9000_S8P2P1_0005
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="RFC9000-S8-2-1-P5-S1-R01">An endpoint MUST expand datagrams that contain a PATH_CHALLENGE frame to at least the smallest allowed maximum datagram size of 1200 bytes, unless the anti-amplification limit for the path does not permit sending a datagram of this size.</workbench-requirement>
    ///   <workbench-requirement requirementId="RFC9000-S8-2-2-P3-S1-R01">An endpoint MUST expand datagrams that contain a PATH_RESPONSE frame to at least the smallest allowed maximum datagram size of 1200 bytes.</workbench-requirement>
    ///   <workbench-requirement requirementId="RFC9000-S8-2-2-P3-S3-R01">However, an endpoint MUST NOT expand the datagram containing the PATH_RESPONSE if the resulting data exceeds the anti-amplification limit.</workbench-requirement>
    ///   <workbench-requirement requirementId="RFC9000-S9-3-1-P2-S2-R01">Until a peer&apos;s address is deemed valid, an endpoint MUST limit the amount of data it sends to that address.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9000-S8-2-1-P5-S1-R01")]
    [Requirement("RFC9000-S8-2-2-P3-S1-R01")]
    [Requirement("RFC9000-S8-2-2-P3-S3-R01")]
    [Requirement("RFC9000-S9-3-1-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatPathValidationDatagramPadding_WritesRepeatedPaddingFramesWhenAmplificationBudgetAllows()
    {
        QuicAntiAmplificationBudget budget = new();
        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(100, uniquelyAttributedToSingleConnection: true));

        Span<byte> destination = stackalloc byte[13];
        Assert.True(QuicPathValidation.TryFormatPathValidationDatagramPadding(
            1187,
            budget,
            destination,
            out int bytesWritten));

        Assert.Equal(13, bytesWritten);
        Assert.All(destination[..bytesWritten].ToArray(), static value => Assert.Equal(0, value));

        for (int index = 0; index < bytesWritten; index++)
        {
            Assert.True(QuicFrameCodec.TryParsePaddingFrame(destination[index..bytesWritten], out int bytesConsumed));
            Assert.Equal(1, bytesConsumed);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    [Requirement("RFC9000-S8-2-1-P5-S1-R01")]
    [Requirement("RFC9000-S8-2-2-P3-S1-R01")]
    [Requirement("RFC9000-S8-2-2-P3-S3-R01")]
    [Requirement("RFC9000-S9-3-1-P2-S2-R01")]
    public void Fuzz_PathValidationPaddingHonorsMinimumDatagramSizeAndAntiAmplificationBudget()
    {
        PathValidationPaddingFuzzCase[] scenarios =
        [
            new(CurrentPayloadLength: -1, ReceivedPayloadBytes: 100, SentPayloadBytes: 0, AddressValidated: false, DestinationLength: 1200),
            new(CurrentPayloadLength: 0, ReceivedPayloadBytes: 400, SentPayloadBytes: 0, AddressValidated: false, DestinationLength: 1200),
            new(CurrentPayloadLength: 1, ReceivedPayloadBytes: 400, SentPayloadBytes: 0, AddressValidated: false, DestinationLength: 1199),
            new(CurrentPayloadLength: 1187, ReceivedPayloadBytes: 4, SentPayloadBytes: 0, AddressValidated: false, DestinationLength: 13),
            new(CurrentPayloadLength: 1187, ReceivedPayloadBytes: 5, SentPayloadBytes: 0, AddressValidated: false, DestinationLength: 13),
            new(CurrentPayloadLength: 1198, ReceivedPayloadBytes: 100, SentPayloadBytes: 0, AddressValidated: false, DestinationLength: 1),
            new(CurrentPayloadLength: 1198, ReceivedPayloadBytes: 0, SentPayloadBytes: 0, AddressValidated: true, DestinationLength: 2),
            new(CurrentPayloadLength: 1199, ReceivedPayloadBytes: 0, SentPayloadBytes: 0, AddressValidated: false, DestinationLength: 1),
            new(CurrentPayloadLength: 1199, ReceivedPayloadBytes: 1, SentPayloadBytes: 0, AddressValidated: false, DestinationLength: 1),
            new(CurrentPayloadLength: 1200, ReceivedPayloadBytes: 0, SentPayloadBytes: 0, AddressValidated: false, DestinationLength: 0),
            new(CurrentPayloadLength: 1350, ReceivedPayloadBytes: 0, SentPayloadBytes: 0, AddressValidated: false, DestinationLength: 0),
        ];

        foreach (PathValidationPaddingFuzzCase scenario in scenarios)
        {
            QuicAntiAmplificationBudget budget = CreateBudget(scenario);
            byte[] destination = new byte[scenario.DestinationLength];

            int expectedPaddingLength = GetExpectedPaddingLength(scenario.CurrentPayloadLength);
            bool hasValidPayloadLength = scenario.CurrentPayloadLength >= 0;
            bool destinationCanHoldPadding = destination.Length >= expectedPaddingLength;
            bool budgetAllowsPadding = scenario.AddressValidated
                || (hasValidPayloadLength && budget.CanSend(expectedPaddingLength));
            bool expectedSuccess = hasValidPayloadLength
                && (expectedPaddingLength == 0 || (budgetAllowsPadding && destinationCanHoldPadding));

            bool formatted = QuicPathValidation.TryFormatPathValidationDatagramPadding(
                scenario.CurrentPayloadLength,
                budget,
                destination,
                out int bytesWritten);

            Assert.Equal(expectedSuccess, formatted);
            Assert.Equal(expectedSuccess ? expectedPaddingLength : 0, bytesWritten);

            if (formatted && bytesWritten > 0)
            {
                Assert.All(destination[..bytesWritten].ToArray(), static value => Assert.Equal(0, value));
                for (int index = 0; index < bytesWritten; index++)
                {
                    Assert.True(QuicFrameCodec.TryParsePaddingFrame(destination.AsSpan(index, bytesWritten - index), out int bytesConsumed));
                    Assert.Equal(1, bytesConsumed);
                }
            }
        }
    }

    [Fact]
    [Requirement("RFC9000-S8-2-1-P5-S1-R01")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RuntimePathChallengeDatagramIsExactlyTheRfcMinimumWhenBudgetAllows()
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        QuicConnectionPathIdentity candidatePath = new("203.0.113.127", RemotePort: 443);

        QuicConnectionTransitionResult result =
            QuicS8P2PathValidationTestSupport.StartCandidatePath(runtime, candidatePath, observedAtTicks: 20);

        QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(
            result,
            candidatePath,
            expectMinimumSize: true,
            runtime: runtime);
    }

    private static int GetExpectedPaddingLength(int currentPayloadLength)
    {
        if (currentPayloadLength < 0
            || currentPayloadLength >= QuicVersionNegotiation.Version1MinimumDatagramPayloadSize)
        {
            return 0;
        }

        return QuicVersionNegotiation.Version1MinimumDatagramPayloadSize - currentPayloadLength;
    }

    private static QuicAntiAmplificationBudget CreateBudget(PathValidationPaddingFuzzCase scenario)
    {
        QuicAntiAmplificationBudget budget = new();
        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(
            scenario.ReceivedPayloadBytes,
            uniquelyAttributedToSingleConnection: true));

        if (scenario.AddressValidated)
        {
            budget.MarkAddressValidated();
        }

        if (scenario.SentPayloadBytes > 0)
        {
            Assert.True(budget.TryConsumeSendBudget(scenario.SentPayloadBytes));
        }

        return budget;
    }

    private readonly record struct PathValidationPaddingFuzzCase(
        int CurrentPayloadLength,
        int ReceivedPayloadBytes,
        int SentPayloadBytes,
        bool AddressValidated,
        int DestinationLength);
}
