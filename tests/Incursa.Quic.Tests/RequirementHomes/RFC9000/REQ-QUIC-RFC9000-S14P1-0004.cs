// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S14P1-0004">Sending UDP datagrams of this size ensures that the network path supports a reasonable Path Maximum Transmission Unit (PMTU), in both directions.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S14P1-0004")]
public sealed class REQ_QUIC_RFC9000_S14P1_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Requirement("REQ-QUIC-RFC9000-0857")]
    [Trait("Category", "Positive")]
    public void TryFormatPathValidationDatagramPadding_ExpandsTheProbePayloadWhenBudgetPermits()
    {
        QuicAntiAmplificationBudget budget = new();
        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(1200, uniquelyAttributedToSingleConnection: true));

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
    [CoverageType(RequirementCoverageType.Negative)]
    [Requirement("REQ-QUIC-RFC9000-0857")]
    [Trait("Category", "Negative")]
    public void TryFormatPathValidationDatagramPadding_RejectsExpansionWhenAmplificationBudgetIsTooSmall()
    {
        QuicAntiAmplificationBudget budget = new();
        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(4, uniquelyAttributedToSingleConnection: true));

        Assert.False(QuicPathValidation.TryFormatPathValidationDatagramPadding(
            1187,
            budget,
            stackalloc byte[13],
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Requirement("REQ-QUIC-RFC9000-0857")]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PathValidationDatagramPaddingHonorsDatagramSizeAndBudgetBoundaries()
    {
        PathValidationDatagramSizingCase[] scenarios =
        [
            new(CurrentPayloadLength: -1, ReceivedPayloadBytes: 400, AddressValidated: false, DestinationLength: 1200),
            new(CurrentPayloadLength: 0, ReceivedPayloadBytes: 400, AddressValidated: false, DestinationLength: 1200),
            new(CurrentPayloadLength: 1, ReceivedPayloadBytes: 400, AddressValidated: false, DestinationLength: 1199),
            new(CurrentPayloadLength: 63, ReceivedPayloadBytes: 379, AddressValidated: false, DestinationLength: 1137),
            new(CurrentPayloadLength: 1187, ReceivedPayloadBytes: 4, AddressValidated: false, DestinationLength: 13),
            new(CurrentPayloadLength: 1187, ReceivedPayloadBytes: 5, AddressValidated: false, DestinationLength: 13),
            new(CurrentPayloadLength: 1198, ReceivedPayloadBytes: 0, AddressValidated: false, DestinationLength: 2),
            new(CurrentPayloadLength: 1198, ReceivedPayloadBytes: 0, AddressValidated: true, DestinationLength: 2),
            new(CurrentPayloadLength: 1199, ReceivedPayloadBytes: 1, AddressValidated: false, DestinationLength: 1),
            new(CurrentPayloadLength: 1200, ReceivedPayloadBytes: 0, AddressValidated: false, DestinationLength: 0),
            new(CurrentPayloadLength: 1201, ReceivedPayloadBytes: 0, AddressValidated: false, DestinationLength: 0),
        ];

        foreach (PathValidationDatagramSizingCase scenario in scenarios)
        {
            QuicAntiAmplificationBudget budget = CreateBudget(scenario);
            byte[] destination = new byte[scenario.DestinationLength];
            int expectedPaddingLength = GetExpectedPaddingLength(scenario.CurrentPayloadLength);
            bool expectedSuccess = scenario.CurrentPayloadLength >= 0
                && (expectedPaddingLength == 0
                    || (destination.Length >= expectedPaddingLength
                        && (scenario.AddressValidated || budget.CanSend(expectedPaddingLength))));

            bool formatted = QuicPathValidation.TryFormatPathValidationDatagramPadding(
                scenario.CurrentPayloadLength,
                budget,
                destination,
                out int bytesWritten);

            Assert.Equal(expectedSuccess, formatted);
            Assert.Equal(expectedSuccess ? expectedPaddingLength : 0, bytesWritten);

            if (formatted)
            {
                Assert.True(scenario.CurrentPayloadLength + bytesWritten >= QuicVersionNegotiation.Version1MinimumDatagramPayloadSize);
            }

            for (int index = 0; index < bytesWritten; index++)
            {
                Assert.True(QuicFrameCodec.TryParsePaddingFrame(destination.AsSpan(index, bytesWritten - index), out int bytesConsumed));
                Assert.Equal(1, bytesConsumed);
            }
        }
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

    private static QuicAntiAmplificationBudget CreateBudget(PathValidationDatagramSizingCase scenario)
    {
        QuicAntiAmplificationBudget budget = new();
        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(
            scenario.ReceivedPayloadBytes,
            uniquelyAttributedToSingleConnection: true));

        if (scenario.AddressValidated)
        {
            budget.MarkAddressValidated();
        }

        return budget;
    }

    private readonly record struct PathValidationDatagramSizingCase(
        int CurrentPayloadLength,
        int ReceivedPayloadBytes,
        bool AddressValidated,
        int DestinationLength);
}
