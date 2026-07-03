// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S8-2-3-P2-S3-R01">However, the endpoint MUST initiate another path validation with an expanded datagram to verify that the path supports the required MTU.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S8-2-3-P2-S3-R01")]
public sealed class REQ_QUIC_RFC9000_S8P2P3_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatPathValidationDatagramPadding_ProducesTheExpandedFollowUpDatagramNeededForMtuValidation()
    {
        QuicAntiAmplificationBudget budget = new();
        budget.MarkAddressValidated();

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
}
