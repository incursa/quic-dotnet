// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S8-2-2-P3-S1-R01")]
public sealed class REQ_QUIC_RFC9000_S8P2P2_0005
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
    [Requirement("RFC9000-S8-2-2-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RuntimePathResponseDatagramIsExactlyTheRfcMinimumWhenBudgetAllows()
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);

        QuicConnectionPathIdentity activePath = runtime.ActivePath!.Value.Identity;
        byte[] challengeData = QuicS8P2PathValidationTestSupport.CreateChallengeData(0x70);

        QuicConnectionTransitionResult result =
            QuicS8P2PathValidationTestSupport.ReceiveProtectedPathChallenge(
                runtime,
                activePath,
                challengeData,
                packetNumber: 0x70,
                observedAtTicks: 20);

        QuicS8P2PathValidationTestSupport.AssertSinglePathResponseDatagram(
            runtime,
            result,
            activePath,
            challengeData,
            expectMinimumSize: true);
    }
}
