// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S17-2-5-2-P2-S2-R01">A client MUST discard a Retry packet with a zero-length Retry Token field.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S17-2-5-2-P2-S2-R01")]
public sealed class REQ_QUIC_RFC9000_1039
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="RFC9000-S17-2-5-2-P2-S2-R01">A client MUST discard a Retry packet with a zero-length Retry Token field.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9000-S17-2-5-2-P2-S2-R01")]
    public void RetryMetadataParserRejectsRetryPacketsWithZeroLengthRetryTokens()
    {
        Assert.True(QuicRetryIntegrity.TryBuildRetryPacket(
            QuicS17P2P5P2TestSupport.OriginalDestinationConnectionId,
            QuicS17P2P5P2TestSupport.InitialSourceConnectionId,
            QuicS17P2P5P2TestSupport.RetrySourceConnectionId,
            retryToken: [],
            out byte[] retryPacket));

        Assert.True(QuicRetryIntegrity.TryValidateRetryPacketIntegrity(
            QuicS17P2P5P2TestSupport.OriginalDestinationConnectionId,
            retryPacket));

        Assert.False(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
            QuicS17P2P5P2TestSupport.OriginalDestinationConnectionId,
            retryPacket,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("RFC9000-S17-2-5-2-P2-S2-R01")]
    public void RetryMetadataParserAcceptsRetryPacketsWithMinimumNonEmptyTokens()
    {
        byte[] retryPacket = QuicS17P2P5P2TestSupport.CreateRetryPacket(
            QuicS17P2P5P2TestSupport.RetrySourceConnectionId,
            QuicS17P2P5P2TestSupport.SingleByteRetryToken);

        Assert.True(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
            QuicS17P2P5P2TestSupport.OriginalDestinationConnectionId,
            retryPacket,
            out QuicRetryBootstrapMetadata retryMetadata));
        Assert.Equal(QuicS17P2P5P2TestSupport.SingleByteRetryToken, retryMetadata.RetryToken);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    [Requirement("RFC9000-S17-2-5-2-P2-S2-R01")]
    public void RetryMetadataParserRejectsTheExactZeroLengthRetryTokenBoundary()
    {
        byte[] retryPacket = QuicS17P2P5P2TestSupport.CreateRetryPacket(
            QuicS17P2P5P2TestSupport.RetrySourceConnectionId,
            retryToken: []);

        Assert.False(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
            QuicS17P2P5P2TestSupport.OriginalDestinationConnectionId,
            retryPacket,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    [Requirement("RFC9000-S17-2-5-2-P2-S2-R01")]
    public void Fuzz_RetryMetadataParserRejectsOnlyZeroLengthRetryTokens()
    {
        foreach (int retryTokenLength in new[] { 0, 1, 2, 8, 32 })
        {
            byte[] retryToken = Enumerable.Range(0, retryTokenLength).Select(index => (byte)(0x80 + index)).ToArray();
            byte[] retryPacket = QuicS17P2P5P2TestSupport.CreateRetryPacket(
                QuicS17P2P5P2TestSupport.RetrySourceConnectionId,
                retryToken);

            bool parsed = QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
                QuicS17P2P5P2TestSupport.OriginalDestinationConnectionId,
                retryPacket,
                out QuicRetryBootstrapMetadata retryMetadata);

            Assert.Equal(retryTokenLength > 0, parsed);
            if (retryTokenLength > 0)
            {
                Assert.Equal(retryToken, retryMetadata.RetryToken);
            }
        }
    }
}
