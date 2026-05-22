namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1039">A client MUST discard a Retry packet with a zero-length Retry Token field.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-1039")]
public sealed class REQ_QUIC_RFC9000_1039
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1039">A client MUST discard a Retry packet with a zero-length Retry Token field.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-1039")]
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
    [Requirement("REQ-QUIC-RFC9000-1039")]
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
    [Requirement("REQ-QUIC-RFC9000-1039")]
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
}
