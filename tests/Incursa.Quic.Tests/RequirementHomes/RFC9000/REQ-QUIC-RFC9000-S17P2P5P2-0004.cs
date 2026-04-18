namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P2-0004">A client MUST discard a Retry packet with a zero-length Retry Token field.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P5P2-0004")]
public sealed class REQ_QUIC_RFC9000_S17P2P5P2_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P2-0004">A client MUST discard a Retry packet with a zero-length Retry Token field.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5P2-0004")]
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
}
