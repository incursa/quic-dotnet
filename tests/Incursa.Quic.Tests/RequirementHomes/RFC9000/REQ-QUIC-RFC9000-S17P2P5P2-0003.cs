namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P2-0003">Clients MUST discard Retry packets that have a Retry Integrity Tag that cannot be validated; see Section 5.8 of [QUIC-TLS].</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P5P2-0003")]
public sealed class REQ_QUIC_RFC9000_S17P2P5P2_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P2-0003">Clients MUST discard Retry packets that have a Retry Integrity Tag that cannot be validated; see Section 5.8 of [QUIC-TLS].</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5P2-0003")]
    public void RetryMetadataParserAcceptsRetryPacketsWithValidIntegrityTags()
    {
        byte[] retryPacket = QuicS17P2P5P2TestSupport.CreateRetryPacket();

        Assert.True(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
            QuicS17P2P5P2TestSupport.OriginalDestinationConnectionId,
            retryPacket,
            out QuicRetryBootstrapMetadata retryMetadata));
        Assert.Equal(QuicS17P2P5P2TestSupport.RetrySourceConnectionId, retryMetadata.RetrySourceConnectionId);
        Assert.Equal(QuicS17P2P5P2TestSupport.RetryToken, retryMetadata.RetryToken);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P2-0003">Clients MUST discard Retry packets that have a Retry Integrity Tag that cannot be validated; see Section 5.8 of [QUIC-TLS].</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5P2-0003")]
    public void RetryMetadataParserRejectsRetryPacketsWithTamperedIntegrityTags()
    {
        byte[] retryPacket = QuicS17P2P5P2TestSupport.CreateRetryPacket();
        retryPacket[^1] ^= 0x01;

        Assert.False(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
            QuicS17P2P5P2TestSupport.OriginalDestinationConnectionId,
            retryPacket,
            out _));
    }
}
