namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P1-0003">A client MUST discard a Retry packet that contains a Source Connection ID field that is identical to the Destination Connection ID field of its Initial packet.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P5P1-0003")]
public sealed class REQ_QUIC_RFC9000_S17P2P5P1_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P1-0003">A client MUST discard a Retry packet that contains a Source Connection ID field that is identical to the Destination Connection ID field of its Initial packet.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5P1-0003")]
    public void RetryMetadataParserAcceptsRetryPacketsWithDistinctSourceConnectionIds()
    {
        byte[] originalDestinationConnectionId =
        [
            0x11, 0x12, 0x13, 0x14,
        ];
        byte[] retryPacketDestinationConnectionId =
        [
            0x20, 0x21, 0x22, 0x23,
        ];
        byte[] retrySourceConnectionId =
        [
            0x31, 0x32, 0x33,
        ];
        byte[] retryToken =
        [
            0x41, 0x42, 0x43, 0x44,
        ];

        Assert.True(QuicRetryIntegrity.TryBuildRetryPacket(
            originalDestinationConnectionId,
            retryPacketDestinationConnectionId,
            retrySourceConnectionId,
            retryToken,
            out byte[] retryPacket));
        Assert.True(QuicRetryIntegrity.TryValidateRetryPacketIntegrity(originalDestinationConnectionId, retryPacket));

        Assert.True(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
            originalDestinationConnectionId,
            retryPacket,
            out QuicRetryBootstrapMetadata retryMetadata));
        Assert.Equal(retrySourceConnectionId, retryMetadata.RetrySourceConnectionId);
        Assert.Equal(retryToken, retryMetadata.RetryToken);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P1-0003">A client MUST discard a Retry packet that contains a Source Connection ID field that is identical to the Destination Connection ID field of its Initial packet.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5P1-0003")]
    public void RetryMetadataParserRejectsRetryPacketsThatReuseTheInitialDestinationConnectionId()
    {
        byte[] originalDestinationConnectionId =
        [
            0x11, 0x12, 0x13, 0x14,
        ];
        byte[] retryPacketDestinationConnectionId =
        [
            0x20, 0x21, 0x22, 0x23,
        ];
        byte[] retryToken =
        [
            0x41, 0x42, 0x43, 0x44,
        ];

        byte[] retryPacket = QuicRetryPacketRequirementTestData.BuildRetryPacket(
            retryPacketDestinationConnectionId,
            originalDestinationConnectionId,
            retryToken: retryToken);

        Assert.True(QuicRetryIntegrity.TryGenerateRetryIntegrityTag(
            originalDestinationConnectionId,
            retryPacket.AsSpan(0, retryPacket.Length - QuicRetryIntegrity.RetryIntegrityTagLength),
            retryPacket.AsSpan(retryPacket.Length - QuicRetryIntegrity.RetryIntegrityTagLength),
            out int integrityTagBytesWritten));
        Assert.Equal(QuicRetryIntegrity.RetryIntegrityTagLength, integrityTagBytesWritten);
        Assert.True(QuicRetryIntegrity.TryValidateRetryPacketIntegrity(originalDestinationConnectionId, retryPacket));

        Assert.False(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
            originalDestinationConnectionId,
            retryPacket,
            out _));
    }
}
