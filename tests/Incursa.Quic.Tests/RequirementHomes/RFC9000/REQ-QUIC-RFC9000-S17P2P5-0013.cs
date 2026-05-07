namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5-0013">A Retry packet MUST NOT contain any protected fields.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P5-0013")]
public sealed class REQ_QUIC_RFC9000_S17P2P5_0013
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5-0013">A Retry packet MUST NOT contain any protected fields.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5-0013")]
    public void TryParseLongHeader_ExposesTheRetryPacketWithoutProtectedFields()
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
        Assert.True(QuicPacketParser.TryParseLongHeader(retryPacket, out QuicLongHeaderPacket header));
        Assert.Equal((byte)QuicLongPacketTypeBits.Retry, header.LongPacketTypeBits);
        Assert.False(QuicPacketParser.TryGetPacketNumberSpace(retryPacket, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5-0013">A Retry packet MUST NOT contain any protected fields.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5-0013")]
    public void TryValidateRetryPacketIntegrity_RejectsRetryPacketsWithInjectedProtectedFieldBytes()
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

        byte[] tamperedRetryPacket = new byte[retryPacket.Length + 1];
        int retryPacketBodyLength = retryPacket.Length - QuicRetryIntegrity.RetryIntegrityTagLength;
        Array.Copy(retryPacket, 0, tamperedRetryPacket, 0, retryPacketBodyLength);
        tamperedRetryPacket[retryPacketBodyLength] = 0xFF;
        Array.Copy(
            retryPacket,
            retryPacketBodyLength,
            tamperedRetryPacket,
            retryPacketBodyLength + 1,
            QuicRetryIntegrity.RetryIntegrityTagLength);

        Assert.True(QuicPacketParser.TryParseLongHeader(tamperedRetryPacket, out QuicLongHeaderPacket header));
        Assert.Equal((byte)QuicLongPacketTypeBits.Retry, header.LongPacketTypeBits);
        Assert.Equal(
            retryToken.Length + QuicRetryIntegrity.RetryIntegrityTagLength + 1,
            header.VersionSpecificData.Length);
        Assert.False(QuicRetryIntegrity.TryValidateRetryPacketIntegrity(originalDestinationConnectionId, tamperedRetryPacket));
        Assert.False(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(originalDestinationConnectionId, tamperedRetryPacket, out _));
    }
}
