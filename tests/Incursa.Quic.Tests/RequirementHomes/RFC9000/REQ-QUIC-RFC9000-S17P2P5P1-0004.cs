namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P1-0004">The client MUST use the value from the Source Connection ID field of the Retry packet in the Destination Connection ID field of subsequent packets that it sends.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P5P1-0004")]
public sealed class REQ_QUIC_RFC9000_S17P2P5P1_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P1-0004">The client MUST use the value from the Source Connection ID field of the Retry packet in the Destination Connection ID field of subsequent packets that it sends.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5P1-0004")]
    public void RetryMetadataFeedsSubsequentInitialPackets()
    {
        byte[] originalDestinationConnectionId =
        [
            0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
        ];
        byte[] initialSourceConnectionId =
        [
            0x21, 0x22, 0x23, 0x24,
        ];
        byte[] retryPacketDestinationConnectionId =
        [
            0x44, 0x45, 0x46, 0x47,
        ];
        byte[] retrySourceConnectionId =
        [
            0x31, 0x32, 0x33, 0x34,
        ];
        byte[] retryToken =
        [
            0xA1, 0xA2, 0xA3, 0xA4,
        ];

        Assert.True(QuicRetryIntegrity.TryBuildRetryPacket(
            originalDestinationConnectionId,
            retryPacketDestinationConnectionId,
            retrySourceConnectionId,
            retryToken,
            out byte[] retryPacket));
        Assert.True(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
            originalDestinationConnectionId,
            retryPacket,
            out QuicRetryBootstrapMetadata retryMetadata));

        Assert.Equal(retrySourceConnectionId, retryMetadata.RetrySourceConnectionId);
        Assert.Equal(retryToken, retryMetadata.RetryToken);

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            originalDestinationConnectionId,
            out QuicInitialPacketProtection clientProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            originalDestinationConnectionId,
            out QuicInitialPacketProtection serverProtection));

        QuicHandshakeFlowCoordinator coordinator = new(originalDestinationConnectionId, initialSourceConnectionId);
        byte[] cryptoPayload = QuicS12P3TestSupport.CreateSequentialBytes(0x60, 20);

        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            cryptoPayload,
            cryptoPayloadOffset: 0,
            retryMetadata.RetrySourceConnectionId,
            retryMetadata.RetryToken,
            clientProtection,
            out byte[] protectedPacket));

        Assert.True(coordinator.TryOpenInitialPacket(
            protectedPacket,
            serverProtection,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        QuicS17P2P2TestSupport.AssertOpenedInitialPacketContainsCryptoPayload(
            openedPacket,
            payloadOffset,
            payloadLength,
            cryptoPayload,
            expectedCryptoOffset: 0);

        Assert.True(QuicPacketParsing.TryParseLongHeaderFields(
            openedPacket,
            out _,
            out uint version,
            out ReadOnlySpan<byte> openedDestinationConnectionId,
            out ReadOnlySpan<byte> openedSourceConnectionId,
            out ReadOnlySpan<byte> versionSpecificData));
        Assert.Equal((uint)1, version);
        Assert.Equal(retrySourceConnectionId, openedDestinationConnectionId.ToArray());
        Assert.Equal(initialSourceConnectionId, openedSourceConnectionId.ToArray());

        Assert.True(QuicVariableLengthInteger.TryParse(
            versionSpecificData,
            out ulong tokenLength,
            out int tokenLengthBytesConsumed));
        Assert.Equal((ulong)retryToken.Length, tokenLength);
        Assert.True(retryToken.AsSpan().SequenceEqual(
            versionSpecificData.Slice(tokenLengthBytesConsumed, retryToken.Length)));
    }
}
