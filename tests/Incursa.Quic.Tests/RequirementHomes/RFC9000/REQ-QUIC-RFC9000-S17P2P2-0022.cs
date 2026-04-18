namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0022">This MUST include all cases where a new packet containing the initial cryptographic message needs to be created, such as the packets sent after receiving a Retry packet; see Section 17.2.5.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P2-0022")]
public sealed class REQ_QUIC_RFC9000_S17P2P2_0022
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0022">This MUST include all cases where a new packet containing the initial cryptographic message needs to be created, such as the packets sent after receiving a Retry packet; see Section 17.2.5.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0022")]
    public void TryBuildProtectedInitialPacket_AfterRetry_UsesTheInitialPacketTypeAndRetryToken()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            QuicS17P2P2TestSupport.InitialDestinationConnectionId,
            out QuicInitialPacketProtection clientProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            QuicS17P2P2TestSupport.InitialDestinationConnectionId,
            out QuicInitialPacketProtection serverProtection));

        byte[] retrySourceConnectionId =
        [
            0x31, 0x32, 0x33, 0x34,
        ];
        byte[] retryToken =
        [
            0xA1, 0xA2, 0xA3, 0xA4,
        ];
        Assert.True(QuicRetryIntegrity.TryBuildRetryPacket(
            QuicS17P2P2TestSupport.InitialDestinationConnectionId,
            QuicS17P2P2TestSupport.InitialSourceConnectionId,
            retrySourceConnectionId,
            retryToken,
            out byte[] retryPacket));
        Assert.True(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
            QuicS17P2P2TestSupport.InitialDestinationConnectionId,
            retryPacket,
            out QuicRetryBootstrapMetadata retryMetadata));
        Assert.True(retrySourceConnectionId.AsSpan().SequenceEqual(retryMetadata.RetrySourceConnectionId));
        Assert.True(retryToken.AsSpan().SequenceEqual(retryMetadata.RetryToken));

        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P2TestSupport.CreateClientCoordinator();
        byte[] cryptoPayload = QuicS12P3TestSupport.CreateSequentialBytes(0x60, 20);

        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            cryptoPayload,
            cryptoPayloadOffset: 0,
            retryMetadata.RetrySourceConnectionId,
            retryMetadata.RetryToken,
            clientProtection,
            out ulong packetNumber,
            out byte[] protectedPacket));
        Assert.Equal(0UL, packetNumber);

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
            out byte headerControlBits,
            out uint version,
            out _,
            out _,
            out ReadOnlySpan<byte> versionSpecificData));
        Assert.Equal((uint)1, version);
        Assert.Equal(
            (byte)QuicLongPacketTypeBits.Initial,
            (byte)((headerControlBits & QuicPacketHeaderBits.LongPacketTypeBitsMask) >> QuicPacketHeaderBits.LongPacketTypeBitsShift));

        Assert.True(QuicVariableLengthInteger.TryParse(
            versionSpecificData,
            out ulong tokenLength,
            out int tokenLengthBytesConsumed));
        Assert.Equal((ulong)retryToken.Length, tokenLength);
        Assert.True(retryToken.AsSpan().SequenceEqual(versionSpecificData.Slice(tokenLengthBytesConsumed, retryToken.Length)));
    }
}
