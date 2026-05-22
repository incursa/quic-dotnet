namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1735">Handshake packets MAY contain CONNECTION_CLOSE frames of type 0x1c.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-1735")]
public sealed class REQ_QUIC_RFC9000_1735
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void HandshakePacketsCanCarryTransportConnectionCloseFrames()
    {
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.Handshake,
            out QuicTlsPacketProtectionMaterial material));

        QuicHandshakeFlowCoordinator coordinator = QuicS17P1TestSupport.CreateHandshakeCoordinator();
        byte[] cryptoPayload = [0xBA, 0xBB];
        byte[] prefixFramePayload = QuicFrameTestData.BuildConnectionCloseFrame(new QuicConnectionCloseFrame(
            QuicTransportErrorCode.NoError,
            triggeringFrameType: 0x04,
            []));

        Assert.True(coordinator.TryBuildProtectedHandshakePacket(
            cryptoPayload,
            cryptoPayloadOffset: 0,
            prefixFramePayload,
            material,
            out byte[] protectedPacket));

        Assert.True(coordinator.TryOpenHandshakePacket(
            protectedPacket,
            material,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        ReadOnlySpan<byte> payload = openedPacket.AsSpan(payloadOffset, payloadLength);
        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(
            payload,
            out QuicConnectionCloseFrame parsedFrame,
            out int bytesConsumed));
        Assert.Equal(0x1CUL, parsedFrame.FrameType);
        Assert.Equal((ulong)QuicTransportErrorCode.NoError, parsedFrame.ErrorCode);
        Assert.Equal(0x04UL, parsedFrame.TriggeringFrameType);
        ReadOnlySpan<byte> remaining = QuicS13AckPiggybackTestSupport.SkipPadding(payload[bytesConsumed..]);
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            remaining,
            out QuicCryptoFrame cryptoFrame,
            out int cryptoBytesConsumed));
        Assert.Equal(0UL, cryptoFrame.Offset);
        Assert.True(cryptoFrame.CryptoData.SequenceEqual(cryptoPayload));
        Assert.True(QuicS13AckPiggybackTestSupport.SkipPadding(remaining[cryptoBytesConsumed..]).IsEmpty);
    }
}
