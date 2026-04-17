namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13-0004">A single QUIC packet can include multiple STREAM frames from one or more streams.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13-0004")]
public sealed class REQ_QUIC_RFC9000_S13_0004
{
    private static readonly byte[] ApplicationDestinationConnectionId =
    [
        0x31, 0x32, 0x33, 0x34,
    ];

    private static readonly byte[] ApplicationSourceConnectionId =
    [
        0x41, 0x42, 0x43, 0x44,
    ];

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildProtectedApplicationDataPacket_CanCarryMultipleStreamFrames()
    {
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            out QuicTlsPacketProtectionMaterial applicationMaterial));

        byte[] streamFrameOne = QuicStreamTestData.BuildStreamFrame(
            0x0A,
            streamId: 0,
            [0xAA]);
        byte[] streamFrameTwo = QuicStreamTestData.BuildStreamFrame(
            0x0A,
            streamId: 4,
            [0xBB, 0xBC]);
        byte[] applicationPayload = [.. streamFrameOne, .. streamFrameTwo];

        QuicHandshakeFlowCoordinator coordinator = CreateApplicationCoordinator();
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            applicationPayload,
            applicationMaterial,
            out byte[] protectedPacket));

        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            applicationMaterial,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool keyPhase));
        Assert.False(keyPhase);

        ReadOnlySpan<byte> payload = openedPacket.AsSpan(payloadOffset, payloadLength);
        Assert.True(QuicStreamParser.TryParseStreamFrame(payload, out QuicStreamFrame parsedFirstFrame));
        Assert.Equal(0UL, parsedFirstFrame.StreamId.Value);
        Assert.True(parsedFirstFrame.StreamData.SequenceEqual(new byte[] { 0xAA }));

        ReadOnlySpan<byte> remainder = payload[parsedFirstFrame.ConsumedLength..];
        Assert.True(QuicStreamParser.TryParseStreamFrame(remainder, out QuicStreamFrame parsedSecondFrame));
        Assert.Equal(4UL, parsedSecondFrame.StreamId.Value);
        Assert.True(parsedSecondFrame.StreamData.SequenceEqual(new byte[] { 0xBB, 0xBC }));

        ReadOnlySpan<byte> tail = remainder[parsedSecondFrame.ConsumedLength..];
        if (!tail.IsEmpty)
        {
            ReadOnlySpan<byte> padding = tail;
            while (!padding.IsEmpty)
            {
                Assert.True(QuicFrameCodec.TryParsePaddingFrame(padding, out int paddingBytesConsumed));
                Assert.Equal(1, paddingBytesConsumed);
                padding = padding[paddingBytesConsumed..];
            }
        }
    }

    private static QuicHandshakeFlowCoordinator CreateApplicationCoordinator()
    {
        return new QuicHandshakeFlowCoordinator(ApplicationDestinationConnectionId, ApplicationSourceConnectionId);
    }
}
