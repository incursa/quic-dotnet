namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P3-0012">Duplicate suppression MUST happen after removing packet protection for the reasons described in Section 9.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P3-0012")]
public sealed class REQ_QUIC_RFC9000_S12P3_0012
{
    private static readonly byte[] DestinationConnectionId =
    [
        0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
    ];

    private static readonly byte[] SourceConnectionId =
    [
        0x01, 0x02, 0x03, 0x04,
    ];

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryOpenProtectedApplicationDataPacket_PublishesThePacketNumberOnlyAfterProtectionIsRemoved()
    {
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            out QuicTlsPacketProtectionMaterial material));

        QuicHandshakeFlowCoordinator coordinator = CreatePacketCoordinator();
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            QuicS12P3TestSupport.CreatePingPayload(),
            material,
            out byte[] protectedPacket));

        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            material,
            out byte[] openedPacket,
            out int payloadOffset,
            out _,
            out bool observedKeyPhase));

        Assert.False(observedKeyPhase);

        ulong packetNumber = ParsePacketNumber(openedPacket, payloadOffset);
        QuicSenderFlowController tracker = new();

        tracker.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber,
            ackEliciting: true,
            receivedAtMicros: 1_000);
        tracker.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber,
            ackEliciting: true,
            receivedAtMicros: 1_200);

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_300,
            out QuicAckFrame frame));

        Assert.Equal(packetNumber, frame.LargestAcknowledged);
        Assert.Equal(0UL, frame.FirstAckRange);
        Assert.Empty(frame.AdditionalRanges);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryOpenProtectedApplicationDataPacket_RejectsTamperedPacketsBeforeAnyReceiptIsRecorded()
    {
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            out QuicTlsPacketProtectionMaterial material));

        QuicHandshakeFlowCoordinator coordinator = CreatePacketCoordinator();
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            QuicS12P3TestSupport.CreatePingPayload(),
            material,
            out byte[] protectedPacket));

        protectedPacket[^1] ^= 0x01;

        Assert.False(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            material,
            out _,
            out _,
            out _,
            out _));

        QuicSenderFlowController tracker = new();
        Assert.False(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_300,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryOpenProtectedApplicationDataPacket_AllowsTheSameOpenedPacketToCollapseToOneReceipt()
    {
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            out QuicTlsPacketProtectionMaterial material));

        QuicHandshakeFlowCoordinator coordinator = CreatePacketCoordinator();
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            QuicS12P3TestSupport.CreatePingPayload(),
            material,
            out byte[] protectedPacket));

        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            material,
            out byte[] openedPacket,
            out int payloadOffset,
            out _,
            out _));
        ulong packetNumber = ParsePacketNumber(openedPacket, payloadOffset);

        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            material,
            out byte[] replayedOpenedPacket,
            out int replayedPayloadOffset,
            out _,
            out _));
        ulong replayedPacketNumber = ParsePacketNumber(replayedOpenedPacket, replayedPayloadOffset);

        QuicSenderFlowController tracker = new();
        tracker.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber,
            ackEliciting: true,
            receivedAtMicros: 1_000);
        tracker.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            replayedPacketNumber,
            ackEliciting: true,
            receivedAtMicros: 1_200);

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_300,
            out QuicAckFrame frame));

        Assert.Equal(packetNumber, frame.LargestAcknowledged);
        Assert.Equal(0UL, frame.FirstAckRange);
        Assert.Empty(frame.AdditionalRanges);
    }

    private static QuicHandshakeFlowCoordinator CreatePacketCoordinator()
    {
        QuicHandshakeFlowCoordinator coordinator = new(DestinationConnectionId, SourceConnectionId);
        Assert.True(coordinator.TrySetDestinationConnectionId(DestinationConnectionId));
        return coordinator;
    }

    private static ulong ParsePacketNumber(ReadOnlySpan<byte> openedPacket, int payloadOffset)
    {
        Assert.True(QuicPacketParser.TryParseShortHeader(openedPacket, out QuicShortHeaderPacket parsedHeader));
        int packetNumberLength = parsedHeader.PacketNumberLengthBits + 1;
        ReadOnlySpan<byte> packetNumberBytes = openedPacket.Slice(payloadOffset - packetNumberLength, packetNumberLength);

        ulong packetNumber = 0;
        foreach (byte packetNumberByte in packetNumberBytes)
        {
            packetNumber = (packetNumber << 8) | packetNumberByte;
        }

        return packetNumber;
    }
}
