namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P3-0002">Each endpoint MUST maintain a separate packet number for sending and receiving.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P3-0002")]
public sealed class REQ_QUIC_RFC9000_S12P3_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SendAndReceivePacketNumbersAdvanceIndependently()
    {
        byte[] initialDcid =
        [
            0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
        ];
        byte[] sourceConnectionId =
        [
            0x01, 0x02, 0x03, 0x04,
        ];

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            initialDcid,
            out QuicInitialPacketProtection protection));

        QuicHandshakeFlowCoordinator coordinator = new(initialDcid, sourceConnectionId);
        QuicSenderFlowController receiver = new();

        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            QuicS12P3TestSupport.CreateSequentialBytes(0x10, 20),
            cryptoPayloadOffset: 0,
            protection,
            out ulong firstSentPacketNumber,
            out _));
        receiver.RecordIncomingPacket(
            QuicPacketNumberSpace.Initial,
            packetNumber: 7,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            QuicS12P3TestSupport.CreateSequentialBytes(0x20, 20),
            cryptoPayloadOffset: 20,
            protection,
            out ulong secondSentPacketNumber,
            out _));
        receiver.RecordIncomingPacket(
            QuicPacketNumberSpace.Handshake,
            packetNumber: 3,
            ackEliciting: true,
            receivedAtMicros: 1_010);

        Assert.Equal(0UL, firstSentPacketNumber);
        Assert.Equal(1UL, secondSentPacketNumber);

        Assert.True(receiver.TryBuildAckFrame(
            QuicPacketNumberSpace.Initial,
            nowMicros: 1_100,
            out QuicAckFrame initialFrame));
        Assert.Equal(7UL, initialFrame.LargestAcknowledged);

        Assert.True(receiver.TryBuildAckFrame(
            QuicPacketNumberSpace.Handshake,
            nowMicros: 1_100,
            out QuicAckFrame handshakeFrame));
        Assert.Equal(3UL, handshakeFrame.LargestAcknowledged);
    }
}
