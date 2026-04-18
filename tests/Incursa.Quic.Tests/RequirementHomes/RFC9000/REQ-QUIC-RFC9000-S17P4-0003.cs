namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P4-0003">An endpoint that does not support this feature MUST disable it, as defined below.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P4-0003")]
public sealed class REQ_QUIC_RFC9000_S17P4_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P4-0003">An endpoint that does not support this feature MUST disable it, as defined below.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P4-0003")]
    public void TryBuildProtectedApplicationDataPacket_DisablesTheSpinBitForUnsupportedEndpoints()
    {
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);
        byte[] payload = QuicS12P3TestSupport.CreatePingPayload();

        byte[] destinationConnectionId = [0x11, 0x31];
        byte[] sourceConnectionId = [0x50];
        QuicHandshakeFlowCoordinator coordinator = new(destinationConnectionId, sourceConnectionId);

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            material,
            out byte[] protectedPacket));

        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            material,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        Assert.True(QuicPacketParser.TryParseShortHeader(openedPacket, out QuicShortHeaderPacket header));
        Assert.Equal(QuicHeaderForm.Short, header.HeaderForm);
        Assert.False(header.SpinBit);
        Assert.Equal(1 + destinationConnectionId.Length + 4, payloadOffset);
        Assert.True(payloadLength >= payload.Length);
        Assert.True(openedPacket.AsSpan(payloadOffset, payload.Length).SequenceEqual(payload));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P4-0003">An endpoint that does not support this feature MUST disable it, as defined below.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P4-0003")]
    public void TryOpenProtectedApplicationDataPacket_IgnoresTheIncomingSpinBitWhenUnsupported(bool incomingSpinBit)
    {
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);
        byte[] payload = QuicS12P3TestSupport.CreatePingPayload();

        byte[] destinationConnectionId = [0x11, 0x31];
        byte[] sourceConnectionId = [0x50];

        QuicHandshakeFlowCoordinator receiver = new(destinationConnectionId, sourceConnectionId);
        byte[] protectedPacket = BuildProtectedApplicationDataPacket(
            incomingSpinBit,
            material,
            payload,
            destinationConnectionId,
            sourceConnectionId);

        Assert.True(receiver.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            material,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        Assert.True(QuicPacketParser.TryParseShortHeader(openedPacket, out QuicShortHeaderPacket header));
        Assert.Equal(QuicHeaderForm.Short, header.HeaderForm);
        Assert.Equal(incomingSpinBit, header.SpinBit);
        Assert.Equal(1 + destinationConnectionId.Length + 4, payloadOffset);
        Assert.True(payloadLength >= payload.Length);
        Assert.True(openedPacket.AsSpan(payloadOffset, payload.Length).SequenceEqual(payload));

        Assert.True(receiver.TryBuildProtectedApplicationDataPacket(
            payload,
            material,
            out byte[] followupProtectedPacket));

        Assert.True(receiver.TryOpenProtectedApplicationDataPacket(
            followupProtectedPacket,
            material,
            out byte[] followupOpenedPacket,
            out int followupPayloadOffset,
            out int followupPayloadLength));

        Assert.True(QuicPacketParser.TryParseShortHeader(followupOpenedPacket, out QuicShortHeaderPacket followupHeader));
        Assert.Equal(QuicHeaderForm.Short, followupHeader.HeaderForm);
        Assert.False(followupHeader.SpinBit);
        Assert.Equal(1 + destinationConnectionId.Length + 4, followupPayloadOffset);
        Assert.True(followupPayloadLength >= payload.Length);
        Assert.True(followupOpenedPacket.AsSpan(followupPayloadOffset, payload.Length).SequenceEqual(payload));
    }

    private static byte[] BuildProtectedApplicationDataPacket(
        bool incomingSpinBit,
        QuicTlsPacketProtectionMaterial material,
        ReadOnlySpan<byte> payload,
        byte[] destinationConnectionId,
        byte[] sourceConnectionId)
    {
        QuicHandshakeFlowCoordinator sender = incomingSpinBit
            ? new QuicHandshakeFlowCoordinator(
                destinationConnectionId,
                sourceConnectionId,
                enableRandomizedSpinBitSelection: true)
            : new QuicHandshakeFlowCoordinator(destinationConnectionId, sourceConnectionId);

        Assert.True(sender.TryBuildProtectedApplicationDataPacket(
            payload,
            material,
            out byte[] protectedPacket));

        return protectedPacket;
    }
}
