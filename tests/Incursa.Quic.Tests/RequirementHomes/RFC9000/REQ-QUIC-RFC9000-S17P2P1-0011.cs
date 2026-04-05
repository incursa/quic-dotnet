namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0011">Clients MUST ignore the value of this field.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P1-0011")]
public sealed class REQ_QUIC_RFC9000_S17P2P1_0011
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0011">Clients MUST ignore the value of this field.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0011")]
    public void TryParseVersionNegotiation_IgnoresTheUnusedFieldWhenDecidingWhetherToDiscard()
    {
        byte[] destinationConnectionId = [0x11, 0x12];
        byte[] sourceConnectionId = [0x21];
        uint[] supportedVersions = [0xAABBCCDD];

        byte[] firstPacket = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x40,
            destinationConnectionId,
            sourceConnectionId,
            supportedVersions);

        byte[] secondPacket = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x7F,
            destinationConnectionId,
            sourceConnectionId,
            supportedVersions);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(firstPacket, out QuicVersionNegotiationPacket firstHeader));
        Assert.True(QuicPacketParser.TryParseVersionNegotiation(secondPacket, out QuicVersionNegotiationPacket secondHeader));
        Assert.Equal((byte)0x40, firstHeader.HeaderControlBits);
        Assert.Equal((byte)0x7F, secondHeader.HeaderControlBits);

        Assert.False(QuicVersionNegotiation.ShouldDiscardVersionNegotiation(
            firstHeader,
            QuicVersionNegotiation.Version1,
            hasSuccessfullyProcessedAnotherPacket: false));
        Assert.False(QuicVersionNegotiation.ShouldDiscardVersionNegotiation(
            secondHeader,
            QuicVersionNegotiation.Version1,
            hasSuccessfullyProcessedAnotherPacket: false));

        Assert.True(QuicVersionNegotiation.ShouldAbandonConnectionAttempt(
            firstHeader,
            QuicVersionNegotiation.Version1,
            [QuicVersionNegotiation.Version1],
            hasSuccessfullyProcessedAnotherPacket: false));
        Assert.True(QuicVersionNegotiation.ShouldAbandonConnectionAttempt(
            secondHeader,
            QuicVersionNegotiation.Version1,
            [QuicVersionNegotiation.Version1],
            hasSuccessfullyProcessedAnotherPacket: false));
    }
}
