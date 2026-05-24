namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0969">Clients MUST ignore the value of this field.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0969")]
public sealed class REQ_QUIC_RFC9000_0969
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0969">Clients MUST ignore the value of this field.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-0969")]
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

    [Theory]
    [InlineData(0x40)]
    [InlineData(0x7F)]
    [Requirement("REQ-QUIC-RFC9000-0969")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseVersionNegotiation_DoesNotUseTheUnusedFieldToBypassDiscardRules(byte headerControlBits)
    {
        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits,
            destinationConnectionId: [0x11, 0x12],
            sourceConnectionId: [0x21],
            supportedVersions: [QuicVersionNegotiation.Version1]);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(packet, out QuicVersionNegotiationPacket header));
        Assert.Equal(headerControlBits, header.HeaderControlBits);
        Assert.True(QuicVersionNegotiation.ShouldDiscardVersionNegotiation(
            header,
            QuicVersionNegotiation.Version1,
            hasSuccessfullyProcessedAnotherPacket: false));
    }
}
