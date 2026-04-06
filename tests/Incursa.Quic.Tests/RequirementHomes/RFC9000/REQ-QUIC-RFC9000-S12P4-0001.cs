namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S12P4-0001")]
public sealed class REQ_QUIC_RFC9000_S12P4_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P4-0001">Version Negotiation, Stateless Reset, and Retry packets MUST NOT contain frames.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S12P4-0001")]
    public void TryParsePacketForms_RecognizesVersionNegotiationRetryAndStatelessResetPackets()
    {
        byte[] versionNegotiationPacket = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4A,
            destinationConnectionId: [0x11, 0x12],
            sourceConnectionId: [0x21],
            supportedVersions: [0x11223344u, 0x55667788u]);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(versionNegotiationPacket, out QuicVersionNegotiationPacket versionNegotiationHeader));
        Assert.Equal(2, versionNegotiationHeader.SupportedVersionCount);
        Assert.False(QuicPacketParser.TryGetPacketNumberSpace(versionNegotiationPacket, out _));

        byte[] retryPacket = QuicRetryPacketRequirementTestData.BuildRetryPacket();
        Assert.True(QuicPacketParser.TryParseLongHeader(retryPacket, out QuicLongHeaderPacket retryHeader));
        Assert.Equal(0x03, retryHeader.LongPacketTypeBits);
        Assert.False(QuicPacketParser.TryGetPacketNumberSpace(retryPacket, out _));

        byte[] statelessResetToken = QuicStatelessResetRequirementTestData.CreateToken();
        byte[] statelessResetPacket = QuicStatelessResetRequirementTestData.FormatDatagram(statelessResetToken);
        QuicStatelessResetRequirementTestData.AssertShortHeaderLayout(statelessResetPacket);
        QuicStatelessResetRequirementTestData.AssertTailTokenMatches(statelessResetPacket, statelessResetToken);
        Assert.True(QuicStatelessReset.IsPotentialStatelessReset(statelessResetPacket));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P4-0001">Version Negotiation, Stateless Reset, and Retry packets MUST NOT contain frames.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S12P4-0001")]
    public void TryParseFramePayloads_RejectsVersionNegotiationRetryAndStatelessResetPackets()
    {
        byte[] versionNegotiationPacket = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4A,
            destinationConnectionId: [0x11, 0x12],
            sourceConnectionId: [0x21],
            supportedVersions: [0x11223344u, 0x55667788u]);
        byte[] retryPacket = QuicRetryPacketRequirementTestData.BuildRetryPacket();
        byte[] statelessResetPacket = QuicStatelessResetRequirementTestData.FormatDatagram(QuicStatelessResetRequirementTestData.CreateToken());

        Assert.False(QuicFrameCodec.TryParsePaddingFrame(versionNegotiationPacket, out _));
        Assert.False(QuicFrameCodec.TryParsePingFrame(versionNegotiationPacket, out _));
        Assert.False(QuicFrameCodec.TryParsePaddingFrame(retryPacket, out _));
        Assert.False(QuicFrameCodec.TryParsePingFrame(retryPacket, out _));
        Assert.False(QuicFrameCodec.TryParsePaddingFrame(statelessResetPacket, out _));
        Assert.False(QuicFrameCodec.TryParsePingFrame(statelessResetPacket, out _));
    }
}
