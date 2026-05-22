namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0976">A Version Negotiation packet MUST NOT be acknowledged.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0976")]
public sealed class REQ_QUIC_RFC9000_0976
{
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0976">A Version Negotiation packet MUST NOT be acknowledged.</workbench-requirement>
    /// </workbench-requirements>
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-RFC9000-0976")]
    public void TryParseVersionNegotiation_RecognizesPacketsThatCannotBeAcknowledged()
    {
        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4A,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            supportedVersions: [QuicVersionNegotiation.Version1, 0x11223344]);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(packet, out QuicVersionNegotiationPacket header));
        Assert.True(header.IsVersionNegotiation);
        Assert.Equal(2, header.SupportedVersionCount);
        Assert.False(QuicPacketParser.TryGetPacketNumberSpace(packet, out _));
    }

    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0976">A Version Negotiation packet MUST NOT be acknowledged.</workbench-requirement>
    /// </workbench-requirements>
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [Requirement("REQ-QUIC-RFC9000-0976")]
    public void TryGetPacketNumberSpace_RejectsVersionNegotiationPackets()
    {
        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4A,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            supportedVersions: [QuicVersionNegotiation.Version1]);

        Assert.False(QuicPacketParser.TryGetPacketNumberSpace(packet, out _));
    }
}
