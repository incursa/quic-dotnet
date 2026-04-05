namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S5-0003">Version Negotiation packets MUST NOT have cryptographic protection.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S5-0003")]
public sealed class REQ_QUIC_RFC9001_S5_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S5-0003">Version Negotiation packets MUST NOT have cryptographic protection.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9001-S5-0003")]
    public void TryParseVersionNegotiation_ExposesVersionListWithoutProtectionState()
    {
        byte[] packetBytes = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4C,
            destinationConnectionId: [0x01, 0x02],
            sourceConnectionId: [0x03],
            supportedVersions: [0x11223344, 0xAABBCCDD]);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(packetBytes, out QuicVersionNegotiationPacket packet));
        Assert.True(packet.IsVersionNegotiation);
        Assert.Equal(2, packet.SupportedVersionCount);
        Assert.Equal((uint)0x11223344, packet.GetSupportedVersion(0));
        Assert.Equal((uint)0xAABBCCDD, packet.GetSupportedVersion(1));
        int offset = QuicHeaderTestData.GetLongHeaderPayloadOffset(packetBytes);
        Assert.True(packetBytes.AsSpan(offset).SequenceEqual(packet.SupportedVersionBytes));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S5-0003">Version Negotiation packets MUST NOT have cryptographic protection.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9001-S5-0003")]
    public void TryFormatVersionNegotiationResponse_WritesAStatelessParseablePacket()
    {
        byte[] destination = new byte[64];

        Assert.True(QuicVersionNegotiation.TryFormatVersionNegotiationResponse(
            clientSelectedVersion: 0x01020304,
            clientDestinationConnectionId: [0xAA, 0xBB],
            clientSourceConnectionId: [0xCC],
            serverSupportedVersions: [QuicVersionNegotiation.Version1, 0x11223344],
            destination,
            out int bytesWritten));

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(
            destination.AsSpan(0, bytesWritten),
            out QuicVersionNegotiationPacket packet));
        Assert.Equal((uint)0, packet.Version);
        Assert.Equal(2, packet.SupportedVersionCount);
        Assert.Equal(QuicVersionNegotiation.Version1, packet.GetSupportedVersion(0));
        Assert.Equal((uint)0x11223344, packet.GetSupportedVersion(1));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S5-0003">Version Negotiation packets MUST NOT have cryptographic protection.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9001-S5-0003")]
    public void TryParseVersionNegotiation_RejectsOrdinaryProtectedLongHeaders()
    {
        byte[] packetBytes = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: QuicVersionNegotiation.Version1,
            destinationConnectionId: [0x01],
            sourceConnectionId: [0x02],
            versionSpecificData: [0x03, 0x04]);

        Assert.False(QuicPacketParser.TryParseVersionNegotiation(packetBytes, out _));
    }
}
