using System.Buffers.Binary;

using FsCheck.Xunit;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17-0001">All numeric values MUST be encoded in network byte order (that is, big endian), and all field sizes are in bits.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17-0001")]
public sealed class REQ_QUIC_RFC9000_S17_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17-0001">All numeric values MUST be encoded in network byte order (that is, big endian), and all field sizes are in bits.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17-0001")]
    public void TryParseVersionNegotiation_PreservesSupportedVersionsInNetworkByteOrder()
    {
        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4C,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            supportedVersions: [0x11223344, 0xAABBCCDD]);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(packet, out QuicVersionNegotiationPacket header));
        Assert.Equal(QuicHeaderForm.Long, header.HeaderForm);
        Assert.Equal(0u, header.Version);
        Assert.Equal(2, header.SupportedVersionCount);
        Assert.Equal((uint)0x11223344, header.GetSupportedVersion(0));
        Assert.Equal((uint)0xAABBCCDD, header.GetSupportedVersion(1));

        int supportedVersionOffset = QuicHeaderTestData.GetLongHeaderPayloadOffset(packet);
        Assert.True(packet.AsSpan(supportedVersionOffset, 8).SequenceEqual([
            0x11, 0x22, 0x33, 0x44,
            0xAA, 0xBB, 0xCC, 0xDD]));
        Assert.Equal((uint)0x11223344, BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(supportedVersionOffset, 4)));
        Assert.Equal((uint)0xAABBCCDD, BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(supportedVersionOffset + 4, 4)));
    }

    [Property(Arbitrary = new[] { typeof(QuicHeaderPropertyGenerators) })]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17-0001">All numeric values MUST be encoded in network byte order (that is, big endian), and all field sizes are in bits.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17-0001")]
    public void Fuzz_VersionNegotiationParsing_UsesBigEndianSupportedVersionEncoding(VersionNegotiationScenario scenario)
    {
        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            scenario.HeaderControlBits,
            scenario.DestinationConnectionId,
            scenario.SourceConnectionId,
            scenario.SupportedVersions);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(packet, out QuicVersionNegotiationPacket header));
        Assert.Equal(QuicHeaderForm.Long, header.HeaderForm);
        Assert.Equal(0u, header.Version);
        Assert.Equal(scenario.SupportedVersions.Length, header.SupportedVersionCount);

        int supportedVersionOffset = QuicHeaderTestData.GetLongHeaderPayloadOffset(packet);
        for (int index = 0; index < scenario.SupportedVersions.Length; index++)
        {
            uint expectedVersion = scenario.SupportedVersions[index];
            Assert.Equal(expectedVersion, header.GetSupportedVersion(index));
            Assert.Equal(
                expectedVersion,
                BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(supportedVersionOffset + (index * sizeof(uint)), sizeof(uint))));
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17-0001">All numeric values MUST be encoded in network byte order (that is, big endian), and all field sizes are in bits.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17-0001")]
    public void TryParseVersionNegotiation_RejectsTruncatedAndMisalignedVersionLists()
    {
        byte[] truncatedPacket = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4C,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            supportedVersions: [0x11223344])[..^1];

        byte[] emptyVersionListPacket = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4C,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20]);

        byte[] misalignedVersionListPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x4C,
            version: 0,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            versionSpecificData: [0x11, 0x22, 0x33]);

        Assert.False(QuicPacketParser.TryParseVersionNegotiation(truncatedPacket, out _));
        Assert.False(QuicPacketParser.TryParseVersionNegotiation(emptyVersionListPacket, out _));
        Assert.False(QuicPacketParser.TryParseVersionNegotiation(misalignedVersionListPacket, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17-0001">All numeric values MUST be encoded in network byte order (that is, big endian), and all field sizes are in bits.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17-0001")]
    public void TryParseVersionNegotiation_PreservesMaximumSupportedVersionValue()
    {
        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4C,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            supportedVersions: [uint.MaxValue]);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(packet, out QuicVersionNegotiationPacket header));
        Assert.Equal(1, header.SupportedVersionCount);
        Assert.Equal(uint.MaxValue, header.GetSupportedVersion(0));

        int supportedVersionOffset = QuicHeaderTestData.GetLongHeaderPayloadOffset(packet);
        Assert.Equal(uint.MaxValue, BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(supportedVersionOffset, sizeof(uint))));
    }
}
