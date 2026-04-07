using FsCheck.Xunit;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P1-0013")]
public sealed class REQ_QUIC_RFC9000_S17P2P1_0013
{
    [Property(Arbitrary = new[] { typeof(QuicHeaderPropertyGenerators) })]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0001">The first bit of a QUIC long header packet MUST be set to 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0003">The four bytes after the first byte in a QUIC long header packet MUST contain a 32-bit Version field.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0004">The byte after the Version field MUST encode the Destination Connection ID length as an 8-bit unsigned integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0006">The byte after the Destination Connection ID field MUST encode the Source Connection ID length as an 8-bit unsigned integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0008">The remainder of a QUIC long header packet MUST contain version-specific content.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0003">The Header Form field MUST be 1 bits long with value 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0004">The Unused field MUST be 7 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0005">The Version field MUST be 32 bits long with value 0.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0006">The Destination Connection ID Length field MUST be 8 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0007">The Destination Connection ID field MUST be between 0 and 2040 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0008">The Source Connection ID Length field MUST be 8 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0009">The Source Connection ID field MUST be between 0 and 2040 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0013">The Version field of a Version Negotiation packet MUST be set to 0x00000000.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0019">The Version Negotiation packet MUST NOT include the Packet Number and Length fields present in other packets that use the long header form.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1-0012">A Version Negotiation packet MUST echo the connection IDs selected by the client.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P1-0001">If the version selected by the client is not acceptable to the server, the server MUST respond with a Version Negotiation packet that includes a list of versions the server will accept.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC8999-S5P1-0001")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0003")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0004")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0006")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0007")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0009")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0013")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0019")]
    [Requirement("REQ-QUIC-RFC9000-S5P1-0012")]
    [Requirement("REQ-QUIC-RFC9000-S6P1-0001")]
    [Trait("Category", "Property")]
    public void TryParseVersionNegotiation_RoundTripsSupportedVersions(VersionNegotiationScenario scenario)
    {
        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            scenario.HeaderControlBits,
            scenario.DestinationConnectionId,
            scenario.SourceConnectionId,
            scenario.SupportedVersions);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(packet, out QuicVersionNegotiationPacket header));
        Assert.Equal(QuicHeaderForm.Long, header.HeaderForm);
        Assert.Equal((byte)(scenario.HeaderControlBits & 0x7F), header.HeaderControlBits);
        Assert.True(header.IsVersionNegotiation);
        Assert.Equal((uint)0, header.Version);
        Assert.Equal(scenario.DestinationConnectionId.Length, header.DestinationConnectionIdLength);
        Assert.True(scenario.DestinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
        Assert.Equal(scenario.SourceConnectionId.Length, header.SourceConnectionIdLength);
        Assert.True(scenario.SourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
        Assert.Equal(scenario.SupportedVersions.Length, header.SupportedVersionCount);

        for (int index = 0; index < scenario.SupportedVersions.Length; index++)
        {
            Assert.Equal(scenario.SupportedVersions[index], header.GetSupportedVersion(index));
        }
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0001">The first bit of a QUIC long header packet MUST be set to 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0003">The four bytes after the first byte in a QUIC long header packet MUST contain a 32-bit Version field.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0004">The byte after the Version field MUST encode the Destination Connection ID length as an 8-bit unsigned integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0006">The byte after the Destination Connection ID field MUST encode the Source Connection ID length as an 8-bit unsigned integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0008">The remainder of a QUIC long header packet MUST contain version-specific content.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0003">The Header Form field MUST be 1 bits long with value 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0004">The Unused field MUST be 7 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0005">The Version field MUST be 32 bits long with value 0.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0006">The Destination Connection ID Length field MUST be 8 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0007">The Destination Connection ID field MUST be between 0 and 2040 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0008">The Source Connection ID Length field MUST be 8 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0009">The Source Connection ID field MUST be between 0 and 2040 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0013">The Version field of a Version Negotiation packet MUST be set to 0x00000000.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0019">The Version Negotiation packet MUST NOT include the Packet Number and Length fields present in other packets that use the long header form.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1-0012">A Version Negotiation packet MUST echo the connection IDs selected by the client.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P1-0001">If the version selected by the client is not acceptable to the server, the server MUST respond with a Version Negotiation packet that includes a list of versions the server will accept.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC8999-S5P1-0001")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0003")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0004")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0006")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0007")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0009")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0013")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0019")]
    [Requirement("REQ-QUIC-RFC9000-S5P1-0012")]
    [Requirement("REQ-QUIC-RFC9000-S6P1-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_VersionNegotiationParsing_RoundTripsValidInputsAndRejectsTruncation()
    {
        Random random = new(0x5150_2027);

        for (int iteration = 0; iteration < 128; iteration++)
        {
            byte headerControlBits = (byte)random.Next(0, 0x80);
            byte[] destinationConnectionId = QuicHeaderTestData.RandomBytes(random, random.Next(0, 8));
            byte[] sourceConnectionId = QuicHeaderTestData.RandomBytes(random, random.Next(0, 8));
            uint[] supportedVersions = new uint[random.Next(1, 5)];

            for (int i = 0; i < supportedVersions.Length; i++)
            {
                supportedVersions[i] = (uint)random.Next(1, int.MaxValue);
            }

            byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
                headerControlBits,
                destinationConnectionId,
                sourceConnectionId,
                supportedVersions);

            Assert.True(QuicPacketParser.TryParseVersionNegotiation(packet, out QuicVersionNegotiationPacket header));
            Assert.Equal(QuicHeaderForm.Long, header.HeaderForm);
            Assert.True(header.IsVersionNegotiation);
            Assert.Equal(headerControlBits, header.HeaderControlBits);
            Assert.Equal(supportedVersions.Length, header.SupportedVersionCount);
            Assert.True(header.ContainsSupportedVersion(supportedVersions[random.Next(0, supportedVersions.Length)]));

            for (int i = 0; i < supportedVersions.Length; i++)
            {
                Assert.Equal(supportedVersions[i], header.GetSupportedVersion(i));
            }

            int truncateBy = random.Next(1, 4);
            if (packet.Length > truncateBy)
            {
                byte[] truncatedPacket = packet[..^truncateBy];
                Assert.False(QuicPacketParser.TryParseVersionNegotiation(truncatedPacket, out _));
            }
        }
    }
}
