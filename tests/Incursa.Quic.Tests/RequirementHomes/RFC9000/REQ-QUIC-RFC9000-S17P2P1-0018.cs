namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0018">It is only sent in response to a packet that MUST indicate an unsupported version; see Section 5.2.2.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P1-0018")]
public sealed class REQ_QUIC_RFC9000_S17P2P1_0018
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0018">It is only sent in response to a packet that MUST indicate an unsupported version; see Section 5.2.2.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0018")]
    public void ShouldSendVersionNegotiation_ReturnsTrueForAnUnsupportedClientVersion()
    {
        Assert.True(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            0x11223344,
            [QuicVersionNegotiation.Version1]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0018">It is only sent in response to a packet that MUST indicate an unsupported version; see Section 5.2.2.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0018")]
    public void ShouldSendVersionNegotiation_ReturnsFalseForASupportedClientVersion()
    {
        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            QuicVersionNegotiation.Version1,
            [QuicVersionNegotiation.Version1]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0018">It is only sent in response to a packet that MUST indicate an unsupported version; see Section 5.2.2.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0018")]
    public void ShouldSendVersionNegotiation_ReturnsFalseForTheReservedVersionNegotiationVersion()
    {
        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            QuicVersionNegotiation.VersionNegotiationVersion,
            [QuicVersionNegotiation.Version1]));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0001">The first bit of a QUIC long header packet MUST be set to 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0003">The four bytes after the first byte in a QUIC long header packet MUST contain a 32-bit Version field.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0004">The byte after the Version field MUST encode the Destination Connection ID length as an 8-bit unsigned integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0006">The byte after the Destination Connection ID field MUST encode the Source Connection ID length as an 8-bit unsigned integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0008">The remainder of a QUIC long header packet MUST contain version-specific content.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1-0012">A Version Negotiation packet MUST echo the connection IDs selected by the client.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P1-0001">If the version selected by the client is not acceptable to the server, the server MUST respond with a Version Negotiation packet that includes a list of versions the server will accept.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P1-0002">An endpoint MUST NOT send a Version Negotiation packet in response to receiving a Version Negotiation packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P3-0001">Endpoints MAY add reserved versions to any field where unknown or unsupported versions are ignored to test that a peer correctly ignores the value.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P2-0002">Each endpoint MUST use the Source Connection ID field to specify the connection ID that is used in the Destination Connection ID field of packets being sent to it.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S5-0003">Version Negotiation packets MUST NOT have cryptographic protection.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC8999-S5P1-0001")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0003")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0004")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0006")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S5P1-0012")]
    [Requirement("REQ-QUIC-RFC9000-S6P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S6P1-0002")]
    [Requirement("REQ-QUIC-RFC9000-S6P3-0001")]
    [Requirement("REQ-QUIC-RFC9000-S7P2-0002")]
    [Requirement("REQ-QUIC-RFC9001-S5-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_VersionNegotiationFormatting_RoundTripsFormattedResponses()
    {
        Random random = new(0x5150_2030);

        for (int iteration = 0; iteration < 128; iteration++)
        {
            byte[] clientDestinationConnectionId = QuicHeaderTestData.RandomBytes(random, random.Next(0, 21));
            byte[] clientSourceConnectionId = QuicHeaderTestData.RandomBytes(random, random.Next(0, 21));
            uint clientSelectedVersion = (uint)random.Next(2, int.MaxValue);
            uint[] serverSupportedVersions = new uint[random.Next(1, 5)];

            for (int index = 0; index < serverSupportedVersions.Length; index++)
            {
                serverSupportedVersions[index] = index == 0 && (iteration & 1) == 0
                    ? QuicVersionNegotiation.CreateReservedVersion((uint)random.Next())
                    : NextAdvertisedVersion(random, clientSelectedVersion);
            }

            byte[] destination = new byte[512];

            Assert.True(QuicVersionNegotiation.TryFormatVersionNegotiationResponse(
                clientSelectedVersion,
                clientDestinationConnectionId,
                clientSourceConnectionId,
                serverSupportedVersions,
                destination,
                out int bytesWritten));
            Assert.True(QuicPacketParser.TryParseVersionNegotiation(destination.AsSpan(0, bytesWritten), out QuicVersionNegotiationPacket packet));
            Assert.True(clientSourceConnectionId.AsSpan().SequenceEqual(packet.DestinationConnectionId));
            Assert.True(clientDestinationConnectionId.AsSpan().SequenceEqual(packet.SourceConnectionId));
            Assert.Equal(serverSupportedVersions.Length, packet.SupportedVersionCount);

            for (int index = 0; index < serverSupportedVersions.Length; index++)
            {
                Assert.Equal(serverSupportedVersions[index], packet.GetSupportedVersion(index));
            }
        }
    }

    private static uint NextAdvertisedVersion(Random random, uint excludedVersion)
    {
        while (true)
        {
            uint candidate = (uint)random.Next(1, int.MaxValue);
            if (candidate != excludedVersion)
            {
                return candidate;
            }
        }
    }
}
