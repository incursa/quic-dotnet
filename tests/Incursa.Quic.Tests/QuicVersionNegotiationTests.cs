namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P2-0001">The codepoint of 0x00000001 for the protocol MUST be assigned with permanent status to the protocol defined in this document.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P2-0002">The codepoint of 0x00000000 MUST be permanently reserved.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P2-0003">All codepoints that follow the pattern 0x?a?a?a?a MUST NOT appear in the listing of assigned values.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P2-0004">All codepoints that follow the pattern 0x?a?a?a?a MUST NOT be assigned by IANA.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S22P2-0001")]
[Requirement("REQ-QUIC-RFC9000-S22P2-0002")]
[Requirement("REQ-QUIC-RFC9000-S22P2-0003")]
[Requirement("REQ-QUIC-RFC9000-S22P2-0004")]
public sealed class QuicVersionNegotiationTests
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S14-0003">The maximum datagram size MUST be defined as the largest size of UDP payload that can be sent across a network path using a single UDP datagram.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S14-0004">QUIC MUST NOT be used if the network path cannot support a maximum datagram size of at least 1200 bytes.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6-0001">Clients that support multiple QUIC versions SHOULD ensure that the first UDP datagram they send is sized to the largest of the minimum datagram sizes from all versions they support, using PADDING frames as necessary.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6-0002">Clients that support multiple QUIC versions SHOULD ensure that the first UDP datagram they send is sized to the largest of the minimum datagram sizes from all versions they support, using PADDING frames (Section 19.1) as necessary.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S14-0003")]
    [Requirement("REQ-QUIC-RFC9000-S14-0004")]
    [Requirement("REQ-QUIC-RFC9000-S6-0001")]
    [Requirement("REQ-QUIC-RFC9000-S6-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryGetRequiredInitialDatagramPayloadSize_UsesTheKnownMinimumForVersion1()
    {
        Assert.True(QuicVersionNegotiation.TryGetRequiredInitialDatagramPayloadSize(
            [QuicVersionNegotiation.Version1],
            out int requiredPayloadSize));
        Assert.Equal(QuicVersionNegotiation.Version1MinimumDatagramPayloadSize, requiredPayloadSize);

        Assert.False(QuicVersionNegotiation.TryGetRequiredInitialDatagramPayloadSize([], out _));
        Assert.False(QuicVersionNegotiation.TryGetRequiredInitialDatagramPayloadSize([0x0A0A0A0A], out _));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0001">The first bit of a QUIC long header packet MUST be set to 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0003">The four bytes after the first byte in a QUIC long header packet MUST contain a 32-bit Version field.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0004">The byte after the Version field MUST encode the Destination Connection ID length as an 8-bit unsigned integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0006">The byte after the Destination Connection ID field MUST encode the Source Connection ID length as an 8-bit unsigned integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0008">The remainder of a QUIC long header packet MUST contain version-specific content.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P1-0001">If the version selected by the client is not acceptable to the server, the server MUST respond with a Version Negotiation packet that includes a list of versions the server will accept.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P1-0002">An endpoint MUST NOT send a Version Negotiation packet in response to receiving a Version Negotiation packet.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC8999-S5P1-0001")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0003")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0004")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0006")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S6P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S6P1-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ShouldSendVersionNegotiation_RequiresAnUnsupportedClientVersionAndServerSupport()
    {
        Assert.True(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            0x11223344,
            [QuicVersionNegotiation.Version1]));

        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            QuicVersionNegotiation.VersionNegotiationVersion,
            [QuicVersionNegotiation.Version1]));

        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            0x11223344,
            []));

        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            QuicVersionNegotiation.Version1,
            [QuicVersionNegotiation.Version1]));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P1-0003">A server MAY limit the number of Version Negotiation packets it sends.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S6P1-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ShouldSendVersionNegotiation_CanLimitRepeatedResponses()
    {
        Assert.True(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            0x11223344,
            [QuicVersionNegotiation.Version1],
            hasAlreadySentVersionNegotiation: false));

        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            0x11223344,
            [QuicVersionNegotiation.Version1],
            hasAlreadySentVersionNegotiation: true));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P2P2-0001">If a server receives a packet that indicates an unsupported version and the packet is large enough to initiate a new connection for any supported version, the server SHOULD send a Version Negotiation packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P2P2-0004">Servers SHOULD respond with a Version Negotiation packet, provided that the datagram is sufficiently long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P2P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S5P2P2-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ShouldSendVersionNegotiation_RequiresAnUnsupportedClientVersionAndSufficientDatagramSize()
    {
        Assert.True(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            0x11223344,
            QuicVersionNegotiation.Version1MinimumDatagramPayloadSize,
            [QuicVersionNegotiation.Version1]));

        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            0x11223344,
            QuicVersionNegotiation.Version1MinimumDatagramPayloadSize - 1,
            [QuicVersionNegotiation.Version1]));

        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            QuicVersionNegotiation.Version1,
            QuicVersionNegotiation.Version1MinimumDatagramPayloadSize,
            [QuicVersionNegotiation.Version1]));

        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            0x11223344,
            QuicVersionNegotiation.Version1MinimumDatagramPayloadSize,
            []));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0001">The first bit of a QUIC long header packet MUST be set to 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0003">The four bytes after the first byte in a QUIC long header packet MUST contain a 32-bit Version field.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0004">The byte after the Version field MUST encode the Destination Connection ID length as an 8-bit unsigned integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0006">The byte after the Destination Connection ID field MUST encode the Source Connection ID length as an 8-bit unsigned integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0008">The remainder of a QUIC long header packet MUST contain version-specific content.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S21P12-0001">Version Negotiation packets MUST NOT contain any mechanism to prevent version downgrade attacks.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1-0012">A Version Negotiation packet MUST echo the connection IDs selected by the client.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P2-0002">Each endpoint MUST use the Source Connection ID field to specify the connection ID that is used in the Destination Connection ID field of packets being sent to it.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S5-0003">Version Negotiation packets MUST NOT have cryptographic protection.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P1-0001">If the version selected by the client is not acceptable to the server, the server MUST respond with a Version Negotiation packet that includes a list of versions the server will accept.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P1-0002">An endpoint MUST NOT send a Version Negotiation packet in response to receiving a Version Negotiation packet.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC8999-S5P1-0001")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0003")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0004")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0006")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S21P12-0001")]
    [Requirement("REQ-QUIC-RFC9000-S5P1-0012")]
    [Requirement("REQ-QUIC-RFC9000-S7P2-0002")]
    [Requirement("REQ-QUIC-RFC9001-S5-0003")]
    [Requirement("REQ-QUIC-RFC9000-S6P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S6P1-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatVersionNegotiationResponse_FormatsEchoedConnectionIdsAndSupportedVersions()
    {
        byte[] destination = new byte[64];
        byte[] clientDestinationConnectionId = [0x01, 0x02];
        byte[] clientSourceConnectionId = [0x03, 0x04, 0x05];
        uint[] serverSupportedVersions = [QuicVersionNegotiation.Version1, 0x11223344];

        Assert.True(QuicVersionNegotiation.TryFormatVersionNegotiationResponse(
            0xAABBCCDD,
            clientDestinationConnectionId,
            clientSourceConnectionId,
            serverSupportedVersions,
            destination,
            out int bytesWritten));

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(
            destination[..bytesWritten],
            out QuicVersionNegotiationPacket packet));
        Assert.True(clientSourceConnectionId.AsSpan().SequenceEqual(packet.DestinationConnectionId));
        Assert.True(clientDestinationConnectionId.AsSpan().SequenceEqual(packet.SourceConnectionId));
        Assert.Equal(serverSupportedVersions.Length, packet.SupportedVersionCount);
        Assert.True(packet.ContainsSupportedVersion(QuicVersionNegotiation.Version1));
        Assert.True(packet.ContainsSupportedVersion(0x11223344));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P1-0001">If the version selected by the client is not acceptable to the server, the server MUST respond with a Version Negotiation packet that includes a list of versions the server will accept.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S6P1-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryFormatVersionNegotiationResponse_RejectsTheReservedVersionNumberInTheAdvertisedList()
    {
        byte[] destination = new byte[64];

        Assert.False(QuicVersionNegotiation.TryFormatVersionNegotiationResponse(
            0xAABBCCDD,
            clientDestinationConnectionId: [0x01, 0x02],
            clientSourceConnectionId: [0x03],
            serverSupportedVersions: [QuicVersionNegotiation.VersionNegotiationVersion],
            destination,
            out _));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P2-0001">A client that supports only this version of QUIC MUST abandon the current connection attempt if it receives a Version Negotiation packet unless it has received and successfully processed any other packet or the Version Negotiation packet lists the QUIC version selected by the client.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P2-0003">A client MUST discard any Version Negotiation packet if it has received and successfully processed any other packet, including an earlier Version Negotiation packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P2-0004">A client MUST discard a Version Negotiation packet that lists the QUIC version selected by the client.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S6P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S6P2-0003")]
    [Requirement("REQ-QUIC-RFC9000-S6P2-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ShouldDiscardVersionNegotiation_RespectsPreviouslyProcessedPacketsAndSelectedVersions()
    {
        byte[] packetBytes = QuicHeaderTestData.BuildVersionNegotiation(
            0x4C,
            [0x01, 0x02],
            [0x03],
            0x11223344,
            0xAABBCCDD);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(packetBytes, out QuicVersionNegotiationPacket packet));
        Assert.True(QuicVersionNegotiation.ShouldDiscardVersionNegotiation(packet, 0x11223344, true));
        Assert.True(QuicVersionNegotiation.ShouldDiscardVersionNegotiation(packet, 0x11223344, false));
        Assert.False(QuicVersionNegotiation.ShouldDiscardVersionNegotiation(packet, 0xDEADBEEF, false));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P2-0001">A client that supports only this version of QUIC MUST abandon the current connection attempt if it receives a Version Negotiation packet unless it has received and successfully processed any other packet or the Version Negotiation packet lists the QUIC version selected by the client.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P2-0002">A client that supports only this version of QUIC MUST abandon the current connection attempt if it receives a Version Negotiation packet, with the following two exceptions.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P2-0003">A client MUST discard any Version Negotiation packet if it has received and successfully processed any other packet, including an earlier Version Negotiation packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P2-0004">A client MUST discard a Version Negotiation packet that lists the QUIC version selected by the client.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S6P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S6P2-0002")]
    [Requirement("REQ-QUIC-RFC9000-S6P2-0003")]
    [Requirement("REQ-QUIC-RFC9000-S6P2-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ShouldAbandonConnectionAttempt_RequiresOnlyTheSelectedVersionAndANonDiscardablePacket()
    {
        byte[] packetBytes = QuicHeaderTestData.BuildVersionNegotiation(
            0x4C,
            [0x01, 0x02],
            [0x03],
            0xAABBCCDD);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(packetBytes, out QuicVersionNegotiationPacket packet));
        Assert.True(QuicVersionNegotiation.ShouldAbandonConnectionAttempt(
            packet,
            0x11223344,
            [0x11223344],
            hasSuccessfullyProcessedAnotherPacket: false));
        Assert.False(QuicVersionNegotiation.ShouldAbandonConnectionAttempt(
            packet,
            0x11223344,
            [0x11223344, 0xAABBCCDD],
            hasSuccessfullyProcessedAnotherPacket: false));
        Assert.False(QuicVersionNegotiation.ShouldAbandonConnectionAttempt(
            packet,
            0x11223344,
            [0x11223344],
            hasSuccessfullyProcessedAnotherPacket: true));
        Assert.False(QuicVersionNegotiation.ShouldAbandonConnectionAttempt(
            packet,
            0xAABBCCDD,
            [0xAABBCCDD],
            hasSuccessfullyProcessedAnotherPacket: false));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P3-0001">Endpoints MAY add reserved versions to any field where unknown or unsupported versions are ignored to test that a peer correctly ignores the value.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S6P3-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void IsReservedVersion_UsesTheReservedPattern()
    {
        Assert.True(QuicVersionNegotiation.IsReservedVersion(0x0A0A0A0A));
        Assert.False(QuicVersionNegotiation.IsReservedVersion(0x01020304));
        Assert.Equal((uint)0x0A1A2A3A, QuicVersionNegotiation.CreateReservedVersion(0x00112233));
    }
}
