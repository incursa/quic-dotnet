namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S22P2-0001")]
[Requirement("REQ-QUIC-RFC9000-S22P2-0002")]
[Requirement("REQ-QUIC-RFC9000-S22P2-0003")]
[Requirement("REQ-QUIC-RFC9000-S22P2-0004")]
public sealed class QuicVersionNegotiationTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S14-0003")]
    [Requirement("REQ-QUIC-RFC9000-S14-0004")]
    [Requirement("REQ-QUIC-RFC9000-S6-0001")]
    [Requirement("REQ-QUIC-RFC9000-S6-0002")]
    [Trait("Category", "Positive")]
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
    [Requirement("REQ-QUIC-RFC8999-S5P1-0001")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0003")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0004")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0006")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S6P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S6P1-0002")]
    [Trait("Category", "Positive")]
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
    [Requirement("REQ-QUIC-RFC9000-S6P1-0003")]
    [Trait("Category", "Positive")]
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
    [Requirement("REQ-QUIC-RFC9000-S5P2P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S5P2P2-0004")]
    [Trait("Category", "Positive")]
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
    [Trait("Category", "Positive")]
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
    [Requirement("REQ-QUIC-RFC9000-S6P1-0001")]
    [Trait("Category", "Negative")]
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
    [Requirement("REQ-QUIC-RFC9000-S6P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S6P2-0003")]
    [Requirement("REQ-QUIC-RFC9000-S6P2-0004")]
    [Trait("Category", "Positive")]
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
    [Requirement("REQ-QUIC-RFC9000-S6P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S6P2-0002")]
    [Requirement("REQ-QUIC-RFC9000-S6P2-0003")]
    [Requirement("REQ-QUIC-RFC9000-S6P2-0004")]
    [Trait("Category", "Positive")]
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
    [Requirement("REQ-QUIC-RFC9000-S6P3-0001")]
    [Trait("Category", "Positive")]
    public void IsReservedVersion_UsesTheReservedPattern()
    {
        Assert.True(QuicVersionNegotiation.IsReservedVersion(0x0A0A0A0A));
        Assert.False(QuicVersionNegotiation.IsReservedVersion(0x01020304));
        Assert.Equal((uint)0x0A1A2A3A, QuicVersionNegotiation.CreateReservedVersion(0x00112233));
    }
}
