// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0272")]
public sealed class REQ_QUIC_RFC9000_0272
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ListenerHostSendsConnectionRefusedInitialCloseWhenApplicationRefusesConnection()
    {
        byte[] clientInitialDestinationConnectionId =
        [
            0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
        ];
        byte[] clientSourceConnectionId =
        [
            0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8,
        ];
        byte[] clientInitialPacket = InteropEndpointHostTestSupport.BuildProtectedInitialPacket(
            clientInitialDestinationConnectionId,
            clientSourceConnectionId);

        byte[] serverResponse = await QuicS5P2P2ServerPreAcceptanceTestSupport
            .SendInitialAndReceiveServerResponseAsync(
                clientInitialPacket,
                clientSourceConnectionId,
                _ => null);

        Assert.True(QuicS5P2P2ServerPreAcceptanceTestSupport.TryOpenInitialConnectionCloseFrame(
            serverResponse,
            clientInitialDestinationConnectionId,
            out ulong errorCode,
            out ulong triggeringFrameType));
        Assert.Equal((ulong)QuicTransportErrorCode.ConnectionRefused, errorCode);
        Assert.Equal(0UL, triggeringFrameType);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ListenerHostDoesNotSendConnectionRefusedCloseWhenApplicationAcceptsConnection()
    {
        byte[] clientInitialDestinationConnectionId =
        [
            0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
        ];
        byte[] clientSourceConnectionId =
        [
            0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
        ];
        byte[] clientInitialPacket = InteropEndpointHostTestSupport.BuildProtectedInitialPacket(
            clientInitialDestinationConnectionId,
            clientSourceConnectionId);

        byte[] serverResponse = await QuicS5P2P2ServerPreAcceptanceTestSupport
            .SendConformingInitialAndReceiveServerInitialAsync(clientInitialPacket, clientSourceConnectionId);

        Assert.False(QuicS5P2P2ServerPreAcceptanceTestSupport.TryOpenInitialConnectionCloseFrame(
            serverResponse,
            clientInitialDestinationConnectionId,
            out _,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task ConnectionRefusedInitialCloseSupportsTheShortestClientSourceConnectionId()
    {
        byte[] clientInitialDestinationConnectionId =
        [
            0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8,
        ];
        byte[] clientSourceConnectionId = [0xB0];
        byte[] clientInitialPacket = InteropEndpointHostTestSupport.BuildProtectedInitialPacket(
            clientInitialDestinationConnectionId,
            clientSourceConnectionId);

        byte[] serverResponse = await QuicS5P2P2ServerPreAcceptanceTestSupport
            .SendInitialAndReceiveServerResponseAsync(
                clientInitialPacket,
                clientSourceConnectionId,
                _ => null);

        Assert.True(serverResponse.Length >= QuicVersionNegotiation.Version1MinimumDatagramPayloadSize);
        Assert.True(QuicPacketParser.TryParseLongHeader(serverResponse, out QuicLongHeaderPacket responseHeader));
        Assert.Equal(clientSourceConnectionId, responseHeader.DestinationConnectionId.ToArray());
        Assert.Equal(8, responseHeader.SourceConnectionId.Length);
        Assert.True(QuicS5P2P2ServerPreAcceptanceTestSupport.TryOpenInitialConnectionCloseFrame(
            serverResponse,
            clientInitialDestinationConnectionId,
            out ulong errorCode,
            out _));
        Assert.Equal((ulong)QuicTransportErrorCode.ConnectionRefused, errorCode);
    }
}
