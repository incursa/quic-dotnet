// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0305")]
public sealed class REQ_QUIC_RFC9000_0305
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ShortHeaderPacketsCannotEstablishHandshakeConnectionIds()
    {
        byte[] shortHeader = QuicHeaderTestData.BuildShortHeader(
            headerControlBits: 0x01,
            remainder: [0xA0, 0xA1, 0xA2, 0xA3]);

        Assert.True(QuicPacketParser.TryParseShortHeader(shortHeader, out QuicShortHeaderPacket parsedShortHeader));
        Assert.Equal(QuicHeaderForm.Short, parsedShortHeader.HeaderForm);
        Assert.False(QuicPacketParser.TryParseLongHeader(shortHeader, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Requirement("REQ-QUIC-RFC9000-S7-0001")]
    [Requirement("REQ-QUIC-RFC9000-S7-0004")]
    [Trait("Category", "Positive")]
    public void HandshakePacketsUseLongHeadersToEstablishBothConnectionIds()
    {
        byte[] originalDestinationConnectionId =
            QuicS7P2FirstFlightConnectionIdTestSupport.InitialDestinationConnectionId;
        byte[] clientInitialSourceConnectionId =
            QuicS7P2FirstFlightConnectionIdTestSupport.InitialSourceConnectionId;
        byte[] serverSourceConnectionId = [0x30, 0x31, 0x32];

        using QuicConnectionRuntime clientRuntime =
            QuicS7P2ServerConnectionIdTestSupport.CreateClientRuntime(
                originalDestinationConnectionId,
                clientInitialSourceConnectionId);
        QuicConnectionSendDatagramEffect[] clientInitialDatagrams =
            QuicS7P2ServerConnectionIdTestSupport.BootstrapClient(
                clientRuntime,
                clientInitialSourceConnectionId);

        Assert.NotEmpty(clientInitialDatagrams);

        ServerHandshakeFlight serverFlight = QuicS7P2ServerConnectionIdTestSupport.CreateServerHandshakeFlight(
            originalDestinationConnectionId,
            clientInitialSourceConnectionId,
            serverSourceConnectionId,
            QuicS7P2ServerConnectionIdTestSupport.CreateScalar(0x51),
            clientInitialDatagrams);

        Assert.True(QuicS7P2ServerConnectionIdTestSupport.ReceivePacket(
            clientRuntime,
            serverFlight.InitialPacket,
            observedAtTicks: 1).StateChanged);
        Assert.True(QuicS7P2ServerConnectionIdTestSupport.ReceivePacket(
            clientRuntime,
            serverFlight.HandshakePacket,
            observedAtTicks: 2).StateChanged);
        Assert.True(clientRuntime.TlsState.PeerCertificatePolicyAccepted);
        Assert.True(clientRuntime.TlsState.PeerFinishedVerified);
        Assert.True(clientRuntime.TlsState.HandshakeKeysAvailable);
        Assert.True(clientRuntime.TlsState.OneRttKeysAvailable);

        QuicS7P2ServerConnectionIdTestSupport.AssertLongHeaderConnectionIds(
            clientInitialDatagrams[0].Datagram.Span,
            originalDestinationConnectionId,
            clientInitialSourceConnectionId);
        QuicS7P2ServerConnectionIdTestSupport.AssertLongHeaderConnectionIds(
            serverFlight.InitialPacket,
            clientInitialSourceConnectionId,
            serverSourceConnectionId);
        QuicS7P2ServerConnectionIdTestSupport.AssertLongHeaderConnectionIds(
            serverFlight.HandshakePacket,
            clientInitialSourceConnectionId,
            serverSourceConnectionId);
    }
}
