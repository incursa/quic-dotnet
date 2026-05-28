// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S7P2-0011")]
public sealed class REQ_QUIC_RFC9000_S7P2_0011
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientChangesTheOutboundDestinationOnlyForTheFirstServerInitial()
    {
        byte[] originalDestinationConnectionId = [0x11, 0x12, 0x13, 0x14];
        byte[] clientSourceConnectionId = [0x21, 0x22, 0x23, 0x24];
        byte[] serverSourceConnectionId = [0x31, 0x32, 0x33, 0x34];

        using QuicConnectionRuntime clientRuntime =
            QuicS7P2ServerConnectionIdTestSupport.CreateClientRuntime(
                originalDestinationConnectionId,
                clientSourceConnectionId);
        QuicConnectionSendDatagramEffect[] clientInitialDatagrams =
            QuicS7P2ServerConnectionIdTestSupport.BootstrapClient(clientRuntime, clientSourceConnectionId);
        ServerHandshakeFlight serverFlight = QuicS7P2ServerConnectionIdTestSupport.CreateServerHandshakeFlight(
            originalDestinationConnectionId,
            clientSourceConnectionId,
            serverSourceConnectionId,
            QuicS7P2ServerConnectionIdTestSupport.CreateScalar(0x21),
            clientInitialDatagrams);

        Assert.True(QuicS7P2ServerConnectionIdTestSupport.ReceivePacket(
            clientRuntime,
            serverFlight.InitialPacket,
            observedAtTicks: 1).StateChanged);
        byte[] destinationAfterFirstInitial = clientRuntime.CurrentPeerDestinationConnectionId.ToArray();

        _ = QuicS7P2ServerConnectionIdTestSupport.ReceivePacket(
            clientRuntime,
            serverFlight.InitialPacket,
            observedAtTicks: 2);

        Assert.Equal(serverSourceConnectionId, destinationAfterFirstInitial);
        Assert.Equal(destinationAfterFirstInitial, clientRuntime.CurrentPeerDestinationConnectionId.ToArray());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientDoesNotChangeTheOutboundDestinationForASecondServerInitialSourceConnectionId()
    {
        byte[] originalDestinationConnectionId = [0x41, 0x42, 0x43, 0x44];
        byte[] clientSourceConnectionId = [0x51, 0x52, 0x53, 0x54];
        byte[] firstServerSourceConnectionId = [0x61, 0x62, 0x63, 0x64];
        byte[] secondServerSourceConnectionId = [0x71, 0x72, 0x73, 0x74];

        using QuicConnectionRuntime clientRuntime =
            QuicS7P2ServerConnectionIdTestSupport.CreateClientRuntime(
                originalDestinationConnectionId,
                clientSourceConnectionId);
        QuicConnectionSendDatagramEffect[] clientInitialDatagrams =
            QuicS7P2ServerConnectionIdTestSupport.BootstrapClient(clientRuntime, clientSourceConnectionId);
        ServerHandshakeFlight firstFlight = QuicS7P2ServerConnectionIdTestSupport.CreateServerHandshakeFlight(
            originalDestinationConnectionId,
            clientSourceConnectionId,
            firstServerSourceConnectionId,
            QuicS7P2ServerConnectionIdTestSupport.CreateScalar(0x31),
            clientInitialDatagrams);
        ServerHandshakeFlight secondFlight = QuicS7P2ServerConnectionIdTestSupport.CreateServerHandshakeFlight(
            originalDestinationConnectionId,
            clientSourceConnectionId,
            secondServerSourceConnectionId,
            QuicS7P2ServerConnectionIdTestSupport.CreateScalar(0x32),
            clientInitialDatagrams);

        Assert.True(QuicS7P2ServerConnectionIdTestSupport.ReceivePacket(
            clientRuntime,
            firstFlight.InitialPacket,
            observedAtTicks: 1).StateChanged);
        _ = QuicS7P2ServerConnectionIdTestSupport.ReceivePacket(
            clientRuntime,
            secondFlight.InitialPacket,
            observedAtTicks: 2);

        Assert.Equal(firstServerSourceConnectionId, clientRuntime.CurrentPeerDestinationConnectionId.ToArray());
        Assert.NotEqual(secondServerSourceConnectionId, clientRuntime.CurrentPeerDestinationConnectionId.ToArray());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ClientDoesNotChangeTheOutboundDestinationForASecondRetrySourceConnectionId()
    {
        byte[] originalDestinationConnectionId = [0x81, 0x82, 0x83, 0x84];
        byte[] clientSourceConnectionId = [0x91, 0x92, 0x93, 0x94];
        byte[] firstRetrySourceConnectionId = [0xA1, 0xA2, 0xA3, 0xA4];
        byte[] secondRetrySourceConnectionId = [0xB1, 0xB2, 0xB3, 0xB4];

        using QuicConnectionRuntime clientRuntime =
            QuicS7P2ServerConnectionIdTestSupport.CreateClientRuntime(
                originalDestinationConnectionId,
                clientSourceConnectionId);
        _ = QuicS7P2ServerConnectionIdTestSupport.BootstrapClient(clientRuntime, clientSourceConnectionId);

        QuicConnectionTransitionResult firstRetryResult = clientRuntime.Transition(
            new QuicConnectionRetryReceivedEvent(
                ObservedAtTicks: 1,
                RetrySourceConnectionId: firstRetrySourceConnectionId,
                RetryToken: new byte[] { 0x01, 0x02, 0x03 }),
            nowTicks: 1);
        QuicConnectionTransitionResult secondRetryResult = clientRuntime.Transition(
            new QuicConnectionRetryReceivedEvent(
                ObservedAtTicks: 2,
                RetrySourceConnectionId: secondRetrySourceConnectionId,
                RetryToken: new byte[] { 0x04, 0x05, 0x06 }),
            nowTicks: 2);

        Assert.True(firstRetryResult.StateChanged);
        Assert.False(secondRetryResult.StateChanged);
        Assert.Equal(firstRetrySourceConnectionId, clientRuntime.CurrentPeerDestinationConnectionId.ToArray());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ClientDoesNotChangeTheOutboundDestinationForTheFirstInitialAfterRetry()
    {
        byte[] originalDestinationConnectionId = [0xC1, 0xC2, 0xC3, 0xC4];
        byte[] clientSourceConnectionId = [0xD1, 0xD2, 0xD3, 0xD4];
        byte[] retrySourceConnectionId = [0xE1, 0xE2, 0xE3, 0xE4];
        byte[] serverInitialSourceConnectionId = [0xF1, 0xF2, 0xF3, 0xF4];

        using QuicConnectionRuntime clientRuntime =
            QuicS7P2ServerConnectionIdTestSupport.CreateClientRuntime(
                originalDestinationConnectionId,
                clientSourceConnectionId);
        _ = QuicS7P2ServerConnectionIdTestSupport.BootstrapClient(clientRuntime, clientSourceConnectionId);

        QuicConnectionTransitionResult retryResult = clientRuntime.Transition(
            new QuicConnectionRetryReceivedEvent(
                ObservedAtTicks: 1,
                RetrySourceConnectionId: retrySourceConnectionId,
                RetryToken: new byte[] { 0x07, 0x08, 0x09 }),
            nowTicks: 1);
        QuicConnectionSendDatagramEffect[] retryReplayDatagrams = retryResult.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        Assert.NotEmpty(retryReplayDatagrams);
        Assert.Equal(retrySourceConnectionId, clientRuntime.CurrentPeerDestinationConnectionId.ToArray());

        ServerHandshakeFlight serverFlight = QuicS7P2ServerConnectionIdTestSupport.CreateServerHandshakeFlightAfterRetry(
            originalDestinationConnectionId,
            clientSourceConnectionId,
            retrySourceConnectionId,
            serverInitialSourceConnectionId,
            QuicS7P2ServerConnectionIdTestSupport.CreateScalar(0x51),
            retryReplayDatagrams);

        Assert.True(QuicS7P2ServerConnectionIdTestSupport.ReceivePacket(
            clientRuntime,
            serverFlight.InitialPacket,
            observedAtTicks: 2).StateChanged);

        Assert.Equal(retrySourceConnectionId, clientRuntime.CurrentPeerDestinationConnectionId.ToArray());
        Assert.NotEqual(serverInitialSourceConnectionId, clientRuntime.CurrentPeerDestinationConnectionId.ToArray());
    }
}
