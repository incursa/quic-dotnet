// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S7-2-P8-S3-R01")]
public sealed class RFC9000_S7_2_P8_S3_R01
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S5-0008")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task EndpointCanChangeTheDestinationConnectionIdUsingANewConnectionIdFrame()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        byte[] originalDestinationConnectionId = runtime.CurrentPeerDestinationConnectionId.ToArray();
        byte[] peerIssuedConnectionId = [0x51, 0x52, 0x53, 0x54];

        QuicConnectionTransitionResult newConnectionIdResult = QuicConnectionIdLifecycleTestSupport.ProcessNewConnectionIdFrame(
            runtime,
            sequenceNumber: 1,
            retirePriorTo: 1,
            peerIssuedConnectionId,
            observedAtTicks: 10,
            statelessResetTokenStart: 0x90);

        Assert.True(newConnectionIdResult.StateChanged);
        Assert.Equal(peerIssuedConnectionId, runtime.CurrentPeerDestinationConnectionId.ToArray());
        Assert.NotEqual(originalDestinationConnectionId, runtime.CurrentPeerDestinationConnectionId.ToArray());

        QuicConnectionSendDatagramEffect send =
            await QuicPeerConnectionIdSelectionTestSupport.OpenOutboundStreamAndCaptureSingleSendAsync(runtime);

        QuicPeerConnectionIdSelectionTestSupport.AssertApplicationDataDatagramOpensWithDestination(
            runtime,
            send.Datagram,
            peerIssuedConnectionId);
        QuicPeerConnectionIdSelectionTestSupport.AssertApplicationDataDatagramDoesNotOpenWithDestination(
            runtime,
            send.Datagram,
            originalDestinationConnectionId);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EndpointDoesNotChangeTheDestinationConnectionIdFromALaterInitialSourceConnectionId()
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
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void EndpointDoesNotChangeTheDestinationConnectionIdFromALaterRetrySourceConnectionId()
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

        Assert.True(clientRuntime.Transition(
            new QuicConnectionRetryReceivedEvent(
                ObservedAtTicks: 1,
                RetrySourceConnectionId: firstRetrySourceConnectionId,
                RetryToken: new byte[] { 0x01, 0x02, 0x03 }),
            nowTicks: 1).StateChanged);

        QuicConnectionTransitionResult secondRetryResult = clientRuntime.Transition(
            new QuicConnectionRetryReceivedEvent(
                ObservedAtTicks: 2,
                RetrySourceConnectionId: secondRetrySourceConnectionId,
                RetryToken: new byte[] { 0x04, 0x05, 0x06 }),
            nowTicks: 2);

        Assert.False(secondRetryResult.StateChanged);
        Assert.Equal(firstRetrySourceConnectionId, clientRuntime.CurrentPeerDestinationConnectionId.ToArray());
    }
}
