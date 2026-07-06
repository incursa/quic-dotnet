// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class RFC9000_S7P2P8_DestinationConnectionId_DeferredFuzzClosure
{
    [Fact]
    [Requirement("RFC9000-S7-2-P8-S1-R01")]
    [Requirement("RFC9000-S7-2-P8-S2-R01")]
    [Requirement("RFC9000-S7-2-P8-S3-R02")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void InitialConnectionIdFuzz_UsesFirstPeerInitialIdsAndDiscardsLaterSourceChanges()
    {
        InitialConnectionIdCase[] cases =
        [
            new([0x11, 0x12, 0x13, 0x14], [0x21, 0x22, 0x23, 0x24], [0x31, 0x32, 0x33, 0x34], [0x41, 0x42, 0x43, 0x44], 0x21),
            new([0x51, 0x52, 0x53, 0x54], [0x61, 0x62, 0x63, 0x64], [0x71, 0x72, 0x73, 0x74], [0x81, 0x82, 0x83, 0x84], 0x31),
        ];

        foreach (InitialConnectionIdCase testCase in cases)
        {
            using QuicConnectionRuntime clientRuntime =
                QuicS7P2ServerConnectionIdTestSupport.CreateClientRuntime(
                    testCase.OriginalDestinationConnectionId,
                    testCase.ClientSourceConnectionId);
            QuicConnectionSendDatagramEffect[] clientInitialDatagrams =
                QuicS7P2ServerConnectionIdTestSupport.BootstrapClient(
                    clientRuntime,
                    testCase.ClientSourceConnectionId);

            ServerHandshakeFlight firstFlight = QuicS7P2ServerConnectionIdTestSupport.CreateServerHandshakeFlight(
                testCase.OriginalDestinationConnectionId,
                testCase.ClientSourceConnectionId,
                testCase.FirstServerSourceConnectionId,
                QuicS7P2ServerConnectionIdTestSupport.CreateScalar(testCase.ScalarLastByte),
                clientInitialDatagrams);
            ServerHandshakeFlight replacementFlight = QuicS7P2ServerConnectionIdTestSupport.CreateServerHandshakeFlight(
                testCase.OriginalDestinationConnectionId,
                testCase.ClientSourceConnectionId,
                testCase.ReplacementServerSourceConnectionId,
                QuicS7P2ServerConnectionIdTestSupport.CreateScalar((byte)(testCase.ScalarLastByte + 1)),
                clientInitialDatagrams);

            QuicS7P2ServerConnectionIdTestSupport.AssertLongHeaderConnectionIds(
                firstFlight.InitialPacket,
                testCase.ClientSourceConnectionId,
                testCase.FirstServerSourceConnectionId);

            Assert.True(QuicS7P2ServerConnectionIdTestSupport.ReceivePacket(
                clientRuntime,
                firstFlight.InitialPacket,
                observedAtTicks: 1).StateChanged);
            _ = QuicS7P2ServerConnectionIdTestSupport.ReceivePacket(
                clientRuntime,
                replacementFlight.InitialPacket,
                observedAtTicks: 2);

            Assert.Equal(testCase.FirstServerSourceConnectionId, clientRuntime.CurrentPeerDestinationConnectionId.ToArray());
            Assert.NotEqual(testCase.ReplacementServerSourceConnectionId, clientRuntime.CurrentPeerDestinationConnectionId.ToArray());
            Assert.False(clientRuntime.PeerHandshakeTranscriptCompleted);
        }
    }

    [Fact]
    [Requirement("RFC9000-S7-2-P8-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void RetryConnectionIdFuzz_ClientChangesOutboundDestinationOnlyForFirstRetry()
    {
        byte[] originalDestinationConnectionId = [0x81, 0x82, 0x83, 0x84];
        byte[] clientSourceConnectionId = [0x91, 0x92, 0x93, 0x94];
        byte[][] retrySourceConnectionIds =
        [
            [0xA1, 0xA2, 0xA3, 0xA4],
            [0xB1, 0xB2, 0xB3, 0xB4],
            [0xC1, 0xC2, 0xC3, 0xC4],
        ];

        using QuicConnectionRuntime clientRuntime =
            QuicS7P2ServerConnectionIdTestSupport.CreateClientRuntime(
                originalDestinationConnectionId,
                clientSourceConnectionId);
        _ = QuicS7P2ServerConnectionIdTestSupport.BootstrapClient(clientRuntime, clientSourceConnectionId);

        QuicConnectionTransitionResult firstRetryResult = clientRuntime.Transition(
            new QuicConnectionRetryReceivedEvent(
                ObservedAtTicks: 1,
                RetrySourceConnectionId: retrySourceConnectionIds[0],
                RetryToken: new byte[] { 0x01, 0x02, 0x03 }),
            nowTicks: 1);
        Assert.True(firstRetryResult.StateChanged);

        for (int index = 1; index < retrySourceConnectionIds.Length; index++)
        {
            QuicConnectionTransitionResult subsequentRetryResult = clientRuntime.Transition(
                new QuicConnectionRetryReceivedEvent(
                    ObservedAtTicks: index + 1,
                    RetrySourceConnectionId: retrySourceConnectionIds[index],
                    RetryToken: new byte[] { (byte)(0x10 + index) }),
                nowTicks: index + 1);

            Assert.False(subsequentRetryResult.StateChanged);
        }

        Assert.Equal(retrySourceConnectionIds[0], clientRuntime.CurrentPeerDestinationConnectionId.ToArray());
    }

    [Fact]
    [Requirement("RFC9000-S7-2-P8-S3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public async Task NewConnectionIdFuzz_AllowsFurtherDestinationChangesOnlyFromIssuedConnectionIds()
    {
        byte[][] peerIssuedConnectionIds =
        [
            [0x51, 0x52, 0x53, 0x54],
            [0x61, 0x62, 0x63, 0x64],
        ];

        foreach (byte[] peerIssuedConnectionId in peerIssuedConnectionIds)
        {
            using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
            byte[] originalDestinationConnectionId = runtime.CurrentPeerDestinationConnectionId.ToArray();

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
    }

    private sealed record InitialConnectionIdCase(
        byte[] OriginalDestinationConnectionId,
        byte[] ClientSourceConnectionId,
        byte[] FirstServerSourceConnectionId,
        byte[] ReplacementServerSourceConnectionId,
        byte ScalarLastByte);
}
