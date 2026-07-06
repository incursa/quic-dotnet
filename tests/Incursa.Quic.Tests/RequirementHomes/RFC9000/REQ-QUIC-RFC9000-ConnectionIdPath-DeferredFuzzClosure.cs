// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_ConnectionIdPath_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0240")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PeerConnectionIdPathSelectionFuzz_ChangesToAnotherAvailableConnectionIdForNewPaths()
    {
        for (ulong sequenceNumber = 1; sequenceNumber <= 6; sequenceNumber++)
        {
            QuicConnectionPeerConnectionIdState state = new();
            QuicConnectionPathIdentity originalPath = new(
                RemoteAddress: $"203.0.113.{10 + sequenceNumber}",
                LocalAddress: "198.51.100.20",
                RemotePort: 443,
                LocalPort: 5000);
            QuicConnectionPathIdentity migratedPath = new(
                RemoteAddress: $"203.0.113.{30 + sequenceNumber}",
                LocalAddress: "198.51.100.21",
                RemotePort: 443,
                LocalPort: 5001);
            byte[] initialConnectionId = CreateConnectionId(0x20, 4);
            byte[] migratedConnectionId = CreateConnectionId((byte)(0x40 + sequenceNumber), 4);

            Assert.True(state.TryAcceptNewConnectionId(
                new QuicNewConnectionIdFrame(
                    sequenceNumber,
                    retirePriorTo: 0,
                    migratedConnectionId,
                    QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken((byte)(0x60 + sequenceNumber))),
                requiresZeroLengthDestinationConnectionId: false,
                activeConnectionIdLimit: 3,
                initialConnectionId,
                out QuicTransportErrorCode errorCode,
                out bool destinationConnectionIdChanged,
                out ulong[] retiredSequenceNumbers));
            Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
            Assert.False(destinationConnectionIdChanged);
            Assert.Empty(retiredSequenceNumbers);

            Assert.True(state.TryUseDestinationConnectionIdOnPath(
                originalPath,
                activeConnectionIdLimit: 3,
                retireInactivePathConnectionIds: false,
                out errorCode,
                out destinationConnectionIdChanged,
                out retiredSequenceNumbers));
            Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
            Assert.False(destinationConnectionIdChanged);
            Assert.True(initialConnectionId.AsSpan().SequenceEqual(state.CurrentDestinationConnectionId.Span));

            Assert.True(state.TryUseDestinationConnectionIdOnPath(
                migratedPath,
                activeConnectionIdLimit: 3,
                retireInactivePathConnectionIds: false,
                out errorCode,
                out destinationConnectionIdChanged,
                out retiredSequenceNumbers));
            Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
            Assert.True(destinationConnectionIdChanged);
            Assert.Empty(retiredSequenceNumbers);
            Assert.Equal(sequenceNumber, state.CurrentDestinationConnectionIdSequence);
            Assert.True(migratedConnectionId.AsSpan().SequenceEqual(state.CurrentDestinationConnectionId.Span));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0244")]
    [Requirement("REQ-QUIC-RFC9000-0245")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public async Task MigratedAddressPairConnectionIdFuzz_UsesANewConnectionIdAndRetiresTheAbandonedOne()
    {
        for (int iteration = 0; iteration < 3; iteration++)
        {
            using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
            QuicConnectionPathIdentity migratedPath = new(
                $"203.0.113.{80 + iteration}",
                $"198.51.100.{80 + iteration}",
                RemotePort: 443,
                LocalPort: 61240 + iteration);
            byte[] originalPairConnectionId = CreateConnectionId((byte)(0x80 + iteration), 4);
            byte[] migratedPairConnectionId = CreateConnectionId((byte)(0x90 + iteration), 4);

            await REQ_QUIC_RFC9000_0244.BindPeerConnectionIdToCurrentPath(runtime, originalPairConnectionId);
            _ = REQ_QUIC_RFC9000_0244.AddMigratedPathConnectionId(runtime, migratedPairConnectionId);

            QuicConnectionTransitionResult validationResult =
                REQ_QUIC_RFC9000_0244.PromoteMigratedPath(runtime, migratedPath);
            QuicConnectionSendDatagramEffect sendAfterMigration =
                await QuicPeerConnectionIdSelectionTestSupport.OpenOutboundStreamAndCaptureSingleSendAsync(runtime);

            Assert.Equal(migratedPath, sendAfterMigration.PathIdentity);
            Assert.Equal(migratedPairConnectionId, runtime.CurrentPeerDestinationConnectionId.ToArray());
            QuicPeerConnectionIdSelectionTestSupport.AssertApplicationDataDatagramOpensWithDestination(
                runtime,
                sendAfterMigration.Datagram,
                migratedPairConnectionId);
            Assert.Contains(1UL, QuicConnectionIdLifecycleTestSupport.GetRetiredSequenceNumbers(runtime, validationResult));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0247")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ActiveConnectionIdLimitFuzz_ClosesWhenNewIdsExceedProcessingCapacity()
    {
        for (int iteration = 0; iteration < 4; iteration++)
        {
            using QuicConnectionRuntime closingRuntime =
                QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();

            Assert.True(QuicConnectionIdLifecycleTestSupport.ProcessNewConnectionIdFrame(
                closingRuntime,
                sequenceNumber: 1,
                retirePriorTo: 0,
                connectionId: CreateConnectionId((byte)(0xA0 + iteration), 3),
                observedAtTicks: 9,
                statelessResetTokenStart: (byte)(0xA0 + iteration)).StateChanged);

            QuicConnectionTransitionResult closingResult = QuicConnectionIdLifecycleTestSupport.ProcessNewConnectionIdFrame(
                closingRuntime,
                sequenceNumber: 2,
                retirePriorTo: 0,
                connectionId: CreateConnectionId((byte)(0xB0 + iteration), 3),
                observedAtTicks: 10,
                statelessResetTokenStart: (byte)(0xB0 + iteration));

            Assert.True(closingResult.StateChanged);
            Assert.Equal(QuicConnectionPhase.Closing, closingRuntime.Phase);
            Assert.Equal(QuicTransportErrorCode.ConnectionIdLimitError, closingRuntime.TerminalState!.Value.Close.TransportErrorCode);

            using QuicConnectionRuntime activeRuntime =
                QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
            Assert.True(QuicConnectionIdLifecycleTestSupport.ProcessNewConnectionIdFrame(
                activeRuntime,
                sequenceNumber: 1,
                retirePriorTo: 0,
                connectionId: CreateConnectionId((byte)(0xC0 + iteration), 3),
                observedAtTicks: 9,
                statelessResetTokenStart: (byte)(0xC0 + iteration)).StateChanged);
            Assert.True(QuicConnectionIdLifecycleTestSupport.ProcessNewConnectionIdFrame(
                activeRuntime,
                sequenceNumber: 2,
                retirePriorTo: 1,
                connectionId: CreateConnectionId((byte)(0xD0 + iteration), 3),
                observedAtTicks: 10,
                statelessResetTokenStart: (byte)(0xD0 + iteration)).StateChanged);

            Assert.Equal(QuicConnectionPhase.Active, activeRuntime.Phase);
            Assert.Null(activeRuntime.TerminalState);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0255")]
    [Requirement("REQ-QUIC-RFC9000-0261")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ZeroLengthConnectionIdRoutingFuzz_RequiresMatchingLocalEndpoint()
    {
        for (int iteration = 0; iteration < 6; iteration++)
        {
            QuicConnectionPathIdentity registeredPath = new(
                RemoteAddress: $"203.0.113.{20 + iteration}",
                LocalAddress: $"192.0.2.{20 + iteration}",
                RemotePort: 44330 + iteration,
                LocalPort: 4433);
            QuicConnectionPathIdentity matchingLocalEndpoint = new(
                RemoteAddress: $"203.0.113.{80 + iteration}",
                LocalAddress: registeredPath.LocalAddress,
                RemotePort: 44400 + iteration,
                LocalPort: registeredPath.LocalPort);
            QuicConnectionPathIdentity mismatchedLocalEndpoint = new(
                RemoteAddress: matchingLocalEndpoint.RemoteAddress,
                LocalAddress: $"192.0.2.{80 + iteration}",
                RemotePort: matchingLocalEndpoint.RemotePort,
                LocalPort: matchingLocalEndpoint.LocalPort);
            var scenario = QuicS5P2PacketAssociationTestSupport.CreateRegisteredEndpoint(
                ReadOnlySpan<byte>.Empty,
                registeredPath);
            using QuicConnectionRuntime runtime = scenario.Runtime;
            using QuicConnectionRuntimeEndpoint endpoint = scenario.Endpoint;
            byte[] datagram = QuicS5P2PacketAssociationTestSupport.BuildShortHeaderDatagram(ReadOnlySpan<byte>.Empty);

            QuicConnectionIngressResult matchingResult = endpoint.ReceiveDatagram(datagram, matchingLocalEndpoint);
            Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, matchingResult.Disposition);
            Assert.Equal(scenario.Handle, matchingResult.Handle);

            QuicConnectionIngressResult mismatchedResult = endpoint.ReceiveDatagram(datagram, mismatchedLocalEndpoint);
            Assert.Equal(QuicConnectionIngressDisposition.Unroutable, mismatchedResult.Disposition);
            Assert.Null(mismatchedResult.Handle);
        }
    }

    private static byte[] CreateConnectionId(byte startValue, int length)
    {
        byte[] connectionId = new byte[length];
        for (int index = 0; index < connectionId.Length; index++)
        {
            connectionId[index] = unchecked((byte)(startValue + index));
        }

        return connectionId;
    }
}
