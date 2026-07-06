// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_ConnectionId_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0316")]
    [Requirement("REQ-QUIC-RFC9000-0317")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ServerInitialSourceConnectionIdFuzz_AdoptsFirstValueAndIgnoresReplacementFlights()
    {
        for (int iteration = 0; iteration < 6; iteration++)
        {
            byte[] originalDestinationConnectionId = CreateConnectionId(0x10, iteration);
            byte[] clientSourceConnectionId = CreateConnectionId(0x20, iteration);
            byte[] firstServerSourceConnectionId = CreateConnectionId(0x30, iteration);
            byte[] replacementServerSourceConnectionId = CreateConnectionId(0x40, iteration);

            using QuicConnectionRuntime clientRuntime = QuicS7P2ServerConnectionIdTestSupport.CreateClientRuntime(
                originalDestinationConnectionId,
                clientSourceConnectionId);
            QuicConnectionSendDatagramEffect[] clientInitialDatagrams =
                QuicS7P2ServerConnectionIdTestSupport.BootstrapClient(clientRuntime, clientSourceConnectionId);
            ServerHandshakeFlight firstFlight = QuicS7P2ServerConnectionIdTestSupport.CreateServerHandshakeFlight(
                originalDestinationConnectionId,
                clientSourceConnectionId,
                firstServerSourceConnectionId,
                QuicS7P2ServerConnectionIdTestSupport.CreateScalar((byte)(0x50 + iteration)),
                clientInitialDatagrams);
            ServerHandshakeFlight replacementFlight = QuicS7P2ServerConnectionIdTestSupport.CreateServerHandshakeFlight(
                originalDestinationConnectionId,
                clientSourceConnectionId,
                replacementServerSourceConnectionId,
                QuicS7P2ServerConnectionIdTestSupport.CreateScalar((byte)(0x60 + iteration)),
                clientInitialDatagrams);

            Assert.True(QuicS7P2ServerConnectionIdTestSupport.ReceivePacket(
                clientRuntime,
                firstFlight.InitialPacket,
                observedAtTicks: 10 + iteration).StateChanged);

            Assert.Equal(firstServerSourceConnectionId, clientRuntime.CurrentPeerDestinationConnectionId.ToArray());
            Assert.True(
                clientRuntime.TlsState.TryGetHandshakeOpenPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial firstHandshakeMaterial));

            _ = QuicS7P2ServerConnectionIdTestSupport.ReceivePacket(
                clientRuntime,
                replacementFlight.InitialPacket,
                observedAtTicks: 20 + iteration);

            Assert.Equal(firstServerSourceConnectionId, clientRuntime.CurrentPeerDestinationConnectionId.ToArray());
            Assert.True(
                clientRuntime.TlsState.TryGetHandshakeOpenPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial retainedHandshakeMaterial));
            Assert.True(firstHandshakeMaterial.Matches(retainedHandshakeMaterial));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0316")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ZeroRttConnectionIdFuzz_UsesAdoptedServerSourceConnectionIdAsDestination()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            byte[] initialDestinationConnectionId = CreateConnectionId(0x70, iteration);
            byte[] clientSourceConnectionId = CreateConnectionId(0x80, iteration);
            byte[] serverSourceConnectionId = CreateConnectionId(0x90, iteration);

            byte[] zeroRttPacket = QuicS7P2ServerConnectionIdTestSupport.BuildZeroRttPacketAfterServerSourceConnectionIdAdoption(
                initialDestinationConnectionId,
                clientSourceConnectionId,
                serverSourceConnectionId);

            QuicS7P2ServerConnectionIdTestSupport.AssertLongHeaderConnectionIds(
                zeroRttPacket,
                serverSourceConnectionId,
                clientSourceConnectionId);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0332")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ZeroLengthInitialSourceConnectionIdFuzz_RoundTripsAndCommitsEmptyValue()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            QuicTransportParameters parsed = QuicS7P3ConnectionIdBindingTestSupport.FormatAndParse(
                new QuicTransportParameters
                {
                    InitialSourceConnectionId = [],
                    MaxIdleTimeout = (ulong)(30 + iteration),
                },
                QuicTransportParameterRole.Client,
                QuicTransportParameterRole.Server);

            Assert.NotNull(parsed.InitialSourceConnectionId);
            Assert.Empty(parsed.InitialSourceConnectionId!);

            QuicConnectionRuntime runtime = QuicS7P3ConnectionIdBindingTestSupport.CreateClientRuntimeForPeerTransportParameterCommit();
            QuicConnectionTransitionResult result =
                QuicS7P3ConnectionIdBindingTestSupport.CommitPeerTransportParametersThroughClientRuntime(
                    runtime,
                    new QuicTransportParameters
                    {
                        OriginalDestinationConnectionId = QuicS7P3ConnectionIdBindingTestSupport.InitialDestinationConnectionId,
                        InitialSourceConnectionId = parsed.InitialSourceConnectionId,
                    });

            Assert.True(result.StateChanged);
            Assert.Null(runtime.TerminalState);
            Assert.True(runtime.TlsState.PeerTransportParametersCommitted);
            Assert.Equal(0, runtime.CurrentPeerDestinationConnectionId.Length);
        }
    }

    private static byte[] CreateConnectionId(byte prefix, int iteration)
    {
        return
        [
            prefix,
            (byte)(prefix + 1),
            (byte)(prefix + 2),
            (byte)(prefix + 3 + iteration),
        ];
    }
}
