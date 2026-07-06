// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S17-2-5-3-P2-S3-R01")]
public sealed class REQ_QUIC_RFC9000_1051
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequirementStatement_AllowsDiscardingDifferentHandshakeMessages()
    {
        string statement = QuicRfc9000RequirementSpecSupport.GetStatement("RFC9000-S17-2-5-3-P2-S3-R01");

        Assert.True(statement.Contains("MAY", StringComparison.Ordinal));
        Assert.True(statement.Contains("different cryptographic handshake message", StringComparison.Ordinal));
        Assert.True(statement.Contains("discard it", StringComparison.Ordinal));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerRuntimeDiscardsARetryReplayThatCarriesADifferentClientHello()
    {
        using QuicConnectionRuntime serverRuntime = CreateServerRuntime(QuicS17P2P5P2TestSupport.OriginalDestinationConnectionId);
        using QuicConnectionRuntime bootstrapRuntime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();

        byte[] bootstrapClientHelloBytes = QuicResumptionClientHelloTestSupport.GetInitialBootstrapClientHelloBytes(bootstrapRuntime);
        byte[] differentClientHelloBytes = new byte[bootstrapClientHelloBytes.Length];
        bootstrapClientHelloBytes.CopyTo(differentClientHelloBytes, 0);
        Assert.True(differentClientHelloBytes.Length > 38);
        differentClientHelloBytes[38] = 0xFF;

        QuicConnectionRetryReceivedEvent retryReceivedEvent = QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(1);
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            QuicS17P2P5P2TestSupport.OriginalDestinationConnectionId,
            out QuicInitialPacketProtection clientProtection));

        QuicHandshakeFlowCoordinator coordinator = new(
            QuicS17P2P5P2TestSupport.OriginalDestinationConnectionId,
            QuicS17P2P5P2TestSupport.InitialSourceConnectionId);
        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            differentClientHelloBytes,
            cryptoPayloadOffset: 0,
            retryReceivedEvent.RetrySourceConnectionId.Span,
            retryReceivedEvent.RetryToken.Span,
            clientProtection,
            out byte[] protectedPacket));

        QuicConnectionTransitionResult result = serverRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                new QuicConnectionPathIdentity("203.0.113.10", "198.51.100.20", 443, 12345),
                protectedPacket),
            nowTicks: 1);

        Assert.True(result.StateChanged);
        Assert.Null(serverRuntime.TerminalState);
        Assert.Empty(result.Effects);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    [Requirement("RFC9000-S17-2-5-3-P2-S3-R01")]
    public void ServerRuntimeFuzz_DiscardsRetryReplaysThatCarryDifferentClientHelloBytes()
    {
        byte[] bootstrapClientHelloBytes = QuicS17P2P5P2TestSupport.GetOriginalClientHelloBytes();
        Assert.True(bootstrapClientHelloBytes.Length > 64);

        int[] mutationOffsets =
        [
            38,
            bootstrapClientHelloBytes.Length / 2,
            bootstrapClientHelloBytes.Length - 2,
        ];

        foreach (int mutationOffset in mutationOffsets)
        {
            using QuicConnectionRuntime serverRuntime = CreateServerRuntime(QuicS17P2P5P2TestSupport.OriginalDestinationConnectionId);

            byte[] differentClientHelloBytes = new byte[bootstrapClientHelloBytes.Length];
            bootstrapClientHelloBytes.CopyTo(differentClientHelloBytes, 0);
            differentClientHelloBytes[mutationOffset] ^= 0x7F;

            QuicConnectionTransitionResult result = serverRuntime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: mutationOffset,
                    new QuicConnectionPathIdentity("203.0.113.10", "198.51.100.20", 443, 12345),
                    BuildProtectedRetryReplayInitialPacket(differentClientHelloBytes)),
                nowTicks: mutationOffset);

            Assert.True(result.StateChanged);
            Assert.Null(serverRuntime.TerminalState);
            Assert.Empty(result.Effects);
        }
    }

    private static QuicConnectionRuntime CreateServerRuntime(ReadOnlySpan<byte> initialDestinationConnectionId)
    {
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Server);

        Assert.True(runtime.TryConfigureInitialPacketProtection(initialDestinationConnectionId));
        return runtime;
    }

    private static byte[] BuildProtectedRetryReplayInitialPacket(ReadOnlySpan<byte> clientHelloBytes)
    {
        QuicConnectionRetryReceivedEvent retryReceivedEvent = QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(1);
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            QuicS17P2P5P2TestSupport.OriginalDestinationConnectionId,
            out QuicInitialPacketProtection clientProtection));

        QuicHandshakeFlowCoordinator coordinator = new(
            QuicS17P2P5P2TestSupport.OriginalDestinationConnectionId,
            QuicS17P2P5P2TestSupport.InitialSourceConnectionId);
        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            clientHelloBytes,
            cryptoPayloadOffset: 0,
            retryReceivedEvent.RetrySourceConnectionId.Span,
            retryReceivedEvent.RetryToken.Span,
            clientProtection,
            out byte[] protectedPacket));

        return protectedPacket;
    }
}
