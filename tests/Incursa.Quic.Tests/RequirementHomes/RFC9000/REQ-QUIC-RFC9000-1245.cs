// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1245")]
public sealed class REQ_QUIC_RFC9000_1245
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientRuntimeRejectsOutboundNewTokenPayloadConstruction()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();

        Assert.False(runtime.TryBuildOutboundNewTokenPayload(
            QuicS19P7NewTokenFrameTestSupport.RepresentativeToken,
            out byte[] payload));
        Assert.Empty(payload);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerRuntimeCanBuildOutboundNewTokenPayload()
    {
        using QuicConnectionRuntime runtime = QuicS9P3TokenEmissionTestSupport.CreateServerRuntimeReadyForTokenEmission();

        Assert.True(runtime.TryBuildOutboundNewTokenPayload(
            QuicS19P7NewTokenFrameTestSupport.RepresentativeToken,
            out byte[] payload));
        Assert.True(QuicFrameCodec.TryParseNewTokenFrame(payload, out QuicNewTokenFrame parsed, out int bytesConsumed));
        Assert.True(QuicS19P7NewTokenFrameTestSupport.RepresentativeToken.AsSpan().SequenceEqual(parsed.Token));
        Assert.Equal(QuicS19P7NewTokenFrameTestSupport.RepresentativeToken.Length + 2, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ClientAddressValidationDoesNotEmitNewToken()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        QuicConnectionPathIdentity migratedPath = new("203.0.113.21", RemotePort: 443);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                migratedPath,
                datagram),
            nowTicks: 20).StateChanged);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            migratedPath,
            observedAtTicks: 30);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
        Assert.DoesNotContain(validationResult.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ClientNeverBuildsOutboundNewTokenWhileServerCanBuildRepresentativeTokens()
    {
        foreach (int tokenLength in new[] { 1, 2, 4, 16, 32 })
        {
            byte[] token = QuicS19P7NewTokenFrameTestSupport.CreateSequentialToken(tokenLength);
            using QuicConnectionRuntime clientRuntime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();

            Assert.False(clientRuntime.TryBuildOutboundNewTokenPayload(token, out byte[] clientPayload));
            Assert.Empty(clientPayload);

            using QuicConnectionRuntime serverRuntime = QuicS9P3TokenEmissionTestSupport.CreateServerRuntimeReadyForTokenEmission();
            Assert.True(serverRuntime.TryBuildOutboundNewTokenPayload(token, out byte[] serverPayload));
            Assert.True(QuicFrameCodec.TryParseNewTokenFrame(
                serverPayload,
                out QuicNewTokenFrame parsed,
                out int bytesConsumed));
            Assert.True(bytesConsumed <= serverPayload.Length);
            Assert.True(token.AsSpan().SequenceEqual(parsed.Token));
        }
    }
}
