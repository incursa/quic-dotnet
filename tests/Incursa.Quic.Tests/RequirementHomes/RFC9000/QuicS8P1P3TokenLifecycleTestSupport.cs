// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

internal static class QuicS8P1P3TokenLifecycleTestSupport
{
    internal static readonly IPEndPoint ApplicableEndPoint = new(IPAddress.Parse("203.0.113.10"), 443);

    internal static readonly IPEndPoint OtherEndPoint = new(IPAddress.Parse("203.0.113.11"), 443);

    internal static readonly byte[] NewToken =
    [
        0xA0, 0xA1, 0xA2, 0xA3,
    ];

    internal static QuicClientAddressValidationToken CreateNewTokenFor(
        IPEndPoint? endpoint = null,
        uint version = QuicVersionNegotiation.Version1)
    {
        Assert.True(QuicClientAddressValidationToken.TryCreate(
            NewToken,
            endpoint ?? ApplicableEndPoint,
            version,
            QuicAddressValidationTokenSource.NewToken,
            out QuicClientAddressValidationToken? token));

        return token!;
    }

    internal static QuicClientConnectionSettings CaptureSettingsWith(
        QuicClientAddressValidationToken token,
        IPEndPoint? remoteEndPoint = null)
    {
        QuicClientConnectionOptions options = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            remoteEndPoint ?? ApplicableEndPoint);

        return QuicClientConnectionOptionsValidator.Capture(
            options,
            nameof(options),
            addressValidationToken: token);
    }

    internal static byte[][] BootstrapAndReadInitialTokens(ReadOnlyMemory<byte> token)
    {
        using QuicConnectionRuntime runtime = QuicS17P2P5P2TestSupport.CreateClientRuntime();
        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 0,
                LocalTransportParameters: QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters(
                    QuicS17P2P5P2TestSupport.InitialSourceConnectionId),
                InitialAddressValidationToken: token),
            nowTicks: 0);

        Assert.True(result.StateChanged);
        return ReadInitialTokens(result, QuicS17P2P5P2TestSupport.OriginalDestinationConnectionId);
    }

    internal static byte[][] ReadInitialTokens(
        QuicConnectionTransitionResult result,
        ReadOnlySpan<byte> initialDestinationConnectionId)
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            initialDestinationConnectionId,
            out QuicInitialPacketProtection serverProtection));

        List<byte[]> tokens = [];
        foreach (QuicConnectionSendDatagramEffect sendEffect in QuicS17P2P3TestSupport.GetInitialSendEffects(result.Effects))
        {
            QuicHandshakeFlowCoordinator coordinator = new();
            Assert.True(coordinator.TryOpenInitialPacket(
                sendEffect.Datagram.Span,
                serverProtection,
                out byte[] openedPacket,
                out _,
                out _));

            Assert.True(QuicPacketParsing.TryParseLongHeaderFields(
                openedPacket,
                out _,
                out _,
                out _,
                out _,
                out ReadOnlySpan<byte> versionSpecificData));

            Assert.True(QuicVariableLengthInteger.TryParse(
                versionSpecificData,
                out ulong tokenLength,
                out int tokenLengthBytesConsumed));
            Assert.True(tokenLength <= (ulong)(versionSpecificData.Length - tokenLengthBytesConsumed));

            tokens.Add(versionSpecificData.Slice(tokenLengthBytesConsumed, checked((int)tokenLength)).ToArray());
        }

        Assert.NotEmpty(tokens);
        return tokens.ToArray();
    }
}
