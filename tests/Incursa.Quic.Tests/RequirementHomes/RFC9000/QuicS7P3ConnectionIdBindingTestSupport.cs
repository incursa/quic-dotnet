// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

internal static class QuicS7P3ConnectionIdBindingTestSupport
{
    internal static readonly byte[] InitialDestinationConnectionId = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
    internal static readonly byte[] ClientInitialSourceConnectionId = [0x20, 0x21];
    internal static readonly byte[] ServerInitialSourceConnectionId = [0x30, 0x31, 0x32];
    internal static readonly byte[] RetrySourceConnectionId = [0x40, 0x41, 0x42, 0x43];

    internal static QuicTransportParameters FormatAndParse(
        QuicTransportParameters parameters,
        QuicTransportParameterRole senderRole,
        QuicTransportParameterRole receiverRole)
    {
        Span<byte> destination = stackalloc byte[256];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            senderRole,
            destination,
            out int bytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            receiverRole,
            out QuicTransportParameters parsed));

        return parsed;
    }

    internal static QuicConnectionRuntime CreateClientRuntimeForPeerTransportParameterCommit()
    {
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0),
            currentProbeTimeoutMicros: 1);

        Assert.True(runtime.TryConfigureInitialPacketProtection(InitialDestinationConnectionId));
        return runtime;
    }

    internal static QuicConnectionTransitionResult CommitPeerTransportParametersThroughClientRuntime(
        QuicConnectionRuntime runtime,
        QuicTransportParameters peerParameters)
    {
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 1,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.TranscriptProgressed,
                    HandshakeMessageType: QuicTlsHandshakeMessageType.ServerHello,
                    HandshakeMessageLength: 48,
                    SelectedCipherSuite: QuicTlsCipherSuite.TlsAes128GcmSha256,
                    TranscriptHashAlgorithm: QuicTlsTranscriptHashAlgorithm.Sha256,
                    TranscriptPhase: QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage)),
            nowTicks: 1).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 2,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.TranscriptProgressed,
                    HandshakeMessageType: QuicTlsHandshakeMessageType.EncryptedExtensions,
                    HandshakeMessageLength: 48,
                    TransportParameters: peerParameters,
                    TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)),
            nowTicks: 2).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 3,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.TranscriptProgressed,
                    HandshakeMessageType: QuicTlsHandshakeMessageType.CertificateVerify,
                    HandshakeMessageLength: 48,
                    TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)),
            nowTicks: 3).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 4,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificateVerifyVerified)),
            nowTicks: 4).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 5,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificatePolicyAccepted)),
            nowTicks: 5).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 6,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.TranscriptProgressed,
                    HandshakeMessageType: QuicTlsHandshakeMessageType.Finished,
                    HandshakeMessageLength: 48,
                    TranscriptPhase: QuicTlsTranscriptPhase.Completed)),
            nowTicks: 6).StateChanged);

        return runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 7,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerFinishedVerified)),
            nowTicks: 7);
    }

    internal static void AssertTransportParameterErrorClose(QuicConnectionRuntime runtime)
    {
        Assert.NotNull(runtime.TerminalState);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState!.Value.Origin);
        Assert.Equal(QuicTransportErrorCode.TransportParameterError, runtime.TerminalState.Value.Close.TransportErrorCode);
    }
}
