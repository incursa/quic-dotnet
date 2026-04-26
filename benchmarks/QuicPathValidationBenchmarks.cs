using System.Net;
using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks representative path-validation helper and runtime retry paths.
/// </summary>
[MemoryDiagnoser]
public class QuicPathValidationBenchmarks
{
    private static readonly QuicConnectionPathIdentity ActivePath = new("203.0.113.150", RemotePort: 443);
    private static readonly QuicConnectionPathIdentity MigratedPath = new("203.0.113.151", RemotePort: 443);

    /// <summary>
    /// Measures generating and formatting a PATH_CHALLENGE frame.
    /// </summary>
    [Benchmark]
    public int GenerateAndFormatPathChallenge()
    {
        Span<byte> challengeData = stackalloc byte[QuicPathValidation.PathChallengeDataLength];
        Span<byte> destination = stackalloc byte[16];
        if (!QuicPathValidation.TryGeneratePathChallengeData(challengeData, out int challengeBytesWritten)
            || !QuicFrameCodec.TryFormatPathChallengeFrame(
                new QuicPathChallengeFrame(challengeData[..challengeBytesWritten]),
                destination,
                out int frameBytesWritten))
        {
            return -1;
        }

        return frameBytesWritten ^ challengeBytesWritten;
    }

    /// <summary>
    /// Measures formatting a PATH_RESPONSE frame that echoes an existing challenge payload.
    /// </summary>
    [Benchmark]
    public int FormatPathResponse()
    {
        Span<byte> challengeData =
        [
            0x10, 0x11, 0x12, 0x13,
            0x14, 0x15, 0x16, 0x17,
        ];
        Span<byte> destination = stackalloc byte[16];
        return QuicFrameCodec.TryFormatPathResponseFrame(
            new QuicPathResponseFrame(challengeData),
            destination,
            out int frameBytesWritten)
            ? frameBytesWritten
            : -1;
    }

    /// <summary>
    /// Measures starting candidate-path validation and retrying it on timer expiry.
    /// </summary>
    [Benchmark]
    public ulong StartAndRetryCandidatePathValidation()
    {
        using QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        QuicConnectionTransitionResult firstResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                MigratedPath,
                datagram),
            nowTicks: 10);

        if (!runtime.CandidatePaths.TryGetValue(MigratedPath, out QuicConnectionCandidatePathRecord candidatePath)
            || !candidatePath.Validation.ValidationDeadlineTicks.HasValue)
        {
            return 0;
        }

        long validationDeadlineTicks = candidatePath.Validation.ValidationDeadlineTicks.Value;
        ulong generation = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.PathValidation);

        QuicConnectionTransitionResult retryResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: validationDeadlineTicks,
                QuicConnectionTimerKind.PathValidation,
                generation),
            nowTicks: validationDeadlineTicks);

        return runtime.CandidatePaths.TryGetValue(MigratedPath, out QuicConnectionCandidatePathRecord retriedPath)
            ? retriedPath.Validation.ChallengeSendCount
                + (ulong)firstResult.Effects.Count()
                + (ulong)retryResult.Effects.Count()
            : 0;
    }

    /// <summary>
    /// Measures promoting a preferred-address path and switching the current destination connection ID to the preferred-address CID.
    /// </summary>
    [Benchmark]
    public int PromotePreferredAddressPathAndSelectDestinationConnectionId()
    {
        using QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();
        byte[] initialDestinationConnectionId = [0x10, 0x11, 0x12, 0x13];
        byte[] initialSourceConnectionId = [0x14, 0x15, 0x16, 0x17];
        QuicTransportParameters peerTransportParameters = CreatePreferredAddressTransportParameters(initialSourceConnectionId);
        QuicConnectionPathIdentity preferredPath = CreatePreferredAddressPath(peerTransportParameters);

        if (!runtime.TrySetHandshakeDestinationConnectionId(initialDestinationConnectionId))
        {
            throw new InvalidOperationException("Failed to prepare the benchmark handshake destination connection ID.");
        }

        if (!runtime.TrySetHandshakeSourceConnectionId(initialSourceConnectionId))
        {
            throw new InvalidOperationException("Failed to prepare the benchmark handshake source connection ID.");
        }

        CommitPeerTransportParameters(runtime, peerTransportParameters);

        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];
        if (!runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 10,
                    preferredPath,
                    datagram),
                nowTicks: 10).StateChanged)
        {
            throw new InvalidOperationException("Failed to start preferred-address validation in the benchmark.");
        }

        if (!runtime.Transition(
                new QuicConnectionPathValidationSucceededEvent(
                    ObservedAtTicks: 20,
                    preferredPath),
                nowTicks: 20).StateChanged)
        {
            throw new InvalidOperationException("Failed to promote the preferred-address path in the benchmark.");
        }

        return runtime.CurrentPeerDestinationConnectionId.Length;
    }

    private static QuicConnectionRuntime CreateRuntimeWithActivePath()
    {
        QuicConnectionRuntime runtime = new(
            CreateStreamState(),
            currentProbeTimeoutMicros: 1_000);

        if (!runtime.Transition(
                new QuicConnectionPeerHandshakeTranscriptCompletedEvent(ObservedAtTicks: 1),
                nowTicks: 1).StateChanged
            || !runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 2,
                    ActivePath,
                    new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
                nowTicks: 2).StateChanged
            || !runtime.ActivePath.HasValue)
        {
            runtime.Dispose();
            throw new InvalidOperationException("Failed to prepare the active path validation benchmark runtime.");
        }

        return runtime;
    }

    private static void CommitPeerTransportParameters(
        QuicConnectionRuntime runtime,
        QuicTransportParameters peerTransportParameters)
    {
        QuicTransportTlsBridgeState bridge = runtime.TlsState;

        if (!bridge.TryApply(new QuicTlsStateUpdate(
                QuicTlsUpdateKind.TranscriptProgressed,
                HandshakeMessageType: QuicTlsHandshakeMessageType.ServerHello,
                HandshakeMessageLength: 48,
                SelectedCipherSuite: QuicTlsCipherSuite.TlsAes128GcmSha256,
                TranscriptHashAlgorithm: QuicTlsTranscriptHashAlgorithm.Sha256,
                TranscriptPhase: QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage)))
        {
            throw new InvalidOperationException("Failed to apply benchmark ServerHello state.");
        }

        if (!bridge.TryApply(new QuicTlsStateUpdate(
                QuicTlsUpdateKind.TranscriptProgressed,
                HandshakeMessageType: QuicTlsHandshakeMessageType.EncryptedExtensions,
                HandshakeMessageLength: 48,
                TransportParameters: peerTransportParameters,
                TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)))
        {
            throw new InvalidOperationException("Failed to stage benchmark peer transport parameters.");
        }

        if (!bridge.TryApply(new QuicTlsStateUpdate(
                QuicTlsUpdateKind.TranscriptProgressed,
                HandshakeMessageType: QuicTlsHandshakeMessageType.CertificateVerify,
                HandshakeMessageLength: 48,
                TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)))
        {
            throw new InvalidOperationException("Failed to apply benchmark CertificateVerify state.");
        }

        if (!bridge.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificateVerifyVerified)))
        {
            throw new InvalidOperationException("Failed to apply benchmark certificate verification state.");
        }

        if (!bridge.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificatePolicyAccepted)))
        {
            throw new InvalidOperationException("Failed to accept benchmark certificate policy.");
        }

        if (!bridge.TryApply(new QuicTlsStateUpdate(
                QuicTlsUpdateKind.TranscriptProgressed,
                HandshakeMessageType: QuicTlsHandshakeMessageType.Finished,
                HandshakeMessageLength: 48,
                TranscriptPhase: QuicTlsTranscriptPhase.Completed)))
        {
            throw new InvalidOperationException("Failed to apply benchmark Finished state.");
        }

        if (!bridge.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerFinishedVerified)))
        {
            throw new InvalidOperationException("Failed to apply benchmark peer Finished state.");
        }

        if (!bridge.TryApply(new QuicTlsStateUpdate(
                QuicTlsUpdateKind.PeerTransportParametersCommitted,
                TransportParameters: peerTransportParameters)))
        {
            throw new InvalidOperationException("Failed to commit benchmark peer transport parameters.");
        }
    }

    private static QuicConnectionPathIdentity CreatePreferredAddressPath(QuicTransportParameters peerTransportParameters)
    {
        if (peerTransportParameters.PreferredAddress is not QuicPreferredAddress preferredAddress)
        {
            throw new InvalidOperationException("The benchmark preferred-address transport parameters were not populated.");
        }

        return new QuicConnectionPathIdentity(
            new IPAddress(preferredAddress.IPv4Address).ToString(),
            RemotePort: preferredAddress.IPv4Port);
    }

    private static QuicTransportParameters CreatePreferredAddressTransportParameters(ReadOnlySpan<byte> initialSourceConnectionId)
    {
        return new QuicTransportParameters
        {
            InitialSourceConnectionId = initialSourceConnectionId.ToArray(),
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = [198, 51, 100, 24],
                IPv4Port = 9444,
                IPv6Address =
                [
                    0x20, 0x01, 0x0D, 0xB8,
                    0x00, 0x01, 0x00, 0x02,
                    0x00, 0x03, 0x00, 0x04,
                    0x00, 0x05, 0x00, 0x18,
                ],
                IPv6Port = 9554,
                ConnectionId = [0x20, 0x21, 0x22, 0x23],
                StatelessResetToken =
                [
                    0x40, 0x41, 0x42, 0x43,
                    0x44, 0x45, 0x46, 0x47,
                    0x48, 0x49, 0x4A, 0x4B,
                    0x4C, 0x4D, 0x4E, 0x4F,
                ],
            },
        };
    }

    private static QuicConnectionStreamState CreateStreamState()
    {
        return new QuicConnectionStreamState(
            new QuicConnectionStreamStateOptions(
                IsServer: false,
                InitialConnectionReceiveLimit: 512,
                InitialConnectionSendLimit: 512,
                InitialIncomingBidirectionalStreamLimit: 4,
                InitialIncomingUnidirectionalStreamLimit: 4,
                InitialPeerBidirectionalStreamLimit: 4,
                InitialPeerUnidirectionalStreamLimit: 4,
                InitialLocalBidirectionalReceiveLimit: 128,
                InitialPeerBidirectionalReceiveLimit: 128,
                InitialPeerUnidirectionalReceiveLimit: 128,
                InitialLocalBidirectionalSendLimit: 128,
                InitialLocalUnidirectionalSendLimit: 128,
                InitialPeerBidirectionalSendLimit: 128));
    }
}
