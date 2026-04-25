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
