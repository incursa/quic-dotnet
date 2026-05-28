// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

/// <summary>
/// Severity for transport-visible diagnostics.
/// </summary>
internal enum QuicDiagnosticSeverity
{
    Trace = 0,
    Info = 1,
    Warning = 2,
    Error = 3,
}

/// <summary>
/// Stable transport diagnostic kinds understood by the core transport layer.
/// </summary>
internal enum QuicDiagnosticKind
{
    Unknown = 0,
    InitialPacketReceived = 1,
    InitialPacketOpenFailed = 2,
    InitialPacketAdvanced = 3,
    InitialPacketNotAdvanced = 4,
    HandshakePacketOpenFailed = 5,
    InitialTranscriptAdvanced = 6,
    HandshakeTranscriptAdvanced = 7,
    PathValidationFailedNoValidatedPathsRemain = 8,
    PathValidationTimerExpiredNoValidatedPathsRemain = 9,
    AcceptedStatelessReset = 10,
    AddressChangeClassified = 11,
    CandidatePathBudgetExhausted = 12,
    InitialPacketSent = 13,
    RetryReceived = 14,
    VersionNegotiationReceived = 15,
    HandshakePacketReceived = 16,
    HandshakePacketSent = 17,
    VersionNegotiationSent = 18,
    PeerHandshakeTranscriptCompleted = 19,
    SocketDatagramReceived = 20,
    ListenerIngressClassified = 21,
    ListenerPreAcceptanceClassified = 22,
    ListenerInitialAdmissionResult = 23,
    FlowControlBlocked = 24,
    StreamLimitBlocked = 25,
    PacketHeaderObserved = 26,
    CoalescedDatagramReceived = 27,
    ConnectionIdIssued = 28,
    ConnectionIdRetired = 29,
    ConnectionIdUsedOnPath = 30,
    PathValidationChallengeSent = 31,
    PathValidationSucceeded = 32,
    PathValidationFailed = 33,
    PathValidationTimedOut = 34,
    PathPromoted = 35,
    SpinBitUpdated = 36,
    IcmpPacketTooBigReceived = 37,
    PmtuUpdated = 38,
    ConnectionCloseStateChanged = 39,
    UdpReceiveError = 40,
    UdpSendError = 41,
    AntiAmplificationBlocked = 42,
}

/// <summary>
/// A structured diagnostic event emitted by the transport.
/// </summary>
/// <param name="Category">The stable transport category for the event.</param>
/// <param name="Name">The stable transport event name.</param>
/// <param name="Message">A human-readable summary.</param>
/// <param name="Severity">The event severity.</param>
internal readonly record struct QuicDiagnosticEvent(
    string Category,
    string Name,
    string Message,
    QuicDiagnosticSeverity Severity = QuicDiagnosticSeverity.Info)
{
    /// <summary>
    /// Gets the stable transport kind for the diagnostic event.
    /// </summary>
    public QuicDiagnosticKind Kind => InferKind(Category, Name);

    /// <summary>
    /// Gets the path identity associated with the diagnostic, if any.
    /// </summary>
    public QuicConnectionPathIdentity? PathIdentity { get; init; }

    /// <summary>
    /// Gets the path classification associated with the diagnostic, if any.
    /// </summary>
    public QuicConnectionPathClassification? PathClassification { get; init; }

    /// <summary>
    /// Gets the TLS encryption level associated with the diagnostic, if any.
    /// </summary>
    public QuicTlsEncryptionLevel? EncryptionLevel { get; init; }

    /// <summary>
    /// Gets the number of TLS transcript updates associated with the diagnostic, if any.
    /// </summary>
    public int? TranscriptUpdateCount { get; init; }

    /// <summary>
    /// Gets the connection ID associated with the diagnostic, if any.
    /// </summary>
    public ulong? ConnectionId { get; init; }

    /// <summary>
    /// Gets the packet bytes associated with the diagnostic, if any.
    /// </summary>
    public ReadOnlyMemory<byte> PacketBytes { get; init; }

    /// <summary>
    /// Gets the received UDP datagram length associated with the diagnostic, if any.
    /// </summary>
    public int? DatagramLength { get; init; }

    /// <summary>
    /// Gets the listener endpoint ingress disposition associated with the diagnostic, if any.
    /// </summary>
    public QuicConnectionIngressDisposition? IngressDisposition { get; init; }

    /// <summary>
    /// Gets the listener endpoint handling kind associated with the diagnostic, if any.
    /// </summary>
    public QuicConnectionEndpointHandlingKind? EndpointHandlingKind { get; init; }

    /// <summary>
    /// Gets the listener pre-acceptance action associated with the diagnostic, if any.
    /// </summary>
    public QuicListenerPreAcceptanceDatagramAction? PreAcceptanceAction { get; init; }

    /// <summary>
    /// Gets the Initial admission stage associated with the diagnostic, if any.
    /// </summary>
    public string? AdmissionStage { get; init; }

    /// <summary>
    /// Gets the Initial admission reason associated with the diagnostic, if any.
    /// </summary>
    public string? Reason { get; init; }

    /// <summary>
    /// Gets whether the diagnostic operation succeeded, if any.
    /// </summary>
    public bool? Succeeded { get; init; }

    /// <summary>
    /// Gets the affected stream identifier associated with the diagnostic, if any.
    /// </summary>
    public ulong? StreamId { get; init; }

    /// <summary>
    /// Gets whether the diagnostic applies to bidirectional streams, if any.
    /// </summary>
    public bool? IsBidirectionalStream { get; init; }

    /// <summary>
    /// Gets the flow-control or stream-limit value associated with the diagnostic, if any.
    /// </summary>
    public ulong? Limit { get; init; }

    /// <summary>
    /// Gets the observed QUIC header form, if any.
    /// </summary>
    public QuicHeaderForm? HeaderForm { get; init; }

    /// <summary>
    /// Gets the observed QUIC packet type, if any.
    /// </summary>
    public string? PacketType { get; init; }

    /// <summary>
    /// Gets the zero-based packet index within a UDP datagram, if any.
    /// </summary>
    public int? PacketIndex { get; init; }

    /// <summary>
    /// Gets the byte offset of the packet within a UDP datagram, if any.
    /// </summary>
    public int? PacketOffset { get; init; }

    /// <summary>
    /// Gets the number of QUIC packets split from a UDP datagram, if any.
    /// </summary>
    public int? PacketCount { get; init; }

    /// <summary>
    /// Gets whether a boolean state is set, if any.
    /// </summary>
    public bool? IsSet { get; init; }

    /// <summary>
    /// Gets whether a diagnostic condition was accepted by the transport, if any.
    /// </summary>
    public bool? Accepted { get; init; }

    /// <summary>
    /// Gets a datagram size associated with the diagnostic, if any.
    /// </summary>
    public ulong? MaximumDatagramSizeBytes { get; init; }

    /// <summary>
    /// Gets whether a path MTU value is provisional, if any.
    /// </summary>
    public bool? IsProvisional { get; init; }

    /// <summary>
    /// Gets a path-validation probe send count, if any.
    /// </summary>
    public ulong? ChallengeSendCount { get; init; }

    /// <summary>
    /// Gets the connection close origin associated with the diagnostic, if any.
    /// </summary>
    public QuicConnectionCloseOrigin? CloseOrigin { get; init; }

    /// <summary>
    /// Gets the connection phase associated with the diagnostic, if any.
    /// </summary>
    public QuicConnectionPhase? ConnectionPhase { get; init; }

    /// <summary>
    /// Gets the socket error name associated with the diagnostic, if any.
    /// </summary>
    public string? SocketErrorName { get; init; }

    /// <summary>
    /// Gets the socket error code associated with the diagnostic, if any.
    /// </summary>
    public int? SocketErrorCode { get; init; }

    /// <summary>
    /// Gets a byte count associated with an attempted operation, if any.
    /// </summary>
    public ulong? AttemptedBytes { get; init; }

    /// <summary>
    /// Gets the remaining anti-amplification send budget, if any.
    /// </summary>
    public ulong? RemainingSendBudget { get; init; }

    private static QuicDiagnosticKind InferKind(string category, string name)
    {
        return (category, name) switch
        {
            ("connection.runtime.handshake", "initial-packet-received") => QuicDiagnosticKind.InitialPacketReceived,
            ("connection.runtime.handshake", "initial-packet-open-failed") => QuicDiagnosticKind.InitialPacketOpenFailed,
            ("connection.runtime.handshake", "initial-packet-advanced") => QuicDiagnosticKind.InitialPacketAdvanced,
            ("connection.runtime.handshake", "initial-packet-not-advanced") => QuicDiagnosticKind.InitialPacketNotAdvanced,
            ("connection.runtime.handshake", "handshake-packet-open-failed") => QuicDiagnosticKind.HandshakePacketOpenFailed,
            ("connection.runtime.handshake", "initial-transcript-advanced") => QuicDiagnosticKind.InitialTranscriptAdvanced,
            ("connection.runtime.handshake", "handshake-transcript-advanced") => QuicDiagnosticKind.HandshakeTranscriptAdvanced,
            ("connection.runtime.handshake", "initial-packet-sent") => QuicDiagnosticKind.InitialPacketSent,
            ("connection.runtime.handshake", "retry-received") => QuicDiagnosticKind.RetryReceived,
            ("connection.runtime.handshake", "version-negotiation-received") => QuicDiagnosticKind.VersionNegotiationReceived,
            ("connection.runtime.handshake", "version-negotiation-sent") => QuicDiagnosticKind.VersionNegotiationSent,
            ("connection.runtime.handshake", "handshake-packet-received") => QuicDiagnosticKind.HandshakePacketReceived,
            ("connection.runtime.handshake", "handshake-packet-sent") => QuicDiagnosticKind.HandshakePacketSent,
            ("connection.runtime.handshake", "peer-handshake-transcript-completed") => QuicDiagnosticKind.PeerHandshakeTranscriptCompleted,
            ("connection.socket", "datagram-received") => QuicDiagnosticKind.SocketDatagramReceived,
            ("connection.listener", "ingress-classified") => QuicDiagnosticKind.ListenerIngressClassified,
            ("connection.listener", "pre-acceptance-classified") => QuicDiagnosticKind.ListenerPreAcceptanceClassified,
            ("connection.listener", "initial-admission-result") => QuicDiagnosticKind.ListenerInitialAdmissionResult,
            ("connection.runtime.flow-control", "blocked") => QuicDiagnosticKind.FlowControlBlocked,
            ("connection.runtime.streams", "limit-blocked") => QuicDiagnosticKind.StreamLimitBlocked,
            ("connection.runtime.packet", "header-observed") => QuicDiagnosticKind.PacketHeaderObserved,
            ("connection.runtime.packet", "coalesced-datagram-received") => QuicDiagnosticKind.CoalescedDatagramReceived,
            ("connection.runtime.connection-id", "issued") => QuicDiagnosticKind.ConnectionIdIssued,
            ("connection.runtime.connection-id", "retired") => QuicDiagnosticKind.ConnectionIdRetired,
            ("connection.runtime.connection-id", "used-on-path") => QuicDiagnosticKind.ConnectionIdUsedOnPath,
            ("connection.runtime.path", "path-validation-challenge-sent") => QuicDiagnosticKind.PathValidationChallengeSent,
            ("connection.runtime.path", "path-validation-succeeded") => QuicDiagnosticKind.PathValidationSucceeded,
            ("connection.runtime.path", "path-validation-failed") => QuicDiagnosticKind.PathValidationFailed,
            ("connection.runtime.path", "path-validation-timed-out") => QuicDiagnosticKind.PathValidationTimedOut,
            ("connection.runtime.path", "promoted") => QuicDiagnosticKind.PathPromoted,
            ("connection.runtime.path", "spin-bit-updated") => QuicDiagnosticKind.SpinBitUpdated,
            ("connection.runtime.path", "icmp-packet-too-big-received") => QuicDiagnosticKind.IcmpPacketTooBigReceived,
            ("connection.runtime.path", "pmtu-updated") => QuicDiagnosticKind.PmtuUpdated,
            ("connection.runtime.lifecycle", "connection-close-state-changed") => QuicDiagnosticKind.ConnectionCloseStateChanged,
            ("connection.socket", "udp-receive-error") => QuicDiagnosticKind.UdpReceiveError,
            ("connection.socket", "udp-send-error") => QuicDiagnosticKind.UdpSendError,
            ("connection.runtime.path", "anti-amplification-blocked") => QuicDiagnosticKind.AntiAmplificationBlocked,
            ("connection.runtime.path", "validated-paths-exhausted") => QuicDiagnosticKind.PathValidationFailedNoValidatedPathsRemain,
            ("connection.runtime.path", "path-validation-timer-exhausted") => QuicDiagnosticKind.PathValidationTimerExpiredNoValidatedPathsRemain,
            ("connection.runtime.lifecycle", "accepted-stateless-reset") => QuicDiagnosticKind.AcceptedStatelessReset,
            ("connection.runtime.path", "address-change-classified") => QuicDiagnosticKind.AddressChangeClassified,
            ("connection.runtime.path", "classified") => QuicDiagnosticKind.AddressChangeClassified,
            ("connection.runtime.path", "candidate-path-budget-exhausted") => QuicDiagnosticKind.CandidatePathBudgetExhausted,
            _ => QuicDiagnosticKind.Unknown,
        };
    }
}

/// <summary>
/// Accepts transport-visible diagnostic events.
/// </summary>
internal interface IQuicDiagnosticsSink
{
    /// <summary>
    /// Gets a value indicating whether the sink is enabled.
    /// </summary>
    bool IsEnabled { get; }

    /// <summary>
    /// Emits one diagnostic event.
    /// </summary>
    /// <param name="diagnosticEvent">The event to emit.</param>
    void Emit(QuicDiagnosticEvent diagnosticEvent);
}

/// <summary>
/// Diagnostics helpers used by the core transport.
/// </summary>
internal static class QuicDiagnostics
{
    private const int MinimumCoalescedPacketCount = 2;

    /// <summary>
    /// Resolves the diagnostics sink for a single connection.
    /// </summary>
    /// <param name="diagnosticsSink">An optional caller-supplied sink.</param>
    /// <returns>The caller-supplied sink, or the null sink when diagnostics are disabled.</returns>
    internal static IQuicDiagnosticsSink ResolveConnectionSink(IQuicDiagnosticsSink? diagnosticsSink = null)
    {
        return diagnosticsSink ?? QuicNullDiagnosticsSink.Instance;
    }

    internal static QuicDiagnosticEvent InitialPacketReceived(
        QuicConnectionPathIdentity pathIdentity,
        ReadOnlySpan<byte> packetBytes = default)
    {
        return new QuicDiagnosticEvent(
            "connection.runtime.handshake",
            "initial-packet-received",
            $"Initial packet reached the runtime on {DescribePath(pathIdentity)}.",
            QuicDiagnosticSeverity.Trace)
        {
            PathIdentity = pathIdentity,
            PacketBytes = packetBytes.ToArray(),
        };
    }

    internal static QuicDiagnosticEvent SocketDatagramReceived(
        QuicConnectionPathIdentity pathIdentity,
        int datagramLength)
    {
        if (datagramLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(datagramLength));
        }

        return new QuicDiagnosticEvent(
            "connection.socket",
            "datagram-received",
            $"UDP datagram of {datagramLength} bytes was received from {DescribePath(pathIdentity)}.",
            QuicDiagnosticSeverity.Trace)
        {
            PathIdentity = pathIdentity,
            DatagramLength = datagramLength,
        };
    }

    internal static QuicDiagnosticEvent ListenerIngressClassified(
        QuicConnectionPathIdentity pathIdentity,
        QuicConnectionIngressResult ingressResult)
    {
        return new QuicDiagnosticEvent(
            "connection.listener",
            "ingress-classified",
            $"Listener endpoint classified datagram from {DescribePath(pathIdentity)} as {ingressResult.Disposition}/{ingressResult.HandlingKind}.",
            QuicDiagnosticSeverity.Trace)
        {
            PathIdentity = pathIdentity,
            IngressDisposition = ingressResult.Disposition,
            EndpointHandlingKind = ingressResult.HandlingKind,
        };
    }

    internal static QuicDiagnosticEvent ListenerPreAcceptanceClassified(
        QuicConnectionPathIdentity pathIdentity,
        QuicListenerPreAcceptanceDatagramAction action)
    {
        return new QuicDiagnosticEvent(
            "connection.listener",
            "pre-acceptance-classified",
            $"Listener pre-acceptance classified datagram from {DescribePath(pathIdentity)} as {action}.",
            QuicDiagnosticSeverity.Trace)
        {
            PathIdentity = pathIdentity,
            PreAcceptanceAction = action,
        };
    }

    internal static QuicDiagnosticEvent ListenerInitialAdmissionResult(
        QuicConnectionPathIdentity pathIdentity,
        string stage,
        bool succeeded,
        string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(stage);
        ArgumentNullException.ThrowIfNull(reason);

        return new QuicDiagnosticEvent(
            "connection.listener",
            "initial-admission-result",
            $"Listener Initial admission stage '{stage}' {(succeeded ? "succeeded" : "failed")} for {DescribePath(pathIdentity)}: {reason}.",
            succeeded ? QuicDiagnosticSeverity.Info : QuicDiagnosticSeverity.Warning)
        {
            PathIdentity = pathIdentity,
            AdmissionStage = stage,
            Reason = reason,
            Succeeded = succeeded,
        };
    }

    internal static QuicDiagnosticEvent InitialPacketOpenFailed(
        QuicConnectionPathIdentity pathIdentity,
        ReadOnlySpan<byte> packetBytes = default)
    {
        return new QuicDiagnosticEvent(
            "connection.runtime.handshake",
            "initial-packet-open-failed",
            "Initial packet could not be opened or parsed by the runtime.",
            QuicDiagnosticSeverity.Warning)
        {
            PathIdentity = pathIdentity,
            PacketBytes = packetBytes.ToArray(),
        };
    }

    internal static QuicDiagnosticEvent InitialPacketProcessingResult(bool processed)
    {
        return new QuicDiagnosticEvent(
            "connection.runtime.handshake",
            processed ? "initial-packet-advanced" : "initial-packet-not-advanced",
            processed
                ? "Initial packet payload advanced the TLS bridge."
                : "Initial packet payload did not advance the TLS bridge.",
            processed ? QuicDiagnosticSeverity.Info : QuicDiagnosticSeverity.Warning);
    }

    internal static QuicDiagnosticEvent InitialPacketSent(
        QuicConnectionPathIdentity pathIdentity,
        ReadOnlySpan<byte> packetBytes = default)
    {
        return new QuicDiagnosticEvent(
            "connection.runtime.handshake",
            "initial-packet-sent",
            $"Initial packet was queued for send on {DescribePath(pathIdentity)}.",
            QuicDiagnosticSeverity.Trace)
        {
            PathIdentity = pathIdentity,
            PacketBytes = packetBytes.ToArray(),
        };
    }

    internal static QuicDiagnosticEvent RetryReceived(ReadOnlySpan<byte> packetBytes = default)
    {
        return new QuicDiagnosticEvent(
            "connection.runtime.handshake",
            "retry-received",
            "Retry packet was received from the peer.",
            QuicDiagnosticSeverity.Trace)
        {
            PacketBytes = packetBytes.ToArray(),
        };
    }

    internal static QuicDiagnosticEvent VersionNegotiationReceived(ReadOnlySpan<byte> packetBytes = default)
    {
        return new QuicDiagnosticEvent(
            "connection.runtime.handshake",
            "version-negotiation-received",
            "Version Negotiation packet was received from the peer.",
            QuicDiagnosticSeverity.Trace)
        {
            PacketBytes = packetBytes.ToArray(),
        };
    }

    internal static QuicDiagnosticEvent VersionNegotiationSent(
        QuicConnectionPathIdentity pathIdentity,
        ReadOnlySpan<byte> packetBytes = default)
    {
        return new QuicDiagnosticEvent(
            "connection.runtime.handshake",
            "version-negotiation-sent",
            "Version Negotiation packet was sent to the peer.",
            QuicDiagnosticSeverity.Trace)
        {
            PathIdentity = pathIdentity,
            PacketBytes = packetBytes.ToArray(),
        };
    }

    internal static QuicDiagnosticEvent HandshakePacketOpenFailed(
        QuicConnectionPathIdentity pathIdentity,
        string reason,
        ReadOnlySpan<byte> packetBytes = default)
    {
        return new QuicDiagnosticEvent(
            "connection.runtime.handshake",
            "handshake-packet-open-failed",
            $"Handshake packet could not be opened or parsed by the runtime: {reason}.",
            QuicDiagnosticSeverity.Warning)
        {
            PathIdentity = pathIdentity,
            PacketBytes = packetBytes.ToArray(),
        };
    }

    internal static QuicDiagnosticEvent HandshakePacketReceived(
        QuicConnectionPathIdentity pathIdentity,
        ReadOnlySpan<byte> packetBytes = default)
    {
        return new QuicDiagnosticEvent(
            "connection.runtime.handshake",
            "handshake-packet-received",
            $"Handshake packet reached the runtime on {DescribePath(pathIdentity)}.",
            QuicDiagnosticSeverity.Trace)
        {
            PathIdentity = pathIdentity,
            PacketBytes = packetBytes.ToArray(),
        };
    }

    internal static QuicDiagnosticEvent HandshakePacketSent(
        QuicConnectionPathIdentity pathIdentity,
        ReadOnlySpan<byte> packetBytes = default)
    {
        return new QuicDiagnosticEvent(
            "connection.runtime.handshake",
            "handshake-packet-sent",
            $"Handshake packet was queued for send on {DescribePath(pathIdentity)}.",
            QuicDiagnosticSeverity.Trace)
        {
            PathIdentity = pathIdentity,
            PacketBytes = packetBytes.ToArray(),
        };
    }

    internal static QuicDiagnosticEvent TranscriptAdvanced(QuicTlsEncryptionLevel encryptionLevel, int transcriptUpdateCount)
    {
        return new QuicDiagnosticEvent(
            "connection.runtime.handshake",
            encryptionLevel == QuicTlsEncryptionLevel.Initial
                ? "initial-transcript-advanced"
                : "handshake-transcript-advanced",
            $"Handshake transcript advancement for {encryptionLevel} produced {transcriptUpdateCount} TLS updates.",
            QuicDiagnosticSeverity.Trace)
            {
            EncryptionLevel = encryptionLevel,
            TranscriptUpdateCount = transcriptUpdateCount,
        };
    }

    internal static QuicDiagnosticEvent PeerHandshakeTranscriptCompleted()
    {
        return new QuicDiagnosticEvent(
            "connection.runtime.handshake",
            "peer-handshake-transcript-completed",
            "Peer handshake transcript completed.",
            QuicDiagnosticSeverity.Trace);
    }

    internal static QuicDiagnosticEvent PathValidationFailedNoValidatedPathsRemain(QuicConnectionPathIdentity pathIdentity)
    {
        return new QuicDiagnosticEvent(
            "connection.runtime.path",
            "validated-paths-exhausted",
            $"No validated paths remain after path validation failed for {pathIdentity.RemoteAddress}.",
            QuicDiagnosticSeverity.Warning)
        {
            PathIdentity = pathIdentity,
        };
    }

    internal static QuicDiagnosticEvent PathValidationTimerExpiredNoValidatedPathsRemain()
    {
        return new QuicDiagnosticEvent(
            "connection.runtime.path",
            "path-validation-timer-exhausted",
            "No validated paths remain after a path-validation timer expired.",
            QuicDiagnosticSeverity.Warning);
    }

    internal static QuicDiagnosticEvent AcceptedStatelessReset(QuicConnectionPathIdentity pathIdentity, ulong connectionId)
    {
        return new QuicDiagnosticEvent(
            "connection.runtime.lifecycle",
            "accepted-stateless-reset",
            $"Accepted a stateless reset on {DescribePath(pathIdentity)} for connection ID {connectionId}.",
            QuicDiagnosticSeverity.Info)
        {
            PathIdentity = pathIdentity,
            ConnectionId = connectionId,
        };
    }

    internal static QuicDiagnosticEvent AddressChangeClassified(
        QuicConnectionPathIdentity pathIdentity,
        QuicConnectionPathClassification classification)
    {
        return new QuicDiagnosticEvent(
            "connection.runtime.path",
            "address-change-classified",
            $"Packet from {pathIdentity.RemoteAddress} classified as {classification}.",
            QuicDiagnosticSeverity.Info)
        {
            PathIdentity = pathIdentity,
            PathClassification = classification,
        };
    }

    internal static QuicDiagnosticEvent CandidatePathBudgetExhausted(QuicConnectionPathIdentity pathIdentity)
    {
        return new QuicDiagnosticEvent(
            "connection.runtime.path",
            "candidate-path-budget-exhausted",
            $"Packet from {pathIdentity.RemoteAddress} classified as {QuicConnectionPathClassification.NoiseOrAttack} because the candidate-path budget is exhausted.",
            QuicDiagnosticSeverity.Warning)
        {
            PathIdentity = pathIdentity,
            PathClassification = QuicConnectionPathClassification.NoiseOrAttack,
        };
    }

    internal static QuicDiagnosticEvent FlowControlBlocked(QuicDataBlockedFrame frame)
    {
        return new QuicDiagnosticEvent(
            "connection.runtime.flow-control",
            "blocked",
            $"Application stream data is blocked by the connection flow-control limit {frame.MaximumData}.",
            QuicDiagnosticSeverity.Info)
        {
            Limit = frame.MaximumData,
        };
    }

    internal static QuicDiagnosticEvent FlowControlBlocked(QuicStreamDataBlockedFrame frame)
    {
        return new QuicDiagnosticEvent(
            "connection.runtime.flow-control",
            "blocked",
            $"Application stream {frame.StreamId} data is blocked by the stream flow-control limit {frame.MaximumStreamData}.",
            QuicDiagnosticSeverity.Info)
        {
            StreamId = frame.StreamId,
            Limit = frame.MaximumStreamData,
        };
    }

    internal static QuicDiagnosticEvent StreamLimitBlocked(QuicStreamsBlockedFrame frame)
    {
        return new QuicDiagnosticEvent(
            "connection.runtime.streams",
            "limit-blocked",
            $"{(frame.IsBidirectional ? "Bidirectional" : "Unidirectional")} stream opening is blocked by the peer stream limit {frame.MaximumStreams}.",
            QuicDiagnosticSeverity.Info)
        {
            IsBidirectionalStream = frame.IsBidirectional,
            Limit = frame.MaximumStreams,
        };
    }

    internal static QuicDiagnosticEvent PacketHeaderObserved(
        QuicConnectionPathIdentity pathIdentity,
        ReadOnlySpan<byte> packet,
        int packetIndex,
        int packetOffset,
        int datagramLength)
    {
        if (packetIndex < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(packetIndex));
        }

        if (packetOffset < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(packetOffset));
        }

        if (datagramLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(datagramLength));
        }

        QuicHeaderForm? headerForm = null;
        string? packetType = null;
        if (QuicPacketParser.TryClassifyHeaderForm(packet, out QuicHeaderForm parsedHeaderForm))
        {
            headerForm = parsedHeaderForm;
            packetType = DescribePacketType(packet, parsedHeaderForm);
        }

        string typeDescription = packetType ?? "unknown";
        return new QuicDiagnosticEvent(
            "connection.runtime.packet",
            "header-observed",
            $"Observed {typeDescription} packet header on {DescribePath(pathIdentity)}.",
            QuicDiagnosticSeverity.Trace)
        {
            PathIdentity = pathIdentity,
            HeaderForm = headerForm,
            PacketType = packetType,
            PacketIndex = packetIndex,
            PacketOffset = packetOffset,
            DatagramLength = datagramLength,
        };
    }

    internal static QuicDiagnosticEvent CoalescedDatagramReceived(
        QuicConnectionPathIdentity pathIdentity,
        int packetCount,
        int datagramLength)
    {
        if (packetCount < MinimumCoalescedPacketCount)
        {
            throw new ArgumentOutOfRangeException(nameof(packetCount));
        }

        if (datagramLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(datagramLength));
        }

        return new QuicDiagnosticEvent(
            "connection.runtime.packet",
            "coalesced-datagram-received",
            $"Split coalesced UDP datagram from {DescribePath(pathIdentity)} into {packetCount} QUIC packets.",
            QuicDiagnosticSeverity.Trace)
        {
            PathIdentity = pathIdentity,
            PacketCount = packetCount,
            DatagramLength = datagramLength,
        };
    }

    internal static QuicDiagnosticEvent ConnectionIdIssued(ulong connectionId)
    {
        return new QuicDiagnosticEvent(
            "connection.runtime.connection-id",
            "issued",
            $"Issued connection ID sequence {connectionId}.",
            QuicDiagnosticSeverity.Trace)
        {
            ConnectionId = connectionId,
        };
    }

    internal static QuicDiagnosticEvent ConnectionIdRetired(ulong connectionId)
    {
        return new QuicDiagnosticEvent(
            "connection.runtime.connection-id",
            "retired",
            $"Retired connection ID sequence {connectionId}.",
            QuicDiagnosticSeverity.Trace)
        {
            ConnectionId = connectionId,
        };
    }

    internal static QuicDiagnosticEvent ConnectionIdUsedOnPath(
        QuicConnectionPathIdentity pathIdentity,
        ulong connectionId)
    {
        return new QuicDiagnosticEvent(
            "connection.runtime.connection-id",
            "used-on-path",
            $"Connection ID sequence {connectionId} was first observed on {DescribePath(pathIdentity)}.",
            QuicDiagnosticSeverity.Trace)
        {
            PathIdentity = pathIdentity,
            ConnectionId = connectionId,
        };
    }

    internal static QuicDiagnosticEvent PathValidationChallengeSent(
        QuicConnectionPathIdentity pathIdentity,
        ulong challengeSendCount)
    {
        return new QuicDiagnosticEvent(
            "connection.runtime.path",
            "path-validation-challenge-sent",
            $"Path validation challenge {challengeSendCount} was sent on {DescribePath(pathIdentity)}.",
            QuicDiagnosticSeverity.Trace)
        {
            PathIdentity = pathIdentity,
            ChallengeSendCount = challengeSendCount,
        };
    }

    internal static QuicDiagnosticEvent PathValidationSucceeded(QuicConnectionPathIdentity pathIdentity)
    {
        return new QuicDiagnosticEvent(
            "connection.runtime.path",
            "path-validation-succeeded",
            $"Path validation succeeded on {DescribePath(pathIdentity)}.",
            QuicDiagnosticSeverity.Info)
        {
            PathIdentity = pathIdentity,
            Succeeded = true,
        };
    }

    internal static QuicDiagnosticEvent PathValidationFailed(QuicConnectionPathIdentity pathIdentity)
    {
        return new QuicDiagnosticEvent(
            "connection.runtime.path",
            "path-validation-failed",
            $"Path validation failed on {DescribePath(pathIdentity)}.",
            QuicDiagnosticSeverity.Warning)
        {
            PathIdentity = pathIdentity,
            Succeeded = false,
        };
    }

    internal static QuicDiagnosticEvent PathValidationTimedOut(QuicConnectionPathIdentity pathIdentity)
    {
        return new QuicDiagnosticEvent(
            "connection.runtime.path",
            "path-validation-timed-out",
            $"Path validation timed out on {DescribePath(pathIdentity)}.",
            QuicDiagnosticSeverity.Warning)
        {
            PathIdentity = pathIdentity,
            Succeeded = false,
        };
    }

    internal static QuicDiagnosticEvent PathPromoted(
        QuicConnectionPathIdentity pathIdentity,
        bool preserveRecoveryState)
    {
        return new QuicDiagnosticEvent(
            "connection.runtime.path",
            "promoted",
            $"Validated path {DescribePath(pathIdentity)} was promoted to active.",
            QuicDiagnosticSeverity.Info)
        {
            PathIdentity = pathIdentity,
            IsSet = preserveRecoveryState,
        };
    }

    internal static QuicDiagnosticEvent SpinBitUpdated(
        QuicConnectionPathIdentity pathIdentity,
        bool spinBit)
    {
        return new QuicDiagnosticEvent(
            "connection.runtime.path",
            "spin-bit-updated",
            $"Spin bit state updated on {DescribePath(pathIdentity)}.",
            QuicDiagnosticSeverity.Trace)
        {
            PathIdentity = pathIdentity,
            IsSet = spinBit,
        };
    }

    internal static QuicDiagnosticEvent IcmpPacketTooBigReceived(
        QuicConnectionPathIdentity pathIdentity,
        ulong maximumDatagramSizeBytes,
        bool accepted)
    {
        return new QuicDiagnosticEvent(
            "connection.runtime.path",
            "icmp-packet-too-big-received",
            accepted
                ? $"Accepted ICMP Packet Too Big maximum datagram size {maximumDatagramSizeBytes} on {DescribePath(pathIdentity)}."
                : $"Ignored ICMP Packet Too Big maximum datagram size {maximumDatagramSizeBytes} on {DescribePath(pathIdentity)}.",
            accepted ? QuicDiagnosticSeverity.Info : QuicDiagnosticSeverity.Trace)
        {
            PathIdentity = pathIdentity,
            MaximumDatagramSizeBytes = maximumDatagramSizeBytes,
            Accepted = accepted,
        };
    }

    internal static QuicDiagnosticEvent PmtuUpdated(
        QuicConnectionPathIdentity pathIdentity,
        ulong maximumDatagramSizeBytes,
        bool isProvisional)
    {
        return new QuicDiagnosticEvent(
            "connection.runtime.path",
            "pmtu-updated",
            $"Path maximum datagram size is now {maximumDatagramSizeBytes} bytes on {DescribePath(pathIdentity)}.",
            QuicDiagnosticSeverity.Info)
        {
            PathIdentity = pathIdentity,
            MaximumDatagramSizeBytes = maximumDatagramSizeBytes,
            IsProvisional = isProvisional,
        };
    }

    internal static QuicDiagnosticEvent ConnectionCloseStateChanged(
        QuicConnectionCloseOrigin origin,
        QuicConnectionPhase phase)
    {
        return new QuicDiagnosticEvent(
            "connection.runtime.lifecycle",
            "connection-close-state-changed",
            $"Connection entered {phase} due to {origin} close.",
            QuicDiagnosticSeverity.Info)
        {
            CloseOrigin = origin,
            ConnectionPhase = phase,
        };
    }

    internal static QuicDiagnosticEvent UdpReceiveError(string socketErrorName, int socketErrorCode)
    {
        return UdpError("udp-receive-error", "UDP receive error", socketErrorName, socketErrorCode, QuicDiagnosticSeverity.Warning);
    }

    internal static QuicDiagnosticEvent UdpSendError(string socketErrorName, int socketErrorCode)
    {
        return UdpError("udp-send-error", "UDP send error", socketErrorName, socketErrorCode, QuicDiagnosticSeverity.Warning);
    }

    internal static QuicDiagnosticEvent AntiAmplificationBlocked(
        QuicConnectionPathIdentity pathIdentity,
        ulong attemptedBytes,
        ulong remainingSendBudget)
    {
        return new QuicDiagnosticEvent(
            "connection.runtime.path",
            "anti-amplification-blocked",
            $"Anti-amplification budget blocked {attemptedBytes} bytes on {DescribePath(pathIdentity)}.",
            QuicDiagnosticSeverity.Warning)
        {
            PathIdentity = pathIdentity,
            AttemptedBytes = attemptedBytes,
            RemainingSendBudget = remainingSendBudget,
        };
    }

    private static QuicDiagnosticEvent UdpError(
        string name,
        string message,
        string socketErrorName,
        int socketErrorCode,
        QuicDiagnosticSeverity severity)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(socketErrorName);

        return new QuicDiagnosticEvent(
            "connection.socket",
            name,
            $"{message}: {socketErrorName} ({socketErrorCode}).",
            severity)
        {
            SocketErrorName = socketErrorName,
            SocketErrorCode = socketErrorCode,
        };
    }

    private static string DescribePacketType(ReadOnlySpan<byte> packet, QuicHeaderForm headerForm)
    {
        if (headerForm == QuicHeaderForm.Short)
        {
            return "short";
        }

        if (!QuicPacketParser.TryParseLongHeader(packet, allowClearedFixedBit: true, out QuicLongHeaderPacket longHeader))
        {
            return "long";
        }

        if (longHeader.IsVersionNegotiation)
        {
            return "version_negotiation";
        }

        return QuicVersionNegotiation.TryGetLongHeaderPacketType(
                longHeader.Version,
                longHeader.LongPacketTypeBits,
                out QuicLongPacketType longPacketType)
            ? longPacketType switch
            {
                QuicLongPacketType.Initial => "initial",
                QuicLongPacketType.ZeroRtt => "0rtt",
                QuicLongPacketType.Handshake => "handshake",
                QuicLongPacketType.Retry => "retry",
                _ => "long",
            }
            : "long";
    }

    private static string DescribePath(QuicConnectionPathIdentity pathIdentity)
    {
        return pathIdentity.RemotePort is int remotePort
            ? $"{pathIdentity.RemoteAddress}:{remotePort}"
            : pathIdentity.RemoteAddress;
    }
}

/// <summary>
/// A disabled diagnostics sink.
/// </summary>
internal sealed class QuicNullDiagnosticsSink : IQuicDiagnosticsSink
{
    /// <summary>
    /// Gets the singleton disabled sink instance.
    /// </summary>
    public static QuicNullDiagnosticsSink Instance { get; } = new();

    private QuicNullDiagnosticsSink()
    {
    }

    /// <inheritdoc />
    public bool IsEnabled => false;

    /// <inheritdoc />
    public void Emit(QuicDiagnosticEvent diagnosticEvent)
    {
        _ = diagnosticEvent;
    }
}
