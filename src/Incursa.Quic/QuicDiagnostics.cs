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
            ("connection.runtime.handshake", "handshake-packet-received") => QuicDiagnosticKind.HandshakePacketReceived,
            ("connection.runtime.handshake", "handshake-packet-sent") => QuicDiagnosticKind.HandshakePacketSent,
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
