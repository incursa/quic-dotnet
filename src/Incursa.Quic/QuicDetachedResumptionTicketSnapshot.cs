namespace Incursa.Quic;

/// <summary>
/// Captures detached resumption ticket material and the metadata needed to resume a connection later.
/// </summary>
internal sealed record QuicDetachedResumptionTicketSnapshot
{
    /// <summary>
    /// Initializes a snapshot that contains only the ticket bytes and leaves optional resume metadata empty.
    /// </summary>
    public QuicDetachedResumptionTicketSnapshot(ReadOnlyMemory<byte> ticketBytes)
        : this(
            ticketBytes,
            ticketNonce: ReadOnlyMemory<byte>.Empty,
            ticketLifetimeSeconds: 0,
            ticketAgeAdd: 0,
            capturedAtTicks: 0,
            resumptionMasterSecret: ReadOnlyMemory<byte>.Empty)
        {
        }

    /// <summary>
    /// Initializes a snapshot with detached ticket material and the associated resumption metadata.
    /// </summary>
    internal QuicDetachedResumptionTicketSnapshot(
        ReadOnlyMemory<byte> ticketBytes,
        ReadOnlyMemory<byte> ticketNonce,
        uint ticketLifetimeSeconds,
        uint ticketAgeAdd,
        long capturedAtTicks,
        ReadOnlyMemory<byte> resumptionMasterSecret,
        uint? ticketMaxEarlyDataSize = null,
        QuicTransportParameters? peerTransportParameters = null)
    {
        if (ticketBytes.IsEmpty)
        {
            throw new ArgumentException("The detached resumption ticket must not be empty.", nameof(ticketBytes));
        }

        if (capturedAtTicks < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(capturedAtTicks));
        }

        // Copy caller-provided buffers so the snapshot stays immutable after construction.
        TicketBytes = ticketBytes.ToArray();
        TicketNonce = ticketNonce.ToArray();
        TicketLifetimeSeconds = ticketLifetimeSeconds;
        TicketAgeAdd = ticketAgeAdd;
        CapturedAtTicks = capturedAtTicks;
        ResumptionMasterSecret = resumptionMasterSecret.ToArray();
        TicketMaxEarlyDataSize = ticketMaxEarlyDataSize;
        PeerTransportParameters = peerTransportParameters;
    }

    /// <summary>
    /// Gets the detached resumption ticket bytes.
    /// </summary>
    public ReadOnlyMemory<byte> TicketBytes { get; }

    /// <summary>
    /// Gets the ticket nonce associated with the detached ticket, if any.
    /// </summary>
    public ReadOnlyMemory<byte> TicketNonce { get; }

    /// <summary>
    /// Gets the advertised lifetime of the ticket, in seconds.
    /// </summary>
    public uint TicketLifetimeSeconds { get; }

    /// <summary>
    /// Gets the ticket age add value captured with the ticket.
    /// </summary>
    public uint TicketAgeAdd { get; }

    /// <summary>
    /// Gets the timestamp, in ticks, at which the ticket was captured.
    /// </summary>
    public long CapturedAtTicks { get; }

    /// <summary>
    /// Gets the resumption master secret captured with the ticket, if any.
    /// </summary>
    public ReadOnlyMemory<byte> ResumptionMasterSecret { get; }

    /// <summary>
    /// Gets the optional maximum early data size advertised for the ticket.
    /// </summary>
    public uint? TicketMaxEarlyDataSize { get; }

    /// <summary>
    /// Gets the peer transport parameters associated with the ticket, if available.
    /// </summary>
    public QuicTransportParameters? PeerTransportParameters { get; }

    /// <summary>
    /// Gets a value that indicates whether ticket bytes are present.
    /// </summary>
    public bool HasTicketBytes => !TicketBytes.IsEmpty;

    /// <summary>
    /// Gets a value that indicates whether the resumption master secret is present.
    /// </summary>
    public bool HasResumptionMasterSecret => !ResumptionMasterSecret.IsEmpty;

    /// <summary>
    /// Gets a value that indicates whether the snapshot contains the core resumption credential material.
    /// </summary>
    public bool HasResumptionCredentialMaterial => HasTicketBytes && HasResumptionMasterSecret;

    /// <summary>
    /// Gets a value that indicates whether the snapshot contains the inputs needed to reason about early data.
    /// </summary>
    public bool HasEarlyDataPrerequisiteMaterial =>
        TicketMaxEarlyDataSize is > 0
        && PeerTransportParameters is not null;
}
