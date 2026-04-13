namespace Incursa.Quic;

internal sealed record QuicDetachedResumptionTicketSnapshot
{
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

    internal QuicDetachedResumptionTicketSnapshot(
        ReadOnlyMemory<byte> ticketBytes,
        ReadOnlyMemory<byte> ticketNonce,
        uint ticketLifetimeSeconds,
        uint ticketAgeAdd,
        long capturedAtTicks,
        ReadOnlyMemory<byte> resumptionMasterSecret)
    {
        if (ticketBytes.IsEmpty)
        {
            throw new ArgumentException("The detached resumption ticket must not be empty.", nameof(ticketBytes));
        }

        if (capturedAtTicks < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(capturedAtTicks));
        }

        TicketBytes = ticketBytes.ToArray();
        TicketNonce = ticketNonce.ToArray();
        TicketLifetimeSeconds = ticketLifetimeSeconds;
        TicketAgeAdd = ticketAgeAdd;
        CapturedAtTicks = capturedAtTicks;
        ResumptionMasterSecret = resumptionMasterSecret.ToArray();
    }

    public ReadOnlyMemory<byte> TicketBytes { get; }

    public ReadOnlyMemory<byte> TicketNonce { get; }

    public uint TicketLifetimeSeconds { get; }

    public uint TicketAgeAdd { get; }

    public long CapturedAtTicks { get; }

    public ReadOnlyMemory<byte> ResumptionMasterSecret { get; }

    public bool HasTicketBytes => !TicketBytes.IsEmpty;

    public bool HasResumptionMasterSecret => !ResumptionMasterSecret.IsEmpty;

    public bool HasResumptionCredentialMaterial => HasTicketBytes && HasResumptionMasterSecret;
}
