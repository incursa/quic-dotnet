// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

// CONTEXT: The public ticket carrier must stay immutable and opaque so callers can move detached
// ticket material without gaining access to the internal resumption snapshot or secret-bearing state.
// SEE: QuicDetachedResumptionTicketSnapshot
/// <summary>
/// Opaque resumption-ticket material that can be exported from one connection and imported by another.
/// </summary>
public sealed class QuicResumptionTicket
{
    private readonly ReadOnlyMemory<byte> ticketBytes;
    private readonly QuicDetachedResumptionTicketSnapshot? detachedResumptionTicketSnapshot;

    /// <summary>
    /// Initializes a new ticket carrier from raw ticket bytes.
    /// </summary>
    public QuicResumptionTicket(ReadOnlyMemory<byte> ticketBytes)
    {
        if (ticketBytes.IsEmpty)
        {
            throw new ArgumentException("The resumption ticket must not be empty.", nameof(ticketBytes));
        }

        this.ticketBytes = CloneBytes(ticketBytes);
    }

    /// <summary>
    /// Gets the opaque resumption ticket bytes.
    /// </summary>
    public ReadOnlyMemory<byte> TicketBytes => ticketBytes;

    /// <summary>
    /// Returns a non-secret string representation of the ticket.
    /// </summary>
    public override string ToString()
    {
        return $"QuicResumptionTicket {{ Length = {ticketBytes.Length} bytes }}";
    }

    internal QuicResumptionTicket(QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot)
    {
        ArgumentNullException.ThrowIfNull(detachedResumptionTicketSnapshot);

        this.detachedResumptionTicketSnapshot = detachedResumptionTicketSnapshot;
        ticketBytes = detachedResumptionTicketSnapshot.TicketBytes;
    }

    internal bool TryGetDetachedResumptionTicketSnapshot(out QuicDetachedResumptionTicketSnapshot? snapshot)
    {
        snapshot = detachedResumptionTicketSnapshot;
        return snapshot is not null;
    }

    private static ReadOnlyMemory<byte> CloneBytes(ReadOnlyMemory<byte> bytes)
    {
        return bytes.IsEmpty ? ReadOnlyMemory<byte>.Empty : bytes.ToArray();
    }
}
