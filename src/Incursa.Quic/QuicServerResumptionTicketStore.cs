using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Incursa.Quic;

internal sealed class QuicServerResumptionTicketStore
{
    private readonly ConcurrentDictionary<string, QuicServerResumptionTicketRecord> tickets = new(StringComparer.Ordinal);

    internal bool TryStoreIssuedTicket(
        ReadOnlySpan<byte> ticketBytes,
        ReadOnlySpan<byte> ticketNonce,
        uint ticketAgeAdd,
        uint ticketLifetimeSeconds,
        ReadOnlySpan<byte> resumptionMasterSecret)
        => TryStoreIssuedTicket(
            ticketBytes,
            ticketNonce,
            ticketAgeAdd,
            ticketLifetimeSeconds,
            resumptionMasterSecret,
            Stopwatch.GetTimestamp());

    internal bool TryStoreIssuedTicket(
        ReadOnlySpan<byte> ticketBytes,
        ReadOnlySpan<byte> ticketNonce,
        uint ticketAgeAdd,
        uint ticketLifetimeSeconds,
        ReadOnlySpan<byte> resumptionMasterSecret,
        long issuedAtTicks)
    {
        if (ticketBytes.IsEmpty || ticketNonce.IsEmpty || resumptionMasterSecret.IsEmpty)
        {
            return false;
        }

        string key = Convert.ToHexString(ticketBytes);
        QuicServerResumptionTicketRecord record = new(
            ticketBytes.ToArray(),
            ticketNonce.ToArray(),
            ticketAgeAdd,
            ticketLifetimeSeconds,
            issuedAtTicks,
            resumptionMasterSecret.ToArray());

        if (tickets.TryAdd(key, record))
        {
            return true;
        }

        record.Clear();
        return false;
    }

    internal bool TryGetLiveTicket(
        ReadOnlySpan<byte> ticketBytes,
        out QuicServerResumptionTicketRecord ticket)
        => TryGetLiveTicket(ticketBytes, Stopwatch.GetTimestamp(), out ticket);

    internal bool TryGetLiveTicket(
        ReadOnlySpan<byte> ticketBytes,
        long nowTicks,
        out QuicServerResumptionTicketRecord ticket)
    {
        ticket = null!;
        if (ticketBytes.IsEmpty)
        {
            return false;
        }

        string key = Convert.ToHexString(ticketBytes);
        if (!tickets.TryGetValue(key, out QuicServerResumptionTicketRecord? record))
        {
            return false;
        }

        if (record.IsExpired(nowTicks))
        {
            if (tickets.TryRemove(key, out QuicServerResumptionTicketRecord? removed))
            {
                removed.Clear();
            }

            return false;
        }

        ticket = record;
        return true;
    }

    internal void Clear()
    {
        foreach (QuicServerResumptionTicketRecord record in tickets.Values)
        {
            record.Clear();
        }

        tickets.Clear();
    }
}

internal sealed class QuicServerResumptionTicketRecord
{
    internal QuicServerResumptionTicketRecord(
        byte[] ticketBytes,
        byte[] ticketNonce,
        uint ticketAgeAdd,
        uint ticketLifetimeSeconds,
        long issuedAtTicks,
        byte[] resumptionMasterSecret)
    {
        TicketBytes = ticketBytes;
        TicketNonce = ticketNonce;
        TicketAgeAdd = ticketAgeAdd;
        TicketLifetimeSeconds = ticketLifetimeSeconds;
        IssuedAtTicks = issuedAtTicks;
        ResumptionMasterSecret = resumptionMasterSecret;
    }

    internal byte[] TicketBytes { get; }

    internal byte[] TicketNonce { get; }

    internal uint TicketAgeAdd { get; }

    internal uint TicketLifetimeSeconds { get; }

    internal long IssuedAtTicks { get; }

    internal byte[] ResumptionMasterSecret { get; }

    internal bool IsExpired(long nowTicks)
    {
        if (TicketLifetimeSeconds == 0)
        {
            return true;
        }

        if (nowTicks <= IssuedAtTicks)
        {
            return false;
        }

        long elapsedTicks = nowTicks - IssuedAtTicks;
        ulong lifetimeTicks = checked((ulong)TicketLifetimeSeconds * (ulong)Stopwatch.Frequency);
        return (ulong)elapsedTicks >= lifetimeTicks;
    }

    internal void Clear()
    {
        CryptographicOperations.ZeroMemory(TicketBytes);
        CryptographicOperations.ZeroMemory(TicketNonce);
        CryptographicOperations.ZeroMemory(ResumptionMasterSecret);
    }
}
