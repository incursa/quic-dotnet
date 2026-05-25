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
            zeroRttTransportParameters: null,
            Stopwatch.GetTimestamp());

    internal bool TryStoreIssuedTicket(
        ReadOnlySpan<byte> ticketBytes,
        ReadOnlySpan<byte> ticketNonce,
        uint ticketAgeAdd,
        uint ticketLifetimeSeconds,
        ReadOnlySpan<byte> resumptionMasterSecret,
        QuicTransportParameters? zeroRttTransportParameters)
        => TryStoreIssuedTicket(
            ticketBytes,
            ticketNonce,
            ticketAgeAdd,
            ticketLifetimeSeconds,
            resumptionMasterSecret,
            zeroRttTransportParameters,
            Stopwatch.GetTimestamp());

    internal bool TryStoreIssuedTicket(
        ReadOnlySpan<byte> ticketBytes,
        ReadOnlySpan<byte> ticketNonce,
        uint ticketAgeAdd,
        uint ticketLifetimeSeconds,
        ReadOnlySpan<byte> resumptionMasterSecret,
        long issuedAtTicks)
        => TryStoreIssuedTicket(
            ticketBytes,
            ticketNonce,
            ticketAgeAdd,
            ticketLifetimeSeconds,
            resumptionMasterSecret,
            zeroRttTransportParameters: null,
            issuedAtTicks);

    internal bool TryStoreIssuedTicket(
        ReadOnlySpan<byte> ticketBytes,
        ReadOnlySpan<byte> ticketNonce,
        uint ticketAgeAdd,
        uint ticketLifetimeSeconds,
        ReadOnlySpan<byte> resumptionMasterSecret,
        QuicTransportParameters? zeroRttTransportParameters,
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
            resumptionMasterSecret.ToArray(),
            CloneZeroRttTransportParameters(zeroRttTransportParameters));

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

    internal bool TryConsumeLiveTicketForEarlyData(
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
        if (!tickets.TryRemove(key, out QuicServerResumptionTicketRecord? record))
        {
            return false;
        }

        if (record.IsExpired(nowTicks))
        {
            record.Clear();
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

    private static QuicTransportParameters? CloneZeroRttTransportParameters(QuicTransportParameters? parameters)
    {
        if (parameters is null)
        {
            return null;
        }

        return new QuicTransportParameters
        {
            MaxIdleTimeout = parameters.MaxIdleTimeout,
            MaxUdpPayloadSize = parameters.MaxUdpPayloadSize,
            MaxDatagramFrameSize = parameters.MaxDatagramFrameSize,
            VersionInformation = CloneVersionInformation(parameters.VersionInformation),
            InitialMaxData = parameters.InitialMaxData,
            InitialMaxStreamDataBidiLocal = parameters.InitialMaxStreamDataBidiLocal,
            InitialMaxStreamDataBidiRemote = parameters.InitialMaxStreamDataBidiRemote,
            InitialMaxStreamDataUni = parameters.InitialMaxStreamDataUni,
            InitialMaxStreamsBidi = parameters.InitialMaxStreamsBidi,
            InitialMaxStreamsUni = parameters.InitialMaxStreamsUni,
            DisableActiveMigration = parameters.DisableActiveMigration,
            ActiveConnectionIdLimit = parameters.ActiveConnectionIdLimit,
        };
    }

    private static QuicVersionInformation? CloneVersionInformation(QuicVersionInformation? versionInformation)
    {
        if (versionInformation is null)
        {
            return null;
        }

        return new QuicVersionInformation
        {
            ChosenVersion = versionInformation.ChosenVersion,
            AvailableVersions = versionInformation.AvailableVersions.ToArray(),
        };
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
        byte[] resumptionMasterSecret,
        QuicTransportParameters? zeroRttTransportParameters = null)
    {
        TicketBytes = ticketBytes;
        TicketNonce = ticketNonce;
        TicketAgeAdd = ticketAgeAdd;
        TicketLifetimeSeconds = ticketLifetimeSeconds;
        IssuedAtTicks = issuedAtTicks;
        ResumptionMasterSecret = resumptionMasterSecret;
        ZeroRttTransportParameters = zeroRttTransportParameters;
    }

    internal byte[] TicketBytes { get; }

    internal byte[] TicketNonce { get; }

    internal uint TicketAgeAdd { get; }

    internal uint TicketLifetimeSeconds { get; }

    internal long IssuedAtTicks { get; }

    internal byte[] ResumptionMasterSecret { get; }

    internal QuicTransportParameters? ZeroRttTransportParameters { get; }

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
