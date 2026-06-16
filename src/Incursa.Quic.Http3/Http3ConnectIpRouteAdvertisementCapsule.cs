// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Http3;

/// <summary>
/// Provides RFC 9484 ROUTE_ADVERTISEMENT capsule codec and route policy helpers.
/// </summary>
public static class Http3ConnectIpRouteAdvertisementCapsule
{
    private const int HopByHopOptionsProtocolNumber = 0;
    private const int RoutingHeaderProtocolNumber = 43;
    private const int FragmentHeaderProtocolNumber = 44;
    private const int EncapsulatingSecurityPayloadProtocolNumber = 50;
    private const int AuthenticationHeaderProtocolNumber = 51;
    private const int DestinationOptionsProtocolNumber = 60;

    /// <summary>
    /// Gets the RFC 9484 ROUTE_ADVERTISEMENT Capsule Type.
    /// </summary>
    public const ulong CapsuleType = 0x03;

    /// <summary>
    /// Indicates that endpoints may validate ROUTE_ADVERTISEMENT route ordering and overlap rules.
    /// </summary>
    public const bool MayValidateRoutes = true;

    /// <summary>
    /// Creates a ROUTE_ADVERTISEMENT capsule.
    /// </summary>
    public static Http3Capsule Create(IReadOnlyList<Http3ConnectIpRouteRange> ranges)
    {
        ArgumentNullException.ThrowIfNull(ranges);
        if (!RoutesAreOrderedAndNonOverlapping(ranges))
        {
            throw new ArgumentException("CONNECT-IP ROUTE_ADVERTISEMENT ranges must be sorted and non-overlapping.", nameof(ranges));
        }

        List<byte> payload = [];
        for (int index = 0; index < ranges.Count; index++)
        {
            AppendRange(payload, ranges[index]);
        }

        return new Http3Capsule(CapsuleType, payload.ToArray());
    }

    /// <summary>
    /// Parses a ROUTE_ADVERTISEMENT capsule payload.
    /// </summary>
    public static Http3ConnectIpRouteRange[] Parse(Http3Capsule capsule)
    {
        ArgumentNullException.ThrowIfNull(capsule);
        if (capsule.Type != CapsuleType)
        {
            throw Malformed("CONNECT-IP ROUTE_ADVERTISEMENT capsule type must be 0x03.");
        }

        List<Http3ConnectIpRouteRange> ranges = [];
        ReadOnlySpan<byte> payload = capsule.Payload;
        int offset = 0;
        while (offset < payload.Length)
        {
            ranges.Add(ReadRange(payload, ref offset));
        }

        if (!RoutesAreOrderedAndNonOverlapping(ranges))
        {
            throw Malformed("CONNECT-IP ROUTE_ADVERTISEMENT ranges must be sorted and non-overlapping.");
        }

        return ranges.ToArray();
    }

    /// <summary>
    /// Applies ROUTE_ADVERTISEMENT supersession semantics.
    /// </summary>
    public static Http3ConnectIpRouteRange[] ApplySupersedingAdvertisement(
        IReadOnlyList<Http3ConnectIpRouteRange> previousRanges,
        IReadOnlyList<Http3ConnectIpRouteRange> latestRanges)
    {
        ArgumentNullException.ThrowIfNull(previousRanges);
        ArgumentNullException.ThrowIfNull(latestRanges);
        return [.. latestRanges];
    }

    /// <summary>
    /// Returns true when a previous range was withdrawn by the latest advertisement.
    /// </summary>
    public static bool IsWithdrawn(Http3ConnectIpRouteRange previousRange, IReadOnlyList<Http3ConnectIpRouteRange> latestRanges)
    {
        ArgumentNullException.ThrowIfNull(previousRange);
        ArgumentNullException.ThrowIfNull(latestRanges);
        string previousKey = CreateRangeKey(previousRange);
        for (int index = 0; index < latestRanges.Count; index++)
        {
            if (CreateRangeKey(latestRanges[index]) == previousKey)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Returns true when route ranges satisfy the RFC ordering and non-overlap rules.
    /// </summary>
    public static bool RoutesAreOrderedAndNonOverlapping(IReadOnlyList<Http3ConnectIpRouteRange> ranges)
    {
        ArgumentNullException.ThrowIfNull(ranges);
        for (int index = 1; index < ranges.Count; index++)
        {
            Http3ConnectIpRouteRange previous = ranges[index - 1];
            Http3ConnectIpRouteRange current = ranges[index];
            if (previous.IpVersion > current.IpVersion)
            {
                return false;
            }

            if (previous.IpVersion == current.IpVersion && previous.IpProtocol > current.IpProtocol)
            {
                return false;
            }

            if (previous.IpVersion == current.IpVersion
                && previous.IpProtocol == current.IpProtocol
                && Http3ConnectIpRouteRange.CompareAddressBytes(previous.EndAddress.GetAddressBytes(), current.StartAddress.GetAddressBytes()) >= 0)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Returns true when an invalid ROUTE_ADVERTISEMENT requires aborting the request stream.
    /// </summary>
    public static bool ShouldAbortRequestStreamForInvalidAdvertisement(bool advertisementValid)
    {
        return !advertisementValid;
    }

    /// <summary>
    /// Returns true when a route set may be sent.
    /// </summary>
    public static bool CanSendRouteAdvertisement(IReadOnlyList<Http3ConnectIpRouteRange> ranges)
    {
        return RoutesAreOrderedAndNonOverlapping(ranges);
    }

    /// <summary>
    /// Returns true when an IP proxy may reject scoping to the protocol number.
    /// </summary>
    public static bool MayRejectExtensionHeaderProtocolNumber(int protocolNumber)
    {
        return protocolNumber is HopByHopOptionsProtocolNumber
            or RoutingHeaderProtocolNumber
            or FragmentHeaderProtocolNumber
            or EncapsulatingSecurityPayloadProtocolNumber
            or AuthenticationHeaderProtocolNumber
            or DestinationOptionsProtocolNumber;
    }

    /// <summary>
    /// Selects the outermost non-extension protocol number from an IPv6 next-header chain.
    /// </summary>
    public static int SelectOutermostNonExtensionProtocol(IReadOnlyList<int> protocolChain)
    {
        ArgumentNullException.ThrowIfNull(protocolChain);
        for (int index = 0; index < protocolChain.Count; index++)
        {
            int protocolNumber = protocolChain[index];
            if (!MayRejectExtensionHeaderProtocolNumber(protocolNumber))
            {
                return protocolNumber;
            }
        }

        return 0;
    }

    private static void AppendRange(List<byte> payload, Http3ConnectIpRouteRange range)
    {
        ArgumentNullException.ThrowIfNull(range);
        payload.Add((byte)range.IpVersion);
        payload.AddRange(range.StartAddress.GetAddressBytes());
        payload.AddRange(range.EndAddress.GetAddressBytes());
        payload.Add((byte)range.IpProtocol);
    }

    private static Http3ConnectIpRouteRange ReadRange(ReadOnlySpan<byte> payload, ref int offset)
    {
        if (offset >= payload.Length)
        {
            throw Malformed("CONNECT-IP ROUTE_ADVERTISEMENT IP Version field is truncated.");
        }

        int ipVersion = payload[offset++];
        int addressLength = ipVersion switch
        {
            Http3ConnectIpScopePolicy.Ipv4Version => 4,
            Http3ConnectIpScopePolicy.Ipv6Version => 16,
            _ => throw Malformed("CONNECT-IP ROUTE_ADVERTISEMENT IP Version must be 4 or 6."),
        };

        int rangeLength = checked(addressLength + addressLength + 1);
        if (payload.Length - offset < rangeLength)
        {
            throw Malformed("CONNECT-IP ROUTE_ADVERTISEMENT address range field is truncated.");
        }

        IPAddress start = new(payload.Slice(offset, addressLength));
        offset += addressLength;
        IPAddress end = new(payload.Slice(offset, addressLength));
        offset += addressLength;
        int ipProtocol = payload[offset++];

        try
        {
            return new Http3ConnectIpRouteRange(start, end, ipProtocol);
        }
        catch (ArgumentException)
        {
            throw Malformed("CONNECT-IP ROUTE_ADVERTISEMENT address range fields are malformed.");
        }
    }

    private static string CreateRangeKey(Http3ConnectIpRouteRange range)
    {
        return string.Create(
            System.Globalization.CultureInfo.InvariantCulture,
            $"{range.IpVersion}|{range.StartAddress}|{range.EndAddress}|{range.IpProtocol}");
    }

    private static Http3Exception Malformed(string message)
    {
        return new Http3Exception(Http3ErrorCode.MessageError, message);
    }
}
