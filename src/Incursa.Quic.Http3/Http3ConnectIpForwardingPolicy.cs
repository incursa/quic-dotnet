// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Http3;

/// <summary>
/// Provides RFC 9484 CONNECT-IP packet forwarding, hop-count, MTU, and ICMP error policy helpers.
/// </summary>
public static class Http3ConnectIpForwardingPolicy
{
    private const int Ipv4VersionNibble = 4;
    private const int Ipv6VersionNibble = 6;
    private const int Ipv4ProtocolOffset = 9;
    private const int Ipv4TtlOffset = 8;
    private const int Ipv4SourceAddressOffset = 12;
    private const int Ipv4DestinationAddressOffset = 16;
    private const int Ipv4AddressLength = 4;
    private const int Ipv6NextHeaderOffset = 6;
    private const int Ipv6HopLimitOffset = 7;
    private const int Ipv6SourceAddressOffset = 8;
    private const int Ipv6DestinationAddressOffset = 24;
    private const int Ipv6AddressLength = 16;
    private const int Ipv4LinkLocalFirstOctet = 169;
    private const int Ipv4LinkLocalSecondOctet = 254;

    /// <summary>
    /// Gets the minimum IPv6 tunnel link MTU.
    /// </summary>
    public const int MinimumIpv6TunnelMtu = 1280;

    /// <summary>
    /// Gets the ICMPv6 echo request data length used for tunnel MTU validation.
    /// </summary>
    public const int Icmpv6EchoMtuProbeDataLength = 1232;

    /// <summary>
    /// Gets the ICMPv6 Destination Unreachable code for invalid source addresses.
    /// </summary>
    public const int Icmpv6DestinationUnreachableInvalidSourceCode = 5;

    /// <summary>
    /// Gets the ICMPv6 Destination Unreachable code for no route to destination.
    /// </summary>
    public const int Icmpv6DestinationUnreachableNoRouteCode = 0;

    /// <summary>
    /// Gets the ICMPv6 Destination Unreachable code for administratively prohibited destination.
    /// </summary>
    public const int Icmpv6DestinationUnreachableAdministrativelyProhibitedCode = 1;

    /// <summary>
    /// Indicates that correctness or policy failures are forwarding errors rather than protocol violations.
    /// </summary>
    public const bool FailedChecksAreForwardingErrors = true;

    /// <summary>
    /// Indicates whether decapsulation decrements Hop Count or TTL.
    /// </summary>
    public const bool DecrementHopCountOnDecapsulation = false;

    /// <summary>
    /// Returns true when a received HTTP Datagram IP packet can be forwarded or delivered locally.
    /// </summary>
    public static bool CanProcessReceivedIpPacket(ReadOnlySpan<byte> ipPacket, bool localPolicyAllowsPacket, bool routeOrLocalApplicationAvailable)
    {
        return Http3ConnectIpDatagram.IsFullIpPacket(ipPacket)
            && localPolicyAllowsPacket
            && routeOrLocalApplicationAvailable;
    }

    /// <summary>
    /// Returns true when an additional configured filtering policy permits forwarding.
    /// </summary>
    public static bool AdditionalFilteringPolicyAllowsPacket(bool filteringPolicyConfigured, bool packetAllowedByPolicy)
    {
        return !filteringPolicyConfigured || packetAllowedByPolicy;
    }

    /// <summary>
    /// Returns true when an IP packet matches a mapped tunnel route and forwarding checks pass.
    /// </summary>
    public static bool CanTransmitPacketOnMappedTunnel(
        ReadOnlySpan<byte> ipPacket,
        IReadOnlyList<Http3ConnectIpRouteRange> routes,
        bool localPolicyAllowsPacket)
    {
        ArgumentNullException.ThrowIfNull(routes);
        if (!localPolicyAllowsPacket || !TryGetDestinationAndProtocol(ipPacket, out IPAddress? destination, out int protocolNumber))
        {
            return false;
        }

        for (int index = 0; index < routes.Count; index++)
        {
            Http3ConnectIpRouteRange route = routes[index];
            if (AddressInRange(destination, route) && route.AllowsProtocol(protocolNumber))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Returns true when encapsulating a forwarded packet requires Hop Count or TTL decrement.
    /// </summary>
    public static bool ShouldDecrementHopCountOnEncapsulation(bool forwardingBetweenDifferentLinks, bool packetGeneratedByProxyingEndpoint)
    {
        return forwardingBetweenDifferentLinks && !packetGeneratedByProxyingEndpoint;
    }

    /// <summary>
    /// Attempts to decrement Hop Count or TTL immediately before HTTP Datagram transmission.
    /// </summary>
    public static bool TryDecrementHopCountBeforeTransmission(ReadOnlySpan<byte> ipPacket, out byte[] decrementedPacket)
    {
        decrementedPacket = ipPacket.ToArray();
        if (!Http3ConnectIpDatagram.IsFullIpPacket(decrementedPacket))
        {
            return false;
        }

        int version = decrementedPacket[0] >> 4;
        int hopOffset = version == Ipv4VersionNibble ? Ipv4TtlOffset : Ipv6HopLimitOffset;
        if (decrementedPacket[hopOffset] == 0)
        {
            return false;
        }

        decrementedPacket[hopOffset]--;
        return true;
    }

    /// <summary>
    /// Returns true when link-local traffic can be forwarded beyond the received interface.
    /// </summary>
    public static bool CanForwardBeyondReceivedInterface(ReadOnlySpan<byte> ipPacket)
    {
        return TryGetSourceAndDestination(ipPacket, out IPAddress? source, out IPAddress? destination)
            && !IsLinkLocal(source)
            && !IsLinkLocal(destination);
    }

    /// <summary>
    /// Returns true when the IPv6 tunnel link MTU satisfies RFC 9484.
    /// </summary>
    public static bool IsIpv6TunnelMtuValid(int tunnelMtu)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(tunnelMtu);
        return tunnelMtu >= MinimumIpv6TunnelMtu;
    }

    /// <summary>
    /// Returns true when ICMPv6 echo requests must be used to verify tunnel MTU.
    /// </summary>
    public static bool ShouldUseIcmpv6EchoRequestsToVerifyLinkMtu(bool outOfBandGuaranteeSufficient)
    {
        return !outOfBandGuaranteeSufficient;
    }

    /// <summary>
    /// Returns true when tunnel MTU probing failure tears down the tunnel.
    /// </summary>
    public static bool ShouldTearDownTunnelAfterMtuProbeFailure(bool outOfBandGuaranteeSufficient, bool echoResponseReceived)
    {
        return ShouldUseIcmpv6EchoRequestsToVerifyLinkMtu(outOfBandGuaranteeSufficient) && !echoResponseReceived;
    }

    /// <summary>
    /// Returns true when QUIC DATAGRAM IPv6 conveyance must abort because the QUIC MTU is too low.
    /// </summary>
    public static bool ShouldAbortRequestStreamForLowQuicMtu(bool usingQuicDatagramForIpv6Packets, int quicMtu)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(quicMtu);
        return usingQuicDatagramForIpv6Packets && quicMtu < MinimumIpv6TunnelMtu;
    }

    /// <summary>
    /// Returns true when forwarding errors should be signaled with ICMP packets carried in HTTP Datagrams.
    /// </summary>
    public static bool ShouldSignalForwardingErrorWithIcmp(bool forwardingErrorDetected)
    {
        return forwardingErrorDetected;
    }

    /// <summary>
    /// Returns true when invalid source addresses map to ICMPv6 Destination Unreachable code 5.
    /// </summary>
    public static bool ShouldSendInvalidSourceDestinationUnreachable(bool invalidSourceAddress)
    {
        return invalidSourceAddress;
    }

    /// <summary>
    /// Returns true when a Destination Unreachable code is valid for unroutable destination addresses.
    /// </summary>
    public static bool IsValidUnroutableDestinationCode(int icmpv6Code)
    {
        return icmpv6Code is Icmpv6DestinationUnreachableNoRouteCode
            or Icmpv6DestinationUnreachableAdministrativelyProhibitedCode;
    }

    /// <summary>
    /// Returns true when packets larger than the outgoing MTU require Packet Too Big feedback.
    /// </summary>
    public static bool ShouldSendPacketTooBig(int packetLength, int outgoingLinkMtu)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(packetLength);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(outgoingLinkMtu);
        return packetLength > outgoingLinkMtu;
    }

    /// <summary>
    /// Returns true when proxied ICMP packets should be processed without ROUTE_ADVERTISEMENT capsules.
    /// </summary>
    public static bool ShouldProcessProxiedIcmpWithoutRouteAdvertisement(bool routeAdvertisementSent, int protocolNumber)
    {
        return !routeAdvertisementSent
            && protocolNumber is Http3ConnectIpProtocolScope.IcmpV4ProtocolNumber or Http3ConnectIpProtocolScope.IcmpV6ProtocolNumber;
    }

    private static bool TryGetDestinationAndProtocol(ReadOnlySpan<byte> ipPacket, out IPAddress destination, out int protocolNumber)
    {
        destination = IPAddress.None;
        protocolNumber = 0;
        if (!Http3ConnectIpDatagram.IsFullIpPacket(ipPacket))
        {
            return false;
        }

        int version = ipPacket[0] >> 4;
        if (version == Ipv4VersionNibble)
        {
            destination = new IPAddress(ipPacket.Slice(Ipv4DestinationAddressOffset, Ipv4AddressLength));
            protocolNumber = ipPacket[Ipv4ProtocolOffset];
            return true;
        }

        if (version == Ipv6VersionNibble)
        {
            destination = new IPAddress(ipPacket.Slice(Ipv6DestinationAddressOffset, Ipv6AddressLength));
            protocolNumber = ipPacket[Ipv6NextHeaderOffset];
            return true;
        }

        return false;
    }

    private static bool TryGetSourceAndDestination(ReadOnlySpan<byte> ipPacket, out IPAddress source, out IPAddress destination)
    {
        source = IPAddress.None;
        destination = IPAddress.None;
        if (!Http3ConnectIpDatagram.IsFullIpPacket(ipPacket))
        {
            return false;
        }

        int version = ipPacket[0] >> 4;
        if (version == Ipv4VersionNibble)
        {
            source = new IPAddress(ipPacket.Slice(Ipv4SourceAddressOffset, Ipv4AddressLength));
            destination = new IPAddress(ipPacket.Slice(Ipv4DestinationAddressOffset, Ipv4AddressLength));
            return true;
        }

        if (version == Ipv6VersionNibble)
        {
            source = new IPAddress(ipPacket.Slice(Ipv6SourceAddressOffset, Ipv6AddressLength));
            destination = new IPAddress(ipPacket.Slice(Ipv6DestinationAddressOffset, Ipv6AddressLength));
            return true;
        }

        return false;
    }

    private static bool AddressInRange(IPAddress address, Http3ConnectIpRouteRange route)
    {
        if (Http3ConnectIpScopePolicy.GetIpVersion(address) != route.IpVersion)
        {
            return false;
        }

        byte[] addressBytes = address.GetAddressBytes();
        return Http3ConnectIpRouteRange.CompareAddressBytes(route.StartAddress.GetAddressBytes(), addressBytes) <= 0
            && Http3ConnectIpRouteRange.CompareAddressBytes(addressBytes, route.EndAddress.GetAddressBytes()) <= 0;
    }

    private static bool IsLinkLocal(IPAddress address)
    {
        if (address.IsIPv6LinkLocal)
        {
            return true;
        }

        byte[] bytes = address.GetAddressBytes();
        return bytes.Length == Ipv4AddressLength
            && bytes[0] == Ipv4LinkLocalFirstOctet
            && bytes[1] == Ipv4LinkLocalSecondOctet;
    }
}
