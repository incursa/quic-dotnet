// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Sockets;

namespace Incursa.Quic.Http3;

/// <summary>
/// Provides RFC 9298 CONNECT-UDP UDP socket lifecycle and forwarding policy helpers.
/// </summary>
public static class Http3ConnectUdpSocketLifecyclePolicy
{
    /// <summary>
    /// Gets the shortest recommended inactivity timeout for proxies that close idle UDP sockets.
    /// </summary>
    public static readonly TimeSpan MinimumRecommendedInactivityTimeout = TimeSpan.FromMinutes(2);

    /// <summary>
    /// Returns true when a packet from a non-connected UDP socket matches the requested target.
    /// </summary>
    public static bool ShouldAcceptPacketFromSource(IPEndPoint requestedTarget, IPEndPoint receivedSource, bool connectedSocket)
    {
        ArgumentNullException.ThrowIfNull(requestedTarget);
        ArgumentNullException.ThrowIfNull(receivedSource);

        return connectedSocket
            || (requestedTarget.Address.Equals(receivedSource.Address) && requestedTarget.Port == receivedSource.Port);
    }

    /// <summary>
    /// Returns true when a packet from a non-connected UDP socket does not match the requested target and must be discarded.
    /// </summary>
    public static bool ShouldDiscardPacketFromSource(IPEndPoint requestedTarget, IPEndPoint receivedSource, bool connectedSocket)
    {
        return !ShouldAcceptPacketFromSource(requestedTarget, receivedSource, connectedSocket);
    }

    /// <summary>
    /// Returns true when the UDP socket should remain open for the CONNECT-UDP request stream.
    /// </summary>
    public static bool ShouldKeepSocketOpen(bool requestStreamOpen, bool socketUsable, bool inactivityTimeoutElapsed)
    {
        return requestStreamOpen && socketUsable && !inactivityTimeoutElapsed;
    }

    /// <summary>
    /// Returns true when the request stream should be closed because the UDP socket cannot continue.
    /// </summary>
    public static bool ShouldCloseRequestStream(bool socketUsable, bool socketClosing)
    {
        return !socketUsable || socketClosing;
    }

    /// <summary>
    /// Returns true when a proxy policy can close the UDP socket due to inactivity.
    /// </summary>
    public static bool CanCloseSocketAfterInactivity(bool inactivityTimeoutElapsed)
    {
        return inactivityTimeoutElapsed;
    }

    /// <summary>
    /// Returns true when an inactivity timeout follows the RFC 9298 two-minute recommendation.
    /// </summary>
    public static bool IsRecommendedInactivityTimeout(TimeSpan timeout)
    {
        return timeout >= MinimumRecommendedInactivityTimeout;
    }

    /// <summary>
    /// Returns true when a UDP payload can be forwarded without introducing IP fragmentation.
    /// </summary>
    public static bool CanForwardWithoutIpFragmentation(int udpPayloadLength, int outgoingUdpPacketLimit)
    {
        return Http3ConnectUdpDatagramPolicy.CanForwardWithoutIpFragmentation(udpPayloadLength, outgoingUdpPacketLimit);
    }

    /// <summary>
    /// Returns true when an oversized HTTP Datagram payload must be silently dropped before UDP forwarding.
    /// </summary>
    public static bool ShouldSilentlyDropOversizedHttpDatagram(int udpPayloadLength, int outgoingUdpPacketLimit)
    {
        return Http3ConnectUdpDatagramPolicy.ShouldDiscardForKnownOutgoingLimit(udpPayloadLength, outgoingUdpPacketLimit);
    }

    /// <summary>
    /// Returns true when the IPv4 Don't Fragment bit should be set for an outbound UDP socket, if supported.
    /// </summary>
    public static bool ShouldSetIpv4DontFragmentBit(IPAddress destinationAddress, bool socketSupportsDontFragmentOption)
    {
        ArgumentNullException.ThrowIfNull(destinationAddress);
        return destinationAddress.AddressFamily == AddressFamily.InterNetwork && socketSupportsDontFragmentOption;
    }
}
