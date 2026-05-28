// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Sockets;

namespace Incursa.Quic.Tests;

internal static class QuicS9P7FlowLabelTestSupport
{
    internal static readonly IPEndPoint Ipv6SocketLocalEndPoint = new(
        IPAddress.IPv6Any,
        61234);

    internal static readonly QuicConnectionPathIdentity PrimaryPath = new(
        RemoteAddress: "2001:db8::20",
        LocalAddress: "2001:db8::10",
        RemotePort: 443,
        LocalPort: 61234);

    internal static readonly QuicConnectionPathIdentity SecondaryPath = new(
        RemoteAddress: "2001:db8::21",
        LocalAddress: "2001:db8::10",
        RemotePort: 443,
        LocalPort: 61234);

    internal static readonly QuicConnectionPathIdentity AlternateLocalPath = new(
        RemoteAddress: "2001:db8::20",
        LocalAddress: "2001:db8::11",
        RemotePort: 443,
        LocalPort: 61234);

    internal const uint SeedA = 0x11223344U;
    internal const uint SeedB = 0x55667788U;

    internal static bool TryResolveSourceAddress(
        QuicConnectionPathIdentity pathIdentity,
        out IPAddress sourceAddress)
    {
        return QuicConnectionEndpointHost.TryResolvePacketInformationSourceAddress(
            Ipv6SocketLocalEndPoint,
            AddressFamily.InterNetworkV6,
            pathIdentity,
            out sourceAddress);
    }

    internal static uint CreateFlowLabel(uint seed, QuicConnectionPathIdentity pathIdentity)
    {
        return QuicSocketPacketInformationSender.CreateIpv6FlowLabel(seed, pathIdentity);
    }
}
