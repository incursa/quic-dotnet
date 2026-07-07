// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9298_SocketLifecycleFuzzClosure
{
    [Fact]
    [Requirement("RFC9298-S3-1-P4-S1-R02")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NonConnectedSocketValidatesPacketSourceAddress()
    {
        foreach ((IPEndPoint requested, IPEndPoint matching, IPEndPoint mismatched) in EndpointCases())
        {
            Assert.True(Http3ConnectUdpSocketLifecyclePolicy.ShouldAcceptPacketFromSource(requested, matching, connectedSocket: false));
            Assert.False(Http3ConnectUdpSocketLifecyclePolicy.ShouldAcceptPacketFromSource(requested, mismatched, connectedSocket: false));
            Assert.True(Http3ConnectUdpSocketLifecyclePolicy.ShouldAcceptPacketFromSource(requested, mismatched, connectedSocket: true));
        }
    }

    [Fact]
    [Requirement("RFC9298-S3-1-P4-S1-R03")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NonConnectedSocketValidatesPacketSourcePort()
    {
        foreach ((IPEndPoint requested, IPEndPoint matching, _) in EndpointCases())
        {
            IPEndPoint wrongPort = new(requested.Address, requested.Port == 443 ? 444 : 443);

            Assert.True(Http3ConnectUdpSocketLifecyclePolicy.ShouldAcceptPacketFromSource(requested, matching, connectedSocket: false));
            Assert.False(Http3ConnectUdpSocketLifecyclePolicy.ShouldAcceptPacketFromSource(requested, wrongPort, connectedSocket: false));
            Assert.True(Http3ConnectUdpSocketLifecyclePolicy.ShouldAcceptPacketFromSource(requested, wrongPort, connectedSocket: true));
        }
    }

    [Fact]
    [Requirement("RFC9298-S3-1-P4-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NonMatchingPacketsAreDiscardedByUdpProxy()
    {
        foreach ((IPEndPoint requested, IPEndPoint matching, IPEndPoint mismatched) in EndpointCases())
        {
            Assert.False(Http3ConnectUdpSocketLifecyclePolicy.ShouldDiscardPacketFromSource(requested, matching, connectedSocket: false));
            Assert.True(Http3ConnectUdpSocketLifecyclePolicy.ShouldDiscardPacketFromSource(requested, mismatched, connectedSocket: false));
            Assert.False(Http3ConnectUdpSocketLifecyclePolicy.ShouldDiscardPacketFromSource(requested, mismatched, connectedSocket: true));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0044")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProxyKeepsSocketOpenWhileRequestStreamIsOpen()
    {
        Assert.True(Http3ConnectUdpSocketLifecyclePolicy.ShouldKeepSocketOpen(
            requestStreamOpen: true,
            socketUsable: true,
            inactivityTimeoutElapsed: false));

        foreach ((bool requestStreamOpen, bool socketUsable, bool inactivityTimeoutElapsed) in new[]
        {
            (false, true, false),
            (true, false, false),
            (true, true, true),
            (false, false, true),
        })
        {
            Assert.False(Http3ConnectUdpSocketLifecyclePolicy.ShouldKeepSocketOpen(requestStreamOpen, socketUsable, inactivityTimeoutElapsed));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0045")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UnusableSocketClosesRequestStream()
    {
        Assert.True(Http3ConnectUdpSocketLifecyclePolicy.ShouldCloseRequestStream(socketUsable: false, socketClosing: false));
        Assert.True(Http3ConnectUdpSocketLifecyclePolicy.ShouldCloseRequestStream(socketUsable: false, socketClosing: true));
        Assert.False(Http3ConnectUdpSocketLifecyclePolicy.ShouldCloseRequestStream(socketUsable: true, socketClosing: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0046")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProxyMayCloseSocketAfterInactivity()
    {
        Assert.True(Http3ConnectUdpSocketLifecyclePolicy.CanCloseSocketAfterInactivity(inactivityTimeoutElapsed: true));
        Assert.False(Http3ConnectUdpSocketLifecyclePolicy.CanCloseSocketAfterInactivity(inactivityTimeoutElapsed: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0047")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ClosingSocketClosesRequestStream()
    {
        Assert.True(Http3ConnectUdpSocketLifecyclePolicy.ShouldCloseRequestStream(socketUsable: true, socketClosing: true));
        Assert.True(Http3ConnectUdpSocketLifecyclePolicy.ShouldCloseRequestStream(socketUsable: false, socketClosing: true));
        Assert.False(Http3ConnectUdpSocketLifecyclePolicy.ShouldCloseRequestStream(socketUsable: true, socketClosing: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0048")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InactivityTimeoutIsNotLowerThanTwoMinutes()
    {
        foreach (TimeSpan timeout in new[]
        {
            TimeSpan.FromSeconds(120),
            TimeSpan.FromMinutes(2),
            TimeSpan.FromMinutes(5),
        })
        {
            Assert.True(Http3ConnectUdpSocketLifecyclePolicy.IsRecommendedInactivityTimeout(timeout));
        }

        foreach (TimeSpan timeout in new[]
        {
            TimeSpan.Zero,
            TimeSpan.FromSeconds(1),
            TimeSpan.FromSeconds(119),
        })
        {
            Assert.False(Http3ConnectUdpSocketLifecyclePolicy.IsRecommendedInactivityTimeout(timeout));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0050")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProxyDoesNotIntroduceIpFragmentation()
    {
        foreach ((int payloadLength, int packetLimit) in new[] { (0, 1200), (1199, 1200), (1200, 1200) })
        {
            Assert.True(Http3ConnectUdpSocketLifecyclePolicy.CanForwardWithoutIpFragmentation(payloadLength, packetLimit));
        }

        foreach ((int payloadLength, int packetLimit) in new[] { (1201, 1200), (1500, 1280), (1300, 1200) })
        {
            Assert.False(Http3ConnectUdpSocketLifecyclePolicy.CanForwardWithoutIpFragmentation(payloadLength, packetLimit));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0051")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProxySilentlyDropsOversizedHttpDatagrams()
    {
        foreach ((int payloadLength, int packetLimit) in new[] { (1201, 1200), (1500, 1280), (1300, 1200) })
        {
            Assert.True(Http3ConnectUdpSocketLifecyclePolicy.ShouldSilentlyDropOversizedHttpDatagram(payloadLength, packetLimit));
        }

        foreach ((int payloadLength, int packetLimit) in new[] { (0, 1200), (1199, 1200), (1200, 1200) })
        {
            Assert.False(Http3ConnectUdpSocketLifecyclePolicy.ShouldSilentlyDropOversizedHttpDatagram(payloadLength, packetLimit));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0052")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Ipv4DontFragmentBitIsSetWhenPossible()
    {
        foreach (IPAddress address in new[] { IPAddress.Parse("192.0.2.44"), IPAddress.Parse("198.51.100.1") })
        {
            Assert.True(Http3ConnectUdpSocketLifecyclePolicy.ShouldSetIpv4DontFragmentBit(address, socketSupportsDontFragmentOption: true));
            Assert.False(Http3ConnectUdpSocketLifecyclePolicy.ShouldSetIpv4DontFragmentBit(address, socketSupportsDontFragmentOption: false));
        }

        foreach (IPAddress address in new[] { IPAddress.Parse("2001:db8::44"), IPAddress.IPv6Loopback })
        {
            Assert.False(Http3ConnectUdpSocketLifecyclePolicy.ShouldSetIpv4DontFragmentBit(address, socketSupportsDontFragmentOption: true));
        }
    }

    private static (IPEndPoint Requested, IPEndPoint Matching, IPEndPoint Mismatched)[] EndpointCases()
    {
        return
        [
            (
                new IPEndPoint(IPAddress.Parse("192.0.2.44"), 443),
                new IPEndPoint(IPAddress.Parse("192.0.2.44"), 443),
                new IPEndPoint(IPAddress.Parse("192.0.2.45"), 443)
            ),
            (
                new IPEndPoint(IPAddress.Parse("2001:db8::44"), 53),
                new IPEndPoint(IPAddress.Parse("2001:db8::44"), 53),
                new IPEndPoint(IPAddress.Parse("2001:db8::45"), 53)
            ),
        ];
    }
}
