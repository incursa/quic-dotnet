// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class Http3ConnectUdpSocketLifecyclePolicyTests
{
    [Fact]
    [Requirement("RFC9298-S3-1-P4-S1-R02")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SocketLifecycle_AcceptsMatchingSourceAddressOnNonConnectedSocket()
    {
        IPEndPoint target = new(IPAddress.Parse("192.0.2.44"), 443);
        IPEndPoint source = new(IPAddress.Parse("192.0.2.44"), 443);

        Assert.True(Http3ConnectUdpSocketLifecyclePolicy.ShouldAcceptPacketFromSource(target, source, connectedSocket: false));
    }

    [Fact]
    [Requirement("RFC9298-S3-1-P4-S1-R02")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SocketLifecycle_RejectsMismatchedSourceAddressOnNonConnectedSocket()
    {
        IPEndPoint target = new(IPAddress.Parse("192.0.2.44"), 443);
        IPEndPoint source = new(IPAddress.Parse("192.0.2.45"), 443);

        Assert.False(Http3ConnectUdpSocketLifecyclePolicy.ShouldAcceptPacketFromSource(target, source, connectedSocket: false));
    }

    [Fact]
    [Requirement("RFC9298-S3-1-P4-S1-R03")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SocketLifecycle_AcceptsMatchingSourcePortOnNonConnectedSocket()
    {
        IPEndPoint target = new(IPAddress.Parse("192.0.2.44"), 443);
        IPEndPoint source = new(IPAddress.Parse("192.0.2.44"), 443);

        Assert.True(Http3ConnectUdpSocketLifecyclePolicy.ShouldAcceptPacketFromSource(target, source, connectedSocket: false));
    }

    [Fact]
    [Requirement("RFC9298-S3-1-P4-S1-R03")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SocketLifecycle_RejectsMismatchedSourcePortOnNonConnectedSocket()
    {
        IPEndPoint target = new(IPAddress.Parse("192.0.2.44"), 443);
        IPEndPoint source = new(IPAddress.Parse("192.0.2.44"), 444);

        Assert.False(Http3ConnectUdpSocketLifecyclePolicy.ShouldAcceptPacketFromSource(target, source, connectedSocket: false));
    }

    [Fact]
    [Requirement("RFC9298-S3-1-P4-S2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SocketLifecycle_DiscardsUnmatchedPacketsOnNonConnectedSocket()
    {
        IPEndPoint target = new(IPAddress.Parse("192.0.2.44"), 443);
        IPEndPoint source = new(IPAddress.Parse("192.0.2.45"), 444);

        Assert.True(Http3ConnectUdpSocketLifecyclePolicy.ShouldDiscardPacketFromSource(target, source, connectedSocket: false));
    }

    [Fact]
    [Requirement("RFC9298-S3-1-P4-S2-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SocketLifecycle_DoesNotDiscardMatchedPacketsOnNonConnectedSocket()
    {
        IPEndPoint target = new(IPAddress.Parse("192.0.2.44"), 443);
        IPEndPoint source = new(IPAddress.Parse("192.0.2.44"), 443);

        Assert.False(Http3ConnectUdpSocketLifecyclePolicy.ShouldDiscardPacketFromSource(target, source, connectedSocket: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0044")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SocketLifecycle_KeepsSocketOpenWhileRequestStreamIsOpen()
    {
        Assert.True(Http3ConnectUdpSocketLifecyclePolicy.ShouldKeepSocketOpen(
            requestStreamOpen: true,
            socketUsable: true,
            inactivityTimeoutElapsed: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0044")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SocketLifecycle_DoesNotKeepSocketOpenAfterRequestStreamCloses()
    {
        Assert.False(Http3ConnectUdpSocketLifecyclePolicy.ShouldKeepSocketOpen(
            requestStreamOpen: false,
            socketUsable: true,
            inactivityTimeoutElapsed: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0045")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SocketLifecycle_ClosesRequestStreamWhenSocketIsUnusable()
    {
        Assert.True(Http3ConnectUdpSocketLifecyclePolicy.ShouldCloseRequestStream(socketUsable: false, socketClosing: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0045")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SocketLifecycle_DoesNotCloseRequestStreamForUsableSocket()
    {
        Assert.False(Http3ConnectUdpSocketLifecyclePolicy.ShouldCloseRequestStream(socketUsable: true, socketClosing: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0046")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SocketLifecycle_CanCloseSocketAfterInactivity()
    {
        Assert.True(Http3ConnectUdpSocketLifecyclePolicy.CanCloseSocketAfterInactivity(inactivityTimeoutElapsed: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0046")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SocketLifecycle_DoesNotCloseSocketBeforeInactivityTimeout()
    {
        Assert.False(Http3ConnectUdpSocketLifecyclePolicy.CanCloseSocketAfterInactivity(inactivityTimeoutElapsed: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0047")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SocketLifecycle_ClosesRequestStreamWhenSocketIsClosing()
    {
        Assert.True(Http3ConnectUdpSocketLifecyclePolicy.ShouldCloseRequestStream(socketUsable: true, socketClosing: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0047")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SocketLifecycle_DoesNotCloseRequestStreamWhenSocketRemainsOpen()
    {
        Assert.False(Http3ConnectUdpSocketLifecyclePolicy.ShouldCloseRequestStream(socketUsable: true, socketClosing: false));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9298-0048")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [InlineData(120)]
    [InlineData(180)]
    public void SocketLifecycle_AcceptsRecommendedInactivityTimeouts(int seconds)
    {
        Assert.True(Http3ConnectUdpSocketLifecyclePolicy.IsRecommendedInactivityTimeout(TimeSpan.FromSeconds(seconds)));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9298-0048")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData(1)]
    [InlineData(119)]
    public void SocketLifecycle_RejectsShortInactivityTimeouts(int seconds)
    {
        Assert.False(Http3ConnectUdpSocketLifecyclePolicy.IsRecommendedInactivityTimeout(TimeSpan.FromSeconds(seconds)));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0050")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SocketLifecycle_ForwardsOnlyWhenIpFragmentationIsNotIntroduced()
    {
        Assert.True(Http3ConnectUdpSocketLifecyclePolicy.CanForwardWithoutIpFragmentation(
            udpPayloadLength: 1200,
            outgoingUdpPacketLimit: 1200));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0050")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SocketLifecycle_RejectsForwardingThatWouldNeedIpFragmentation()
    {
        Assert.False(Http3ConnectUdpSocketLifecyclePolicy.CanForwardWithoutIpFragmentation(
            udpPayloadLength: 1201,
            outgoingUdpPacketLimit: 1200));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0051")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SocketLifecycle_SilentlyDropsOversizedHttpDatagrams()
    {
        Assert.True(Http3ConnectUdpSocketLifecyclePolicy.ShouldSilentlyDropOversizedHttpDatagram(
            udpPayloadLength: 1201,
            outgoingUdpPacketLimit: 1200));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0051")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SocketLifecycle_DoesNotDropHttpDatagramsWithinOutgoingLimit()
    {
        Assert.False(Http3ConnectUdpSocketLifecyclePolicy.ShouldSilentlyDropOversizedHttpDatagram(
            udpPayloadLength: 1200,
            outgoingUdpPacketLimit: 1200));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0052")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SocketLifecycle_SetsIpv4DontFragmentBitWhenSupported()
    {
        Assert.True(Http3ConnectUdpSocketLifecyclePolicy.ShouldSetIpv4DontFragmentBit(
            IPAddress.Parse("192.0.2.44"),
            socketSupportsDontFragmentOption: true));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9298-0052")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData("192.0.2.44", false)]
    [InlineData("2001:db8::44", true)]
    public void SocketLifecycle_DoesNotSetIpv4DontFragmentBitWhenImpossible(string address, bool socketSupportsDontFragmentOption)
    {
        Assert.False(Http3ConnectUdpSocketLifecyclePolicy.ShouldSetIpv4DontFragmentBit(
            IPAddress.Parse(address),
            socketSupportsDontFragmentOption));
    }
}
