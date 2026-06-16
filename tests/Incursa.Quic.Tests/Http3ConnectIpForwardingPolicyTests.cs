// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class Http3ConnectIpForwardingPolicyTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0168")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForwardingPolicy_ProcessesReceivedIpPacketAfterChecksAndRouteSelection()
    {
        Assert.True(Http3ConnectIpForwardingPolicy.CanProcessReceivedIpPacket(CreateIpv4Packet(), localPolicyAllowsPacket: true, routeOrLocalApplicationAvailable: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0168")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForwardingPolicy_RejectsReceivedIpPacketWithoutRouteOrLocalApplication()
    {
        Assert.False(Http3ConnectIpForwardingPolicy.CanProcessReceivedIpPacket(CreateIpv4Packet(), localPolicyAllowsPacket: true, routeOrLocalApplicationAvailable: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0169")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForwardingPolicy_AppliesAdditionalFilteringPolicyWhenConfigured()
    {
        Assert.True(Http3ConnectIpForwardingPolicy.AdditionalFilteringPolicyAllowsPacket(filteringPolicyConfigured: true, packetAllowedByPolicy: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0169")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForwardingPolicy_RejectsPacketsDeniedByAdditionalFilteringPolicy()
    {
        Assert.False(Http3ConnectIpForwardingPolicy.AdditionalFilteringPolicyAllowsPacket(filteringPolicyConfigured: true, packetAllowedByPolicy: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0170")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForwardingPolicy_TreatsFailedChecksAsForwardingErrors()
    {
        Assert.True(Http3ConnectIpForwardingPolicy.FailedChecksAreForwardingErrors);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0170")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForwardingPolicy_DoesNotTreatFailedChecksAsProtocolViolation()
    {
        Assert.True(Http3ConnectIpForwardingPolicy.FailedChecksAreForwardingErrors);
        Assert.False(Http3ConnectIpForwardingPolicy.CanProcessReceivedIpPacket(CreateIpv4Packet(), localPolicyAllowsPacket: false, routeOrLocalApplicationAvailable: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0171")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForwardingPolicy_ChecksMappedRoutesBeforeSendingHttpDatagrams()
    {
        Http3ConnectIpRouteRange route = new(IPAddress.Parse("192.0.2.1"), IPAddress.Parse("192.0.2.10"), 6);

        Assert.True(Http3ConnectIpForwardingPolicy.CanTransmitPacketOnMappedTunnel(CreateIpv4Packet(), [route], localPolicyAllowsPacket: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0171")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForwardingPolicy_RejectsHttpDatagramTransmissionWithoutMatchingRoute()
    {
        Http3ConnectIpRouteRange route = new(IPAddress.Parse("198.51.100.1"), IPAddress.Parse("198.51.100.10"), 6);

        Assert.False(Http3ConnectIpForwardingPolicy.CanTransmitPacketOnMappedTunnel(CreateIpv4Packet(), [route], localPolicyAllowsPacket: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0172")]
    [Requirement("REQ-QUIC-RFC9484-0185")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForwardingPolicy_DecrementsHopCountOnEncapsulation()
    {
        Assert.True(Http3ConnectIpForwardingPolicy.ShouldDecrementHopCountOnEncapsulation(forwardingBetweenDifferentLinks: true, packetGeneratedByProxyingEndpoint: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0172")]
    [Requirement("REQ-QUIC-RFC9484-0185")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForwardingPolicy_DoesNotDecrementHopCountWhenNotForwardingBetweenLinks()
    {
        Assert.False(Http3ConnectIpForwardingPolicy.ShouldDecrementHopCountOnEncapsulation(forwardingBetweenDifferentLinks: false, packetGeneratedByProxyingEndpoint: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0173")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForwardingPolicy_DoesNotDecrementHopCountOnDecapsulation()
    {
        Assert.False(Http3ConnectIpForwardingPolicy.DecrementHopCountOnDecapsulation);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0173")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForwardingPolicy_RejectsDecapsulationHopCountDecrement()
    {
        Assert.False(Http3ConnectIpForwardingPolicy.DecrementHopCountOnDecapsulation);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0174")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForwardingPolicy_DecrementsHopCountBeforeHttpDatagramTransmission()
    {
        Assert.True(Http3ConnectIpForwardingPolicy.TryDecrementHopCountBeforeTransmission(CreateIpv4Packet(ttl: 64), out byte[] decremented));

        Assert.Equal(63, decremented[8]);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0174")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForwardingPolicy_DoesNotTransmitInvalidPacketForHopCountDecrement()
    {
        Assert.False(Http3ConnectIpForwardingPolicy.TryDecrementHopCountBeforeTransmission([0x10, 0x00], out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0175")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForwardingPolicy_ExcludesSelfGeneratedPacketsFromHopCountDecrement()
    {
        Assert.False(Http3ConnectIpForwardingPolicy.ShouldDecrementHopCountOnEncapsulation(forwardingBetweenDifferentLinks: true, packetGeneratedByProxyingEndpoint: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0175")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForwardingPolicy_DoesNotApplySelfGeneratedExceptionToForwardedPackets()
    {
        Assert.True(Http3ConnectIpForwardingPolicy.ShouldDecrementHopCountOnEncapsulation(forwardingBetweenDifferentLinks: true, packetGeneratedByProxyingEndpoint: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0176")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForwardingPolicy_AllowsNonLinkLocalTrafficBeyondReceivedInterface()
    {
        Assert.True(Http3ConnectIpForwardingPolicy.CanForwardBeyondReceivedInterface(CreateIpv4Packet()));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0176")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForwardingPolicy_DoesNotForwardLinkLocalTrafficBeyondReceivedInterface()
    {
        Assert.False(Http3ConnectIpForwardingPolicy.CanForwardBeyondReceivedInterface(CreateIpv4Packet(source: [169, 254, 0, 1])));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0177")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForwardingPolicy_AcceptsIpv6TunnelMtuAtLeast1280()
    {
        Assert.True(Http3ConnectIpForwardingPolicy.IsIpv6TunnelMtuValid(1280));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0177")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForwardingPolicy_RejectsIpv6TunnelMtuBelow1280()
    {
        Assert.False(Http3ConnectIpForwardingPolicy.IsIpv6TunnelMtuValid(1279));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0178")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForwardingPolicy_UsesIcmpv6EchoRequestsToVerifyLinkMtu()
    {
        Assert.True(Http3ConnectIpForwardingPolicy.ShouldUseIcmpv6EchoRequestsToVerifyLinkMtu(outOfBandGuaranteeSufficient: false));
        Assert.Equal(1232, Http3ConnectIpForwardingPolicy.Icmpv6EchoMtuProbeDataLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0178")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForwardingPolicy_DoesNotProbeMtuWithSufficientOutOfBandGuarantee()
    {
        Assert.False(Http3ConnectIpForwardingPolicy.ShouldUseIcmpv6EchoRequestsToVerifyLinkMtu(outOfBandGuaranteeSufficient: true));
        Assert.True(Http3ConnectIpForwardingPolicy.ShouldTearDownTunnelAfterMtuProbeFailure(outOfBandGuaranteeSufficient: false, echoResponseReceived: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0179")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForwardingPolicy_AbortsRequestStreamWhenQuicMtuTooLowForIpv6Datagrams()
    {
        Assert.True(Http3ConnectIpForwardingPolicy.ShouldAbortRequestStreamForLowQuicMtu(usingQuicDatagramForIpv6Packets: true, quicMtu: 1279));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0179")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForwardingPolicy_DoesNotAbortWhenQuicMtuSupportsIpv6Datagrams()
    {
        Assert.False(Http3ConnectIpForwardingPolicy.ShouldAbortRequestStreamForLowQuicMtu(usingQuicDatagramForIpv6Packets: true, quicMtu: 1280));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0180")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForwardingPolicy_SignalsForwardingErrorsWithIcmp()
    {
        Assert.True(Http3ConnectIpForwardingPolicy.ShouldSignalForwardingErrorWithIcmp(forwardingErrorDetected: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0180")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForwardingPolicy_DoesNotSignalIcmpWithoutForwardingError()
    {
        Assert.False(Http3ConnectIpForwardingPolicy.ShouldSignalForwardingErrorWithIcmp(forwardingErrorDetected: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0181")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForwardingPolicy_UsesDestinationUnreachableCodeFiveForInvalidSource()
    {
        Assert.True(Http3ConnectIpForwardingPolicy.ShouldSendInvalidSourceDestinationUnreachable(invalidSourceAddress: true));
        Assert.Equal(5, Http3ConnectIpForwardingPolicy.Icmpv6DestinationUnreachableInvalidSourceCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0181")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForwardingPolicy_DoesNotSendInvalidSourceDestinationUnreachableForValidSource()
    {
        Assert.False(Http3ConnectIpForwardingPolicy.ShouldSendInvalidSourceDestinationUnreachable(invalidSourceAddress: false));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9484-0182")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [InlineData(0)]
    [InlineData(1)]
    public void ForwardingPolicy_AllowsUnroutableDestinationCodesZeroOrOne(int code)
    {
        Assert.True(Http3ConnectIpForwardingPolicy.IsValidUnroutableDestinationCode(code));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0182")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForwardingPolicy_RejectsOtherUnroutableDestinationCodes()
    {
        Assert.False(Http3ConnectIpForwardingPolicy.IsValidUnroutableDestinationCode(5));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0183")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForwardingPolicy_SendsPacketTooBigForMtuExceedingPackets()
    {
        Assert.True(Http3ConnectIpForwardingPolicy.ShouldSendPacketTooBig(packetLength: 1500, outgoingLinkMtu: 1280));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0183")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForwardingPolicy_DoesNotSendPacketTooBigForPacketsWithinMtu()
    {
        Assert.False(Http3ConnectIpForwardingPolicy.ShouldSendPacketTooBig(packetLength: 1280, outgoingLinkMtu: 1280));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0184")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForwardingPolicy_ProcessesProxiedIcmpWhenRouteAdvertisementAbsent()
    {
        Assert.True(Http3ConnectIpForwardingPolicy.ShouldProcessProxiedIcmpWithoutRouteAdvertisement(routeAdvertisementSent: false, protocolNumber: Http3ConnectIpProtocolScope.IcmpV6ProtocolNumber));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0184")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForwardingPolicy_DoesNotUseAbsentRouteAdvertisementPolicyForNonIcmp()
    {
        Assert.False(Http3ConnectIpForwardingPolicy.ShouldProcessProxiedIcmpWithoutRouteAdvertisement(routeAdvertisementSent: false, protocolNumber: 6));
    }

    private static byte[] CreateIpv4Packet(byte ttl = 64, byte protocol = 6, byte[]? source = null, byte[]? destination = null)
    {
        source ??= [192, 0, 2, 1];
        destination ??= [192, 0, 2, 2];
        return [0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, ttl, protocol, 0x00, 0x00, .. source, .. destination];
    }
}
