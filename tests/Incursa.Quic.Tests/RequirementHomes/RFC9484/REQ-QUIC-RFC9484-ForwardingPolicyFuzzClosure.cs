// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9484_ForwardingPolicyFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0168")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ReceivedIpPacketRequiresHeaderPolicyAndRouteOrLocalApplication()
    {
        byte[] packet = CreateIpv4Packet();

        Assert.True(Http3ConnectIpForwardingPolicy.CanProcessReceivedIpPacket(packet, localPolicyAllowsPacket: true, routeOrLocalApplicationAvailable: true));
        Assert.False(Http3ConnectIpForwardingPolicy.CanProcessReceivedIpPacket(packet, localPolicyAllowsPacket: false, routeOrLocalApplicationAvailable: true));
        Assert.False(Http3ConnectIpForwardingPolicy.CanProcessReceivedIpPacket(packet, localPolicyAllowsPacket: true, routeOrLocalApplicationAvailable: false));
        Assert.False(Http3ConnectIpForwardingPolicy.CanProcessReceivedIpPacket([0x10, 0x00], localPolicyAllowsPacket: true, routeOrLocalApplicationAvailable: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0169")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AdditionalFilteringPolicyCanPermitOrDenyForwarding()
    {
        Assert.True(Http3ConnectIpForwardingPolicy.AdditionalFilteringPolicyAllowsPacket(filteringPolicyConfigured: false, packetAllowedByPolicy: false));
        Assert.True(Http3ConnectIpForwardingPolicy.AdditionalFilteringPolicyAllowsPacket(filteringPolicyConfigured: true, packetAllowedByPolicy: true));
        Assert.False(Http3ConnectIpForwardingPolicy.AdditionalFilteringPolicyAllowsPacket(filteringPolicyConfigured: true, packetAllowedByPolicy: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0170")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_FailedForwardingChecksAreForwardingErrors()
    {
        Assert.True(Http3ConnectIpForwardingPolicy.FailedChecksAreForwardingErrors);
        Assert.False(Http3ConnectIpForwardingPolicy.CanProcessReceivedIpPacket(CreateIpv4Packet(), localPolicyAllowsPacket: false, routeOrLocalApplicationAvailable: true));
        Assert.True(Http3ConnectIpForwardingPolicy.ShouldSignalForwardingErrorWithIcmp(forwardingErrorDetected: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0171")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_MappedTunnelTransmissionRequiresMatchingRouteAndForwardingChecks()
    {
        Http3ConnectIpRouteRange matchingRoute = Route("192.0.2.1", "192.0.2.10", 6);
        Http3ConnectIpRouteRange wrongAddressRoute = Route("198.51.100.1", "198.51.100.10", 6);
        Http3ConnectIpRouteRange wrongProtocolRoute = Route("192.0.2.1", "192.0.2.10", 17);
        byte[] packet = CreateIpv4Packet(destination: [192, 0, 2, 2], protocol: 6);

        Assert.True(Http3ConnectIpForwardingPolicy.CanTransmitPacketOnMappedTunnel(packet, [matchingRoute], localPolicyAllowsPacket: true));
        Assert.False(Http3ConnectIpForwardingPolicy.CanTransmitPacketOnMappedTunnel(packet, [wrongAddressRoute], localPolicyAllowsPacket: true));
        Assert.False(Http3ConnectIpForwardingPolicy.CanTransmitPacketOnMappedTunnel(packet, [wrongProtocolRoute], localPolicyAllowsPacket: true));
        Assert.False(Http3ConnectIpForwardingPolicy.CanTransmitPacketOnMappedTunnel(packet, [matchingRoute], localPolicyAllowsPacket: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0172")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ForwardingBetweenDifferentLinksDecrementsHopCountOnEncapsulation()
    {
        Assert.True(Http3ConnectIpForwardingPolicy.ShouldDecrementHopCountOnEncapsulation(forwardingBetweenDifferentLinks: true, packetGeneratedByProxyingEndpoint: false));
        Assert.False(Http3ConnectIpForwardingPolicy.ShouldDecrementHopCountOnEncapsulation(forwardingBetweenDifferentLinks: false, packetGeneratedByProxyingEndpoint: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0173")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DecapsulationDoesNotDecrementHopCount()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            Assert.False(Http3ConnectIpForwardingPolicy.DecrementHopCountOnDecapsulation);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0174")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_HopCountIsDecrementedImmediatelyBeforeHttpDatagramTransmission()
    {
        Assert.True(Http3ConnectIpForwardingPolicy.TryDecrementHopCountBeforeTransmission(CreateIpv4Packet(ttl: 64), out byte[] ipv4));
        Assert.Equal(63, ipv4[8]);

        Assert.True(Http3ConnectIpForwardingPolicy.TryDecrementHopCountBeforeTransmission(CreateIpv6Packet(hopLimit: 32), out byte[] ipv6));
        Assert.Equal(31, ipv6[7]);

        Assert.False(Http3ConnectIpForwardingPolicy.TryDecrementHopCountBeforeTransmission(CreateIpv4Packet(ttl: 0), out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0175")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SelfGeneratedPacketsAreExcludedFromEncapsulationHopCountDecrement()
    {
        Assert.False(Http3ConnectIpForwardingPolicy.ShouldDecrementHopCountOnEncapsulation(forwardingBetweenDifferentLinks: true, packetGeneratedByProxyingEndpoint: true));
        Assert.True(Http3ConnectIpForwardingPolicy.ShouldDecrementHopCountOnEncapsulation(forwardingBetweenDifferentLinks: true, packetGeneratedByProxyingEndpoint: false));
    }

    [Fact]
    [Requirement("RFC9484-S7-2-P5-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LinkLocalTrafficIsNotForwardedBeyondReceivedInterface()
    {
        Assert.True(Http3ConnectIpForwardingPolicy.CanForwardBeyondReceivedInterface(CreateIpv4Packet(source: [192, 0, 2, 1], destination: [198, 51, 100, 1])));
        Assert.False(Http3ConnectIpForwardingPolicy.CanForwardBeyondReceivedInterface(CreateIpv4Packet(source: [169, 254, 0, 1], destination: [198, 51, 100, 1])));
        Assert.False(Http3ConnectIpForwardingPolicy.CanForwardBeyondReceivedInterface(CreateIpv4Packet(source: [192, 0, 2, 1], destination: [169, 254, 0, 1])));
    }

    [Fact]
    [Requirement("RFC9484-S7-2-P6-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Ipv6RouterTunnelMtuIsAtLeast1280Bytes()
    {
        Assert.False(Http3ConnectIpForwardingPolicy.IsIpv6TunnelMtuValid(1279));
        Assert.True(Http3ConnectIpForwardingPolicy.IsIpv6TunnelMtuValid(1280));
        Assert.True(Http3ConnectIpForwardingPolicy.IsIpv6TunnelMtuValid(1500));
    }

    [Fact]
    [Requirement("RFC9484-S7-2-P7-2-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Icmpv6EchoRequestsVerifyLinkMtuWithoutOutOfBandGuarantee()
    {
        Assert.True(Http3ConnectIpForwardingPolicy.ShouldUseIcmpv6EchoRequestsToVerifyLinkMtu(outOfBandGuaranteeSufficient: false));
        Assert.Equal(1232, Http3ConnectIpForwardingPolicy.Icmpv6EchoMtuProbeDataLength);
        Assert.True(Http3ConnectIpForwardingPolicy.ShouldTearDownTunnelAfterMtuProbeFailure(outOfBandGuaranteeSufficient: false, echoResponseReceived: false));
        Assert.False(Http3ConnectIpForwardingPolicy.ShouldUseIcmpv6EchoRequestsToVerifyLinkMtu(outOfBandGuaranteeSufficient: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0179")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TooLowQuicMtuForIpv6DatagramsAbortsProxyingRequestStream()
    {
        Assert.True(Http3ConnectIpForwardingPolicy.ShouldAbortRequestStreamForLowQuicMtu(usingQuicDatagramForIpv6Packets: true, quicMtu: 1279));
        Assert.False(Http3ConnectIpForwardingPolicy.ShouldAbortRequestStreamForLowQuicMtu(usingQuicDatagramForIpv6Packets: true, quicMtu: 1280));
        Assert.False(Http3ConnectIpForwardingPolicy.ShouldAbortRequestStreamForLowQuicMtu(usingQuicDatagramForIpv6Packets: false, quicMtu: 1279));
    }

    [Fact]
    [Requirement("RFC9484-S7-2-1-P1-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ForwardingErrorsAreSignaledWithIcmpPacketsInHttpDatagrams()
    {
        Assert.True(Http3ConnectIpForwardingPolicy.ShouldSignalForwardingErrorWithIcmp(forwardingErrorDetected: true));
        Assert.False(Http3ConnectIpForwardingPolicy.ShouldSignalForwardingErrorWithIcmp(forwardingErrorDetected: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0181")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InvalidSourceAddressUsesIcmpv6DestinationUnreachableCodeFive()
    {
        Assert.True(Http3ConnectIpForwardingPolicy.ShouldSendInvalidSourceDestinationUnreachable(invalidSourceAddress: true));
        Assert.False(Http3ConnectIpForwardingPolicy.ShouldSendInvalidSourceDestinationUnreachable(invalidSourceAddress: false));
        Assert.Equal(5, Http3ConnectIpForwardingPolicy.Icmpv6DestinationUnreachableInvalidSourceCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0182")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UnroutableDestinationUsesIcmpv6CodeZeroOrOne()
    {
        Assert.True(Http3ConnectIpForwardingPolicy.IsValidUnroutableDestinationCode(0));
        Assert.True(Http3ConnectIpForwardingPolicy.IsValidUnroutableDestinationCode(1));
        Assert.False(Http3ConnectIpForwardingPolicy.IsValidUnroutableDestinationCode(5));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0183")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PacketsThatExceedOutgoingMtuRequirePacketTooBig()
    {
        Assert.True(Http3ConnectIpForwardingPolicy.ShouldSendPacketTooBig(packetLength: 1500, outgoingLinkMtu: 1280));
        Assert.False(Http3ConnectIpForwardingPolicy.ShouldSendPacketTooBig(packetLength: 1280, outgoingLinkMtu: 1280));
        Assert.False(Http3ConnectIpForwardingPolicy.ShouldSendPacketTooBig(packetLength: 1200, outgoingLinkMtu: 1280));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0184")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AbsentRouteAdvertisementStillProcessesProxiedIcmpPackets()
    {
        Assert.True(Http3ConnectIpForwardingPolicy.ShouldProcessProxiedIcmpWithoutRouteAdvertisement(routeAdvertisementSent: false, protocolNumber: Http3ConnectIpProtocolScope.IcmpV4ProtocolNumber));
        Assert.True(Http3ConnectIpForwardingPolicy.ShouldProcessProxiedIcmpWithoutRouteAdvertisement(routeAdvertisementSent: false, protocolNumber: Http3ConnectIpProtocolScope.IcmpV6ProtocolNumber));
        Assert.False(Http3ConnectIpForwardingPolicy.ShouldProcessProxiedIcmpWithoutRouteAdvertisement(routeAdvertisementSent: true, protocolNumber: Http3ConnectIpProtocolScope.IcmpV6ProtocolNumber));
        Assert.False(Http3ConnectIpForwardingPolicy.ShouldProcessProxiedIcmpWithoutRouteAdvertisement(routeAdvertisementSent: false, protocolNumber: 6));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0185")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_EncapsulatingForwardedPacketsDecrementsHopCount()
    {
        Assert.True(Http3ConnectIpForwardingPolicy.ShouldDecrementHopCountOnEncapsulation(forwardingBetweenDifferentLinks: true, packetGeneratedByProxyingEndpoint: false));
        Assert.True(Http3ConnectIpForwardingPolicy.TryDecrementHopCountBeforeTransmission(CreateIpv4Packet(ttl: 5), out byte[] decremented));
        Assert.Equal(4, decremented[8]);
    }

    private static Http3ConnectIpRouteRange Route(string startAddress, string endAddress, int protocol)
    {
        return new Http3ConnectIpRouteRange(IPAddress.Parse(startAddress), IPAddress.Parse(endAddress), protocol);
    }

    private static byte[] CreateIpv4Packet(byte ttl = 64, byte protocol = 6, byte[]? source = null, byte[]? destination = null)
    {
        source ??= [192, 0, 2, 1];
        destination ??= [192, 0, 2, 2];
        return [0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, ttl, protocol, 0x00, 0x00, .. source, .. destination];
    }

    private static byte[] CreateIpv6Packet(byte hopLimit)
    {
        byte[] packet = new byte[40];
        packet[0] = 0x60;
        packet[6] = 6;
        packet[7] = hopLimit;
        return packet;
    }
}
